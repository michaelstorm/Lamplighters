from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime
from functools import reduce
from operator import mul
import math
import os
import sys


# Until I find an efficient way to do this, just generate prime numbers
def create_pairwise_coprime_integers(min_bits, coprime_to, num):
    return [getPrime(min_bits) for i in range(num)]


# From http://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q,r = b//a,b%a; m,n = x-u*q,y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    return b, x, y


# From http://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        return None  # modular inverse does not exist
    else:
        return x % m


def solve_crt(a_list, d_list):
    assert len(a_list) == len(d_list)

    D = reduce(mul, d_list, 1)
    C = 0
    for i in range(len(a_list)):
        D_i = D // d_list[i]
        y_i = modinv(D_i, d_list[i])
        C += (a_list[i] * D_i * y_i) % D

    if __debug__:
        for i in range(len(a_list)):
            assert C % d_list[i] == a_list[i] % d_list[i]

    return C


class Server(object):
    def __init__(self, public_key, private_key, encoding_bit_length, secret_data):
        self.secret_data = secret_data
        self.public_key = public_key
        self.private_key = private_key

        max_secret_bits = math.ceil(math.log(max(secret_data), 2))
        d_list = create_pairwise_coprime_integers(encoding_bit_length, public_key.n, len(secret_data))
        if __debug__:
            for d in d_list:
                assert egcd(d, public_key.n)[0] == 1
        
        self.C = solve_crt(self.secret_data, d_list)
        self.T = [pow(d, public_key.e, public_key.n) for d in d_list]

    def get_initiation_message(self):
        return (self.C, self.T)

    def get_response_message(self):
        return self.beta_list

    def process_request_message(self, message):
        self.beta_list = [pow(alpha, self.private_key.d, self.public_key.n) for alpha in message]

class Client(object):
    def __init__(self, public_key, encoding_bit_length, requested_data_indices):
        self.public_key = public_key
        self.requested_data_indices = requested_data_indices
        self.encoding_bit_length = encoding_bit_length

    def process_initiation_message(self, message):
        (self.C, T) = message
        self.r_list = create_pairwise_coprime_integers(self.encoding_bit_length, self.public_key.n, len(self.requested_data_indices))
        if __debug__:
            for r in self.r_list:
                assert egcd(r, self.public_key.n)[0] == 1

        self.alpha_list = [(pow(self.r_list[i], self.public_key.e, self.public_key.n) * T[self.requested_data_indices[i]]) % self.public_key.n for i in range(len(self.requested_data_indices))]

    def process_response_message(self, message):
        beta_list = message
        d_prime_list = [(beta_list[i] // self.r_list[i]) % self.public_key.n for i in range(len(beta_list))]
        requested_data = [self.C % d_prime for d_prime in d_prime_list]
        print(requested_data)

    def get_request_message(self):
        return self.alpha_list


# If the RSA key length is equal to encoding_bit_length*2, it causes corrupted
# results about 20% of the time. If it's less than encoding_bit_length*2, it
# produces corrupted results 100% of the time. This will have to be investigated,
# but in the meantime, we simply ensure that the key is long enough.
encoding_bit_length = 512
min_rsa_bit_length = (encoding_bit_length * 2) + 1
rsa_bit_length = max(1024, min_rsa_bit_length - (min_rsa_bit_length % 256) + 256)
private_key = RSA.generate(rsa_bit_length, os.urandom)
public_key = private_key.publickey()

server = Server(public_key, private_key, encoding_bit_length, [57, 1023, 14, 4545, 23435])
client = Client(public_key, encoding_bit_length, [2, 3])

init_message = server.get_initiation_message()
client.process_initiation_message(init_message)

request_message = client.get_request_message()
server.process_request_message(request_message)

response_message = server.get_response_message()
client.process_response_message(response_message)
