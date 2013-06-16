from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime
from functools import reduce
from operator import mul
import math
import os


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
    D = reduce(mul, d_list, 1)
    C = 0
    for i in range(len(a_list)):
        D_i = D // d_list[i]
        y_i = modinv(D_i, d_list[i])
        C += (a_list[i] * D_i * y_i) % D
    return C


class Alice(object):
    def __init__(self, public_key, private_key, secret_data):
        self.secret_data = secret_data
        self.public_key = public_key
        self.private_key = private_key

        max_secret_bits = math.ceil(math.log(max(secret_data), 2))
        d_bit_length = max([512, max_secret_bits])
        d_list = create_pairwise_coprime_integers(d_bit_length, public_key.n, len(secret_data))
        
        self.C = solve_crt(self.secret_data, d_list)
        self.T = [pow(d, public_key.e, public_key.n) for d in d_list]

    def get_initiation_message(self):
        return (self.C, self.T)

    def get_response_message(self):
        return self.beta_list

    def process_request_message(self, message):
        self.beta_list = [pow(alpha, self.private_key.d, self.public_key.n) for alpha in message]

class Bob(object):
    def __init__(self, public_key, requested_data_indices):
        self.public_key = public_key
        self.requested_data_indices = requested_data_indices

    def process_initiation_message(self, message):
        (self.C, T) = message
        self.r_list = create_pairwise_coprime_integers(512, self.public_key.n, len(self.requested_data_indices))
        self.alpha_list = [(pow(self.r_list[i], self.public_key.e, self.public_key.n) * T[self.requested_data_indices[i]]) % self.public_key.n for i in range(len(self.requested_data_indices))]

    def process_response_message(self, message):
        beta_list = message
        d_prime_list = [(beta_list[i] // self.r_list[i]) % self.public_key.n for i in range(len(beta_list))]
        requested_data = [self.C % d_prime for d_prime in d_prime_list]
        print(requested_data)

    def get_request_message(self):
        return self.alpha_list


private_key = RSA.generate(1024, os.urandom)
public_key = private_key.publickey()
alice = Alice(public_key, private_key, [57, 1023, 14, 4545, 565656])
bob = Bob(public_key, [2, 3])

init_message = alice.get_initiation_message()
bob.process_initiation_message(init_message)

request_message = bob.get_request_message()
alice.process_request_message(request_message)

response_message = alice.get_response_message()
bob.process_response_message(response_message)
