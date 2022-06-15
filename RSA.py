# Author-Trisham Bharat Patil
# License-Free
# This is an implementation of RSA public key cryptography.
import random
import math

# Select p and q, such that both are prime and p!=q.


def primesInRange(x, y):
    prime_list = []
    for n in range(x, y):
        isPrime = True

        for num in range(2, n):
            if n % num == 0:
                isPrime = False

        if isPrime:
            prime_list.append(n)
    return prime_list


prime_list = primesInRange(2, 100)
randomPrime = random.sample(prime_list, 2)
print('Generated random prime number: ', randomPrime)
p = randomPrime[0]
q = randomPrime[1]

# n=p*q
n = p * q

# Calculating Euler Totient Function.
phi_n = (p - 1) * (q - 1)


# Calculating public key e, such that phi_n and e are relatively prime or gcd(phi_n,e)=1.
def publicKeyGenerator(phi_n):
    public_key_list = []
    for n in range(1, phi_n):
        if math.gcd(n, phi_n) == 1 & n < phi_n:
            isRelativePrime = True
        else:
            isRelativePrime = False

        if isRelativePrime:
            public_key_list.append(n)
    return public_key_list


public_key_list = publicKeyGenerator(phi_n)
e = random.choice(public_key_list)
print("Your public key value is:", e)


# Calculating private key d.
# Extended Euclidean Algorithm
def eea(a, b):
    if a % b == 0:
        return b, 0, 1
    else:
        gcd, s, t = eea(b, a % b)
        s = s - ((a // b) * t)
        print("%d = %d*(%d) + (%d)*(%d)" % (gcd, a, t, s, b))
        return gcd, t, s


# Multiplicative Inverse
def mult_inv(e, r):
    gcd, s, _ = eea(e, r)
    if gcd != 1:
        return None
    else:
        if s < 0:
            print("s=%d. Since %d is less than 0, s = s(modr), i.e., s=%d." % (s, s, s % r))
        elif s > 0:
            print("s=%d." % s)
        return s % r


d = mult_inv(e, phi_n)
print("Your private key value is:", d)

# Encryption process.
M = int(input("Please enter a numeric value for message to be transmitted: "))
M_exponential = M**e
C = M_exponential % n # Ciphertext
print("Your Ciphertext is: ",C)
# Decryption process.
C_exponential = C**d
M = C_exponential % n # Original Message
print("Your original message is: ", M)
