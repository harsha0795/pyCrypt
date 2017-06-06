import math
import numpy as np
from random import randint


def PrimeGen(n=10000):
    """ Returns  a list of primes < n. Used Robert William method of high speed prime generation. """
    assert n>=2
    sieve = np.ones(n/2, dtype=np.bool)
    for i in range(3,int(n**0.5)+1,2):
        if sieve[i/2]:
            sieve[i*i/2::i] = False
    return np.r_[2, 2*np.nonzero(sieve)[0][1::]+1]

def lcm(p,q):
    ''' Computes LCM between two Integers p,q'''
    return (p*q)/math.gcd(p,q)

def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError
    return x % m

def mult_inverse(e, lamda):
    ''' Using the Euclidian extended algorithm '''
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_lamda = lamda 
    
    while e > 0:
        temp1 = temp_lamda/e
        temp2 = temp_lamda - temp1 * e
        temp_lamda = e
        e = temp2
        
        x = x2- temp1* x1
        y = d - temp1 * y1
        
        x2 = x1
        x1 = x
        d = y1
        y1 = y

    if temp_lamda == 1:
        return d + lamda

def keyGen():
    ''' Generate  Keypair '''
    i_p=randint(0,20)
    i_q=randint(0,20)
    # Instead of Asking the user for the prime Number which in case is not feasible,
    # generate two numbers which is much highly secure as it chooses higher primes
    while i_p==i_q:
        continue
    primes=PrimeGen(100)
    p=primes[i_p]
    q=primes[i_q]
    #computing n=p*q as a part of the RSA Algorithm
    n=p*q
    #Computing lamda(n), the Carmichael's totient Function.
    # In this case, the totient function is the LCM(lamda(p),lamda(q))=lamda(p-1,q-1)
    # On the Contrary We can also apply the Euler's totient's Function phi(n)
    #  which sometimes may result larger than expected
    lamda_n=int(lcm(p-1,q-1))
    e=randint(1,lamda_n)
    #checking the Following : whether e and lamda(n) are co-prime
    while math.gcd(e,lamda_n)!=1:
        e=randint(1,lamda_n)
    #Determine the modular Multiplicative Inverse
    d=modinv(e,lamda_n)
    #return the Key Pairs
    # Public Key pair : (e,n), private key pair:(d,n)
    return ((e,n),(d,n))

def encrypt(pk,message):
    """ Perform RSA Encryption Algorithm"""
    key, n = pk
    #Convert each letter in the plaintext to numbers based on the character using a^b mod m
    cipher = [(ord(char) ** key) % n for char in message]
    #Return the array of bytes
    return cipher

def decrypt(pk,cipher):
    '''Perform RSA Decryption Algorithm '''
    key, n = pk
    #Generate the plaintext based on the ciphertext and key using a^b mod m
    message = [chr((int(char) ** key) % n) for char in cipher]
    #Return the array of bytes as a string
    return ''.join(message)



    
    
        





    