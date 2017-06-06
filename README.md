
.
# pyCrypt (version 1.0)- Python Cryptography
Cryptogrphy Algorithms implemented using Python 3.6.0.

I have implemented the following Algorithms :
1. MD5 (Message Digest Algorithm)
2. RSA (Ronald Rivest, Adi Shamir, Leonard Adleman based Public Key Cryptography)
3. PGP (Pretty Good Privacy. An Email Encryption Algorithm although I have not added the Symmetric key Encrytpion)


# MD5 (Message Digest Algorithm) RFC 1321
The MD5 algorithm is a widely used hash function producing a 128-bit hash value. Creating a HASH out of the Message is an irreversible process. This means that once a HASH is created for a Message, it is not possible to produce the message from the HASH value. We tell that a pair of Message is Authentic if their hash values are same. But many message might end up with the same hash value.

So, Do we mean that the two different messages are same ?. Unfortunately and luckily YES. However, it is worth noting that the probability of 2 different messages arriving at the same hash value is almost 0.

## Snippet
```PYTHON
def md5(message):
 
    message = bytearray(message) #copy our input into a mutable buffer
    orig_len_in_bits = (8 * len(message)) & 0xffffffffffffffff
    message.append(0x80)
    while len(message)%64 != 56:
        message.append(0)
    message += orig_len_in_bits.to_bytes(8, byteorder='little')
 
    hash_pieces = init_values[:]
 
    for chunk_ofst in range(0, len(message), 64):
        a, b, c, d = hash_pieces
        chunk = message[chunk_ofst:chunk_ofst+64]
        for i in range(64):
            f = functions[i](b, c, d)
            g = index_functions[i](i)
            to_rotate = a + f + constants[i] + int.from_bytes(chunk[4*g:4*g+4], byteorder='little')
            new_b = (b + left_rotate(to_rotate, rotate_amounts[i])) & 0xFFFFFFFF
            a, b, c, d = d, new_b, b, c
        for i, val in enumerate([a, b, c, d]):
            hash_pieces[i] += val
            hash_pieces[i] &= 0xFFFFFFFF
 
    return sum(x<<(32*i) for i, x in enumerate(hash_pieces)

```

## OUTPUT
```cmd
ac4a2ff915edefbc151938a70f4a6db3 <= "He is a good person"
```

# RSA Public Key Cryptography RFC 3447
RSA is an algorithm used by modern computers to encrypt and decrypt messages. It is based on the Asymmetric Encryption or Public Key Cryptography. In asymmetric encryption, there are 2 keys i.e. a private key(KR) and a public key(KU). If any of these keys are used for encryption, the other key is used for decryption. This can only mean that there exist a mathematical relationship between both the keys.
## Steps in RSA Cryptography
There are 4 major steps in RSA crytpography:
1. Key Generation (Generate Public Key and Private Key)
2. Key Distribution
3. Encryption
4. Decryption
### Key Generation
![alt text](https://raw.githubusercontent.com/harsha0795/pyCrypt/master/img/RSA.png)
### Key Distribution
Suppose 2 persons say Alice and Bob wants to securely communicate with each other with Alice as the sender, Alice encrypts the message using Bob's public key and send the Message. Bob uses his private key and successfully decrypt the message.
### RSA Encryption
Encrytpion is done Using Bob's public key in the following manner:
![alt text](https://raw.githubusercontent.com/harsha0795/pyCrypt/master/img/RSAEN.png)
### RSA Decryption
Decryption is done using Bob's private key in the following manner:
![alt text](https://raw.githubusercontent.com/harsha0795/pyCrypt/master/img/RSADE.png)
### Snippet
```python
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
```
### Output
```cmd
Performing the RSA Cryptography on the Encrypted Hash to get the following Ciphertext
[114, 75, 108, 41, 118, 18, 114, 75, 54, 68, 45, 108, 13, 113, 68, 75, 108, 113, 114, 13, 41, 57, 57, 114, 45, 13, 38, 45, 39, 82, 45, 113]
Applying the RSA Cryptography to Decrypt the above Ciphertext
b10a8db164e0754105b7a99be72e3fe5
```
