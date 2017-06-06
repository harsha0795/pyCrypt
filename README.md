# pyCrypt (version 1.0)- Python Cryptography
Cryptogrphy Algorithms implemented using Python 3.6.0.

I have implemented the following Algorithms :
1. MD5 (Message Digest Algorithm)
2. RSA (Ronald Rivest, Adi Shamir, Leonard Adleman based Public Key Cryptography)
3. PGP (Pretty Good Privacy. An Email Encryption Algorithm although I have not added the Symmetric key Encrytpion)


# MD5 (Message Digest Algorithm)
The MD5 algorithm is a widely used hash function producing a 128-bit hash value. Creating a HASH out of the Message is an irreversible process. This means that once a HASH is created for a Message, it is not possible to produce the message from the HASH value. We tell that a pair of Message is Authentic if their hash values are same. But many message might end up with the same hash value.

So, Do we mean that the two different messages are same ?. Unfortunately and luckily YES. However, it is worth noting that the probability of 2 different messages arriving at the same hash value is almost 0.

# Snippet
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

### OUTPUT
```python
ac4a2ff915edefbc151938a70f4a6db3 <= "He is a good person"
```
