import math
import md5
import rsa
import zip

def encrypt(message,public):
    '''
    FUNCTION
    ----------
    PGP follows the Following steps for Encryption according to OpenPGP Standard RFC 4880
    1. Create Secure Hash function for the message
    2. Perform RSA crytpography on the Hashed Message
    3. Concatenate the Original message along with the ciphertext obtained at the previous step
    4. Perform ZIP compression algorithm on the concatenation and send the final ZIP

    PARAMETERS
    ----------
    1. Message : Type <str>. Plaintext which is to be encrypted
    2. Public Key : Type <tuple> containing the pairs (e,n).

    RETURN
    -------
    pgpCipher : Zipped Ciphertext of type <Bytes>

    For More information, please read RFC 4880, RFC 3447, RFC 1321
    '''
    message=message.encode('ascii')
    # Step 1.
    print("1. Applying the HASH Function on the Message")
    md5hashed=md5.md5_to_hex(md5.md5(message))
    print(md5.md5_to_hex(md5.md5(message)),' <= "',message.decode('ascii'),'"', sep='')
    # Step 2.
    print("Performing the RSA Cryptography on the Encrypted Hash")
    ciphertext=rsa.encrypt(public,md5hashed)
    # Step 3.
    ctext=''
    for i in ciphertext:
        ctext=ctext+str(i)+' '
    ciphertext=ctext
    print("Concatenating RSA Ciphertext with the Original Message")
    concat_text=ciphertext+'!!!'+message.decode('ascii')
    byte_text=concat_text.encode('ascii')
    # Step 4.
    print("Applying ZIP compression Algorithm on the Concatenation Text")
    pgpCipher=zip.compress(byte_text)
    print("Successfully Performed PGP encryption !")
    return pgpCipher

def decrypt(pgpCipher,private):
    '''
    FUNCTION
    ----------
    PGP follows the Following steps for Decryption according to OpenPGP Standard RFC 4880.
    1. Apply the ZIP Decompression Algorithm on the PGP Cipher Text to get the concatenated text.
    2. De-concatenate the Concatenated text to split into ciphertext and plain text.
    3. Apply RSA cryptography to decrypt the ciphertext into the HASHED message.
    4. Apply the HASH function on the separated plain text.
    5. Compare the two hash functions. If the two hashes are same, the PGP decryption is successful.

    PARAMETERS
    ----------
    1. PGPCiphertext : Type <Bytes>. Ciphertext which is to be decrypted
    2. Private Key : Type <tuple> containing the pairs (d,n).

    RETURN
    -------
    Message : Original type <str>

    For More information, please read RFC 4880, RFC 3447, RFC 1321
    '''
    print("Applying the PGP decryption Algorithm")
    print("1. Applying the ZIP Decompression Algorithm on the PGP Cipher Text")
    concat_text=(zip.decompress(pgpCipher)).decode('ascii')
    print("2. De-concatenating the Concatenated text")
    separate=concat_text.split('!!!')
    cipher=[int(i) for i in separate[0].split()]
    print("3. Applying the RSA Cryptography to Decrypt the Ciphertext")
    md5hashed=rsa.decrypt(private,cipher)
    print("4. Applying the HASH function for the De-concatenated plaintext")
    print(md5.md5_to_hex(md5.md5(separate[1].encode('ascii'))),' <= "',separate[1],'"', sep='')
    print("5. Comparing the HASH of Decrypted Ciphertext and HASHED Plaintext")
    md5hashed1=md5.md5_to_hex(md5.md5(separate[1].encode('ascii')))
    if md5hashed==md5hashed1:
        print ("Successfully Decrypted the Message")
        return (separate[1])
    else:
        print ("Invalid Private Key Provided")
        return 0

if __name__=='__main__':
    message=str(input("Enter the Message to be Encrypted : "))
    public,private=rsa.keyGen()
    print("Public Key :",public)
    print("Private Key :",private)
    cipher=encrypt(message,public)
    print("Please provide the ciphertext and the private key to be decrypted.")
    print(cipher,private)
    decrypt(cipher,private)

