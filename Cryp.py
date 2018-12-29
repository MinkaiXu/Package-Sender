from Crypto.Cipher import AES
from PacketProcess import *
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA
'''
    AES_encrypt encrypt a message by AES algorithm
    requirements:
    1)iv (16 bytes)
    2)key (16,24,32 bytes)
'''
def AES_encrypt(message,key,iv,mode = AES.MODE_CBC):
    key = hexinput(key)
    iv = hexinput(iv)
    message = hexinput(message)
    obj = AES.new(key, mode, iv)
    padnum = 16 - len(message) % 16
    message = message + padnum * chr(padnum)
    ciphertext = obj.encrypt(message)
    return hexoutput(ciphertext)
'''
    AES_decrypt can decrypt a message by AES
    iv should be 16 bytes
    key should be 16,24,32 bytes
'''
def AES_decrypt(ciphertext,key,iv,mode=AES.MODE_CBC):
    key = hexinput(key)
    iv = hexinput(iv)
    cipher = AES.new(key, mode, iv)
    ciphertext = hexinput(ciphertext)
    message = cipher.decrypt(ciphertext)
    padnum = ord(message[len(message)-1])
    message = message[:len(message) - padnum]
    return hexoutput(message)


'''
   Hash_SHA256 encode a content with hash algorithm
'''
def Hash_SHA256(content):
    h = SHA256.new()
    h.update(content)
    return h.hexdigest()


'''
    RSAkey can generate a pair of rsa key
    and store public key in     filename + '-public.pem'
        store private key in     filename + '-private.pem'
'''
def RSAkey(filename):
    # random generater
    random_generator = Random.new().read
    # rsa object
    rsa = RSA.generate(1024, random_generator)
    # generate rsa key
    private_pem = rsa.exportKey()
    with open(filename + '-private.pem', 'w') as f:
        f.write(private_pem)
    public_pem = rsa.publickey().exportKey()
    with open(filename + '-public.pem', 'w') as f:
        f.write(public_pem)
    return 0

'''
    RSA_encrypt can encrypt a message with loaded public key 
'''
def RSA_encrypt(filename,message):
    message = hexinput(message)
    with open(filename) as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        cipher = Cipher_pkcs1_v1_5.new(rsakey)
        return hexoutput(cipher.encrypt(message))

'''
    RSA_decrypt can decrypt a message with loaded private key
'''
def RSA_decrypt(filename,message):
    with open(filename) as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        sentinel = Random.new().read(15 + len(hexinput(message)))
        cipher = Cipher_pkcs1_v1_5.new(rsakey)
        return hexoutput(cipher.decrypt(hexinput(message),sentinel))



'''
    RSA_sig can sign a message with private key
'''
def RSA_sig(filename,message):
    message = hexinput(message)
    with open(filename) as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        signer = Signature_pkcs1_v1_5.new(rsakey)
        h = SHA256.new(message)
        signature = signer.sign(h)
        return hexoutput(signature)

'''
    RSA_sig_check can check the signature
'''
def RSA_sig_check(filename,message,signature):
    message = hexinput(message)
    with open(filename) as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        verifier = Signature_pkcs1_v1_5.new(rsakey)
        h = SHA256.new(message)
        return verifier.verify(h, hexinput(signature))













