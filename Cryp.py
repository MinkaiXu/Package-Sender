from Crypto.Cipher import AES
from PacketProcess import *
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA
'''
    PackContentAES can encrypt a message by AES
    iv should be 16 bytes
    key should bt 16,24,32 bytes
'''
def PackContentAES(message,key,iv,mode = AES.MODE_CBC):
    key = hexinput(key)
    iv = hexinput(iv)
    message = hexinput(message)
    obj = AES.new(key, mode, iv)
    padnum = 16 - len(message) % 16
    message = message + padnum * chr(padnum)
    ciphertext = obj.encrypt(message)
    return hexoutput(ciphertext)
'''
    PackContentAESdecry can decrypt a message by AES
    iv should be 16 bytes
    key should be 16,24,32 bytes
'''
def PackContentAESdecry(ciphertext,key,iv,mode=AES.MODE_CBC):
    key = hexinput(key)
    iv = hexinput(iv)
    cipher = AES.new(key, mode, iv)
    ciphertext = hexinput(ciphertext)
    message = cipher.decrypt(ciphertext)
    padnum = ord(message[len(message)-1])
    message = message[:len(message) - padnum]
    return hexoutput(message)
'''
a = PackContentAES("sillybsillybzhengjilaisillyb","123456789012345678901234","1230981230984567")
p = PackContentAESdecry(a,"123456789012345678901234","1230981230984567")
print a
print p
'''

'''
    PackContentSha256 can hash256 a content
'''
def PackContentSha256(content):
    h = SHA256.new()
    h.update(content)
    return h.hexdigest()
'''
print PackContentSha256("sillyb")
'''

'''
    PackContentRSAkeygen can generate a pair of rsa key
    while pubkey in     filename + '-public.pem'
          prikey in     filename + '-private.pem'
'''
def PackContentRSAkeygen(filename):
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
    PackContentRSA can crypt a message with pubkey
'''
def PackContentRSA(filename,message):
    message = hexinput(message)
    with open(filename) as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        cipher = Cipher_pkcs1_v1_5.new(rsakey)
        return hexoutput(cipher.encrypt(message))

'''
    PackContentRSA can decrypt a message with prikey
'''
def PackContentRSAdecry(filename,message):
    with open(filename) as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        sentinel = Random.new().read(15 + len(hexinput(message)))
        cipher = Cipher_pkcs1_v1_5.new(rsakey)
        return hexoutput(cipher.decrypt(hexinput(message),sentinel))

'''
#PackContentRSAkeygen("testRSA")
a = PackContentRSA("D:/python doc/PackSender/aaaaa-public.pem","22522222222222222222222666666666666666eeeeeeeeeeeeeeee")
print a
b = PackContentRSAdecry("D:/python doc/PackSender/aaaaa-private.pem",a)
print b
'''

'''
    PackContentRSASig can sign a message with prikey
'''
def PackContentRSASig(filename,message):
    message = hexinput(message)
    with open(filename) as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        signer = Signature_pkcs1_v1_5.new(rsakey)
        h = SHA256.new(message)
        signature = signer.sign(h)
        return hexoutput(signature)

'''
    PackContentRSA can decrypt a message with prikey
'''
def PackContentRSASigCheck(filename,message,signature):
    message = hexinput(message)
    with open(filename) as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        verifier = Signature_pkcs1_v1_5.new(rsakey)
        h = SHA256.new(message)
        return verifier.verify(h, hexinput(signature))

'''
a = PackContentRSASig("D:/python doc/PackSender/aaaaa-private.pem","sillybsiilybsiiiidasjsillybbbbbbb")
print a
b = PackContentRSASigCheck("D:/python doc/PackSender/aaaaa-public.pem","sillybsiilybsiiiidasjsillybbbbbbb",a)
print b
'''











