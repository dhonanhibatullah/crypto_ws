import rsa
import os.path as path


# generate and save new key pair if there's no existing key at the moment
# delete the private.pem and public.pem if you want to generate a new key pair
# - pk stands for public key
# - sk stands for secret (private) key
if not path.exists("example/rsa/public.pem") and not path.exists("rsa/private.pem"):
    pk, sk = rsa.newkeys(2048)
    open("example/rsa/public.pem", "wb").write(pk.save_pkcs1("PEM"))
    open("example/rsa/private.pem", "wb").write(sk.save_pkcs1("PEM"))
    print("RSA key pair generated!")


# open the .pem file
with open("example/rsa/public.pem", "rb") as f:
    pk = rsa.PublicKey.load_pkcs1(f.read())

with open("example/rsa/private.pem", "rb") as f:
    sk = rsa.PrivateKey.load_pkcs1(f.read())



################################################
#######        ENCRYPTING MESSAGE        #######
################################################

# set the following if to True if you want to test the encryption
if False:

    # encrypt and save the message
    msg         = "My name is Dhonan Nabil Hibatullah!"
    filename    = "encrypted.message" 
    enc_msg     = rsa.encrypt(msg.encode(), pk)

    if not path.exists("example/rsa/" + filename):
        open("example/rsa/" + filename, "wb").write(enc_msg)

    # decrypt the message
    enc_msg = open("example/rsa/" + filename, "rb").read()
    dec_msg = rsa.decrypt(enc_msg, sk).decode()
    
    # print to console
    print("ENCRYPTION TEST: ")
    print("[inputted message]  -> ", msg)
    print("[decrypted message] -> ", dec_msg)



#############################################
#######        SIGNING MESSAGE        #######
#############################################

# set the following to True if you want to test the signature
if False:

    # sign a message and save
    msg         = "This document is valid"
    filename    = "signature.sign"
    sign        = rsa.sign(msg.encode(), sk, 'SHA-256')

    if not path.exists("example/rsa/" + filename):
        open("example/rsa/" + filename, "wb").write(sign)

    # open the signature and check the authenticity
    sign = open("example/rsa/" + filename, "rb").read()
    res  = rsa.verify(msg.encode(), sign, pk)

    if res == 'SHA-256':
        print("\nSIGNATURE TEST: ")
        print(msg)