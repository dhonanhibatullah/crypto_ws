from Crypto.Cipher import AES
import os


# AES-EAX always reset whenever the programs run, so everytime the program runs,
# we have to delete the old encrypted message
filename        = "encrypted.message"
tagname         = "encrypted.tag"
if os.path.exists("example/aes/" + filename) and os.path.exists("example/aes/" + tagname):
    os.remove("example/aes/" + filename)
    os.remove("example/aes/" + tagname)


# prepare the AES-EAX setup with 16-byte key
key     = "belajardenganguesangatlahasyikk!".encode()
cipher  = AES.new(key, AES.MODE_EAX)
nonce   = cipher.nonce


# encrypt the message and save
msg             = "Oh baby its triple, oh yeaah...".encode()
enc_msg, tag    = cipher.encrypt_and_digest(msg)

open("example/aes/" + filename, "wb").write(enc_msg)
open("example/aes/" + tagname, "wb").write(tag)


# open the message and tag
encrypted_message = open("example/aes/" + filename, "rb").read()
message_tag       = open("example/aes/" + tagname, "rb").read()


# decrypt the message and verify
decipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
real_msg = decipher.decrypt(encrypted_message)

try:
    decipher.verify(message_tag)
    print("The message is valid and authentic")
    print("[inputted message]  -> ", msg.decode())
    print("[decrypted message] -> ", real_msg.decode())

except ValueError:
    print("Key incorrect or message corrupted")