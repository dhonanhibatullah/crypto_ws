import hashlib
import os.path as path


# we are going to demonstrate how hashing could secure access
# first, let us determine the password and hash it with SHA256
pw          = "whiteblack100"
filename    = "password.key"
hashed_pw   = hashlib.sha256(pw.encode()).hexdigest().encode()

if not path.exists("example/sha256/" + filename):
    open("example/sha256/" + filename, "wb").write(hashed_pw)


# next, create a "login menu" on console
print("\n------[ SHA-256 Test ]------")
input_pw    = input("password: ")


# compare the file and the password
hashed_input_pw = hashlib.sha256(input_pw.encode()).hexdigest().encode()
hashed_pw       = open("example/sha256/" + filename, "rb").read()

if hashed_input_pw == hashed_pw:
    print("\nACCESS GRANTED\n")
else:
    print("\nACCESS DENIED\n")