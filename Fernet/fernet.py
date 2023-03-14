import os
import base64
import getpass
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def encryption():
    # First, we grab the contents of stdin and make sure it's a single string
    plaintext = "".join( sys.stdin.readlines() ).encode('utf-8')

    # Use getpass to prompt the user for a password
    password = getpass.getpass()
    password2 = getpass.getpass("Enter password again:")

    # Do a quick check to make sure that the password is the same!
    if password != password2:
        sys.stderr.write("Passwords did not match")
        sys.exit()

    ### START: This is what you have to change

    # The key for our symmetric system will be the hash of the password
    h = hashes.Hash(hashes.SHA256())
    h.update( password.encode('utf-8'))
    key = base64.urlsafe_b64encode(h.finalize())

    # Define the Fernet
    f = Fernet(key)

    # Actually do the encryption
    ciphertext = f.encrypt(plaintext)

    # Return the ciphertext to standard out
    sys.stdout.write(ciphertext.decode('utf-8'))

    ### END: This is what you have to change

def decryption():
    # Grab stdin.
    stdin_contents = "".join( sys.stdin.readlines() )
    
    # Cinvert to bytes for the ciphertext
    ciphertext = stdin_contents.encode('utf-8')
    
    ### START: This is what you have to change

    # Derive the key in the same way we did in encryption
    password = getpass.getpass()
    h = hashes.Hash(hashes.SHA256())
    h.update( password.encode('utf-8'))
    key = base64.urlsafe_b64encode(h.finalize())
    f = Fernet(key)

    # Attempt to decrypt.
    try:
        plaintext = f.decrypt(ciphertext)
    except:
        sys.stderr.write("Decryption failed. Check your password or the file.\n")
        sys.exit()

    # Return the plaintext to stdout
    sys.stdout.write(plaintext.decode('utf-8'))

    ### END: This is what you have to change

try:
    mode = sys.argv[1]
    assert( mode in ['-e', '-d'] )
except:
    sys.stderr.write("Unrecognized mode. Usage:\n")
    sys.stderr.write("'python3 fernet.py -e' encrypts stdin and returns the ciphertext to stdout\n")
    sys.stderr.write("'python3 fernet.py -d' decrypts stdin and returns the plaintext to stdout\n")

if mode == '-e':
    encryption()
elif mode == '-d':
    decryption()
