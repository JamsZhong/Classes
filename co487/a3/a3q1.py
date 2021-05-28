import os
import base64
import getpass
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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
    
    # Derive key using PBKDF2 as a KDF with 100000 iterations
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=salt, iterations=100000)
    key = kdf.derive(password.encode('utf-8'))
    
    # Pack the message using PKCS7
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext)
    padded += padder.finalize()
    
    # Encrypt packed message using AES-128 in CBC mode
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    
    # Use HMAC to generate MAC
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(ciphertext)
    
    # Join iv, salt, ciphertext, and MAC to send to decryptor
    ciphertext = b"".join([iv, salt, ciphertext, h.finalize()])
    
    # Return the combined result to standard out using URL safe encoding
    sys.stdout.write(str(base64.urlsafe_b64encode(ciphertext), 'utf-8'))

    ### END: This is what you have to change

def decryption():
    # Grab stdin.
    stdin_contents = "".join( sys.stdin.readlines() )
    
    # Cinvert to bytes for the ciphertext
    ciphertext = stdin_contents.encode('utf-8')
    
    ### START: This is what you have to change

    # Obtain combined ciphertext
    password = getpass.getpass()
    ciphertext = base64.urlsafe_b64decode(ciphertext)
    
    # Obtain the various parts of the message by splitting the bytes according to the input format
    iv = ciphertext[0:16]
    salt = ciphertext[16:32]
    mac = ciphertext[-32:]
    ciphertext = ciphertext[32:-32]
    
    # Generate key using password and same salt as encryptor
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=salt, iterations=100000)
    key = kdf.derive(password.encode('utf-8'))
    
    # Generate MAC for received ciphertext using key
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(ciphertext)
    
    # Verify signature of received message matches sent message
    try:
        h.verify(mac)
    except:
        sys.stderr.write("Decryption failed. Signatures don't match.\n")
        sys.exit()
    
    # Define decryptor using key and provided iv and unpadder
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    
    unpadder = padding.PKCS7(128).unpadder()

    # Attempt to decrypt.
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()
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
