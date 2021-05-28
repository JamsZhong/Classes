import os
import sys
import hashlib

## A3 Q2 Part B

alice_hash = '5c34667ce6b6765bb251b637d5395caf2ff90f8375a0e1e6563ea9a3b276de56'
alice_salt = '36685719'

for i in range(0, 1000000):
    pass_guess = str(i).zfill(6)
    pass_salted = alice_salt + pass_guess
    pass_hash = hashlib.sha256(pass_salted.encode()).hexdigest()
    
    if(pass_hash == alice_hash):
        print(pass_guess)
        sys.exit()
        
        