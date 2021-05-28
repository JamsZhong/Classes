import os
import sys
import hashlib

# A3 Q2 Part C

alice_hash = '27087f4e74ff61f8062d0ae78a21f713ca61591a4fb404fe21828aa549e585d0'
alice_salt = '60679939'

f = open("word_list.txt", 'r')

count = 0
for word in f:
    pass_guess_w = word.capitalize()
    for num in range(0, 10000):
        pass_guess_wn = pass_guess_w[:-1] + str(num)
        for sp_char in ['!', '?', '*', '$', '#', '&']:
            pass_guess_final = pass_guess_wn + sp_char
            
            pass_salted = alice_salt + pass_guess_final
            pass_hash = hashlib.sha256(pass_salted.encode()).hexdigest()
            count += 1
            
            if(pass_hash == alice_hash):
                print(pass_guess_final)
                print(count)
                sys.exit()