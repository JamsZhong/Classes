import sys

def sBoxInverse(n):
    if(n == 14):
        return 0
    elif(n == 4):
        return 1
    elif(n == 13):
        return 2
    elif(n == 1):
        return 3
    elif(n == 2):
        return 4
    elif(n == 15):
        return 5
    elif(n == 11):
        return 6
    elif(n == 8):
        return 7
    elif(n == 3):
        return 8
    elif(n == 10):
        return 9
    elif(n == 6):
        return 10
    elif(n == 12):
        return 11
    elif(n == 5):
        return 12
    elif(n == 9):
        return 13
    elif(n == 0):
        return 14
    else:
        return 15

def extractBit(n, pos, l):
    binary = bin(n)
    binary = binary[2:]

    while(len(binary) < l):
        binary = '0' + binary
    return int(binary[pos])

cipherFile = open("Q1_ciphertext.txt", "r")
ciphertexts = cipherFile.readlines()

plainFile = open("Q1_plaintext.txt", "r")
plaintexts = plainFile.readlines()

maxBias = 0
bias = 0
key = 0
for a in range(0b10000):
    for b in range(0b10000):
        for c in range(0b10000):
            for d in range(0b10000):
                counter = 0
                for i in range(20000):
                    v_4_14 = int(ciphertexts[i][0:4], 2) ^ a
                    v_4_58 = int(ciphertexts[i][4:8], 2) ^ b
                    v_4_912 = int(ciphertexts[i][8:12], 2) ^ c
                    v_4_1316 = int(ciphertexts[i][12:16], 2) ^ d

                    u_4_14 = sBoxInverse(v_4_14)
                    u_4_58 = sBoxInverse(v_4_58)
                    u_4_912 = sBoxInverse(v_4_912)
                    u_4_1316 = sBoxInverse(v_4_1316)

                    plaintextDigits = int(plaintexts[i])

                    linApprox = extractBit(u_4_14, 1, 4) ^ extractBit(u_4_58, 1, 4) ^ extractBit(u_4_912, 1, 4) ^ extractBit(u_4_1316, 1, 4) ^ extractBit(plaintextDigits, 0, 16) ^ extractBit(plaintextDigits, 3, 16) ^ extractBit(plaintextDigits, 8, 16) ^ extractBit(plaintextDigits, 11, 16)
                    if(linApprox):
                        counter += 1
                    
                bias = counter / 20000 - 0.5
                if(abs(bias) > maxBias):
                    maxBias = abs(bias)
                    key = a << 12 | b << 8 | c << 4 | d

print(bin(key))
print(maxBias)