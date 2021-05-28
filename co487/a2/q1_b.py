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
k_5_58 = 0
k_5_1316 = 0
for j in range(0b10000):
    for k in range(0b10000):
        counter = 0
        for i in range(20000):
            v_4_58 = int(ciphertexts[i][4:8], 2) ^ j
            v_4_1316 = int(ciphertexts[i][12:16], 2) ^ k
            u_4_58 = sBoxInverse(v_4_58)
            u_4_1316 = sBoxInverse(v_4_1316)

            plaintextDigits = int(plaintexts[i])

            linApprox = extractBit(u_4_58, 1, 4) ^ extractBit(u_4_58, 3, 4) ^ extractBit(u_4_1316, 1, 4) ^ extractBit(u_4_1316, 3, 4) ^ extractBit(plaintextDigits, 6, 16) ^ extractBit(plaintextDigits, 8, 16) ^ extractBit(plaintextDigits, 9, 16)
            if(linApprox):
                counter += 1
            
        bias = counter / 20000 - 0.5
        if(abs(bias) > maxBias):
            maxBias = abs(bias)
            k_5_58 = j
            k_5_1316 = k

print(k_5_58)
print(k_5_1316)