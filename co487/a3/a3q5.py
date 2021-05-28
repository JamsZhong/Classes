import os
import sys

## Part A

# Calculates the secret key given phi = a and e = b
def EEA_RSA(a, b):
    row1 = (1, 0)
    row2 = (0, 1)
    r1 = a
    r2 = b
    
    while(r2 != 1):
        i = 0
        while(r1 - r2 * (i + 1) > 0):
            i += 1
        
        temp_row1, temp_row2 = row1[0] - row2[0] * i, row1[1] - row2[1] * i
        row1 = row2
        row2 = (temp_row1, temp_row2)
        
        temp_r = r1 - r2 * i
        r1 = r2
        r2 = temp_r
    return row2[1]
    
n = 39271
e = 39

p = 0
q = 0
for i in range(1, 39271):
    if(n % i == 0):
        p = i
        q = n / i

phi = (p - 1) * (q - 1)
d = EEA_RSA(phi, e)
while(d < 0):
    d += phi
    
print(d)

## Part B 

# Calculates a^b mod n using repeated square-and-multiply algorithm
def RSM_Exp(a, b, n):
    if(b == 0):
        return 1
    elif(b % 2 == 0):
        return RSM_Exp(a, b / 2, n)**2 % n
    else:
        return (RSM_Exp(a, b - 1, n) * (a % n)) % n

msg = 42
print(RSM_Exp(msg, e, n))