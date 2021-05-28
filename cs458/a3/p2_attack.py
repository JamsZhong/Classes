#!/usr/bin/env python3

import sys
from fractions import gcd
from functools import reduce

encrypt = [int(i) for i in open(sys.argv[1], 'r').readlines()]
decrypt = []

for t in range(min(encrypt)):
    minus_t = [i - t for i in encrypt]
    s = reduce(gcd, minus_t)
    decrypt = [int(i / s) for i in minus_t]
    if(max(decrypt) < 2 ** 32 and t < s):
        break

output = open(sys.argv[2], 'w')
for num in decrypt:
    output.write(str(num) + '\n')
