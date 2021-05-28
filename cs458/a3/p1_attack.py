#!/usr/bin/env python3

import sys
import csv
from collections import Counter

background = []
row_num = 0
csv_reader = csv.reader(open(sys.argv[1], 'r'), delimiter=',')
for row in csv_reader:
    for i in range(len(row)):
        if(row_num == 0):
            background.append([])
        background[i].append(row[i])
    row_num += 1
background_dict = []
for i in range(len(background)):
    background_dict.append(Counter(background[i]))

encrypt = []
row_num = 0
csv_reader = csv.reader(open(sys.argv[2], 'r'), delimiter=',')
for row in csv_reader:
    for i in range(len(row)):
        if(row_num == 0):
            encrypt.append([])
        encrypt[i].append(row[i])
    row_num += 1
encrypt_dict = []
for i in range(len(encrypt)):
    encrypt_dict.append(Counter(encrypt[i]))

translation = []
for i in range(len(background_dict)):
    bg_sorted = sorted(background_dict[i], key=background_dict[i].get)
    en_sorted = sorted(encrypt_dict[i], key=encrypt_dict[i].get)
    row_translation = {}
    for j in range(len(bg_sorted)):
        row_translation[en_sorted[j]] = bg_sorted[j]
    translation.append(row_translation)

row_num = 0
csv_writer = csv.writer(open(sys.argv[3], 'w'), delimiter=',')
for row_translation in translation:
    for k, v in row_translation.items():
        csv_writer.writerow([k, v])