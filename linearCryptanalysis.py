#####           Linear Cryptanalysis for a              #####
#####   Simple Substitution-Permutation Network Cipher  #####

## Cipher Reference:  http://www.engr.mun.ca/~howard/Research/Papers/ldc_tutorial.html

## The program produces the a linear cryptanalysis based on the ##  given a collection of distinct pairs of plaintext and
##  ciphertext. The plaintexts and ciphertext need to be stored ##  in two files, respectively, one for each line.

## Enter command like the following to run the program:
## "./linearCryptanalysis.py (plaintextsFile) (ciphertextsFile)" 

import sys

if len(sys.argv) != 3:
    print("number of argument not matches, run the program with two files (plaintexts and ciphertexts)")
    exit()

plaintexts, ciphertexts =  open(sys.argv[1], 'r'), open(sys.argv[2], 'r')

def printIn():
        i = 1
        pt, ct = plaintexts.readline(), ciphertexts.readline()
        while pt:
            print('plaintext', i, ':', pt, " ", 'ciphertext', i, ':', ct)
            pt, ct = plaintexts.readline(), ciphertexts.readline()
            i += 1

printIn()
