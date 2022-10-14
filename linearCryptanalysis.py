#####           Linear Cryptanalysis for a              #####
#####   Simple Substitution-Permutation Network Cipher  #####

## Cipher Reference:  http://www.engr.mun.ca/~howard/Research/Papers/ldc_tutorial.html

## The program produces the a linear cryptanalysis based on the ##  given a collection of distinct pairs of plaintext and
##  ciphertext. The plaintexts and ciphertext need to be stored ##  in two files, respectively, one for each line.

## Enter command like the following to run the program:
## "./linearCryptanalysis.py (plaintextsFile) (ciphertextsFile)" 

import sys

# check input files
if len(sys.argv) != 3:
    print("number of argument not matches, run the program with two files (plaintexts and ciphertexts)")
    exit()


# reads input files and stored them in blockPairs
def readIn():
    blockPairs = []
    plaintexts, ciphertexts =  open(sys.argv[1], 'r'), open(sys.argv[2], 'r')
    nextline = plaintexts.readline()
    while nextline:
        blockPairs += [[int(nextline,2), int(ciphertexts.readline(),2)]]
        nextline = plaintexts.readline()
    return blockPairs

print(readIn())
