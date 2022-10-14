#####           Linear Cryptanalysis for a              #####
#####   Simple Substitution-Permutation Network Cipher  #####

## Cipher Reference:  
##  http://www.engr.mun.ca/~howard/Research/Papers/ldc_tutorial.html

## The program produces the a linear cryptanalysis based on the 
##  given a collection of distinct pairs of plaintexts and
##  ciphertexts. The plaintexts and ciphertext need to be stored
##  in two files, respectively. One text for each line.

## Enter command like the following to run the program:
## "./linearCryptanalysis.py (plaintextsFile) (ciphertextsFile)" 

import sys
from turtle import back

# check input files
if len(sys.argv) != 3:
    print("number of argument not matches, run the program with two files (plaintexts and ciphertexts)")
    exit()


# reads input files and stored them into a list of decimal numbers
def readIn() -> list: 
    blockPairs = []
    plaintexts, ciphertexts =  open(sys.argv[1], 'r'), open(sys.argv[2], 'r')
    nextline = plaintexts.readline()
    while nextline:
        blockPairs += [[int(nextline,2), int(ciphertexts.readline(),2)]]
        nextline = plaintexts.readline()
    return blockPairs

# creates a list indicating the both directions of a substitution box
#   (or permutation)
def addReverse(forward) -> list:
    backward =  [-1 for i in range(len(forward))]
    for i in range(len(forward)):
        backward[forward[i]] = i
    return [forward, backward]

# undo the substitution once 
#   dir =   0 - forward    1 - backward
def subOnce(txt, sBox, sBoxCount, dir):
    power = len(sBox[0])
    res = 0
    for order in range(sBoxCount):
        res += (sBox[dir][txt%power])*(power**order)
        txt //= power
    return res

# return whether xors all bits of pi and ui gets 0 
def findLinearRelation(pi, ui):
    return 0

# solve
sBoxSize = 4    # number of bit of the input for a s-box
sBoxCount = 4   # number of sub-block in each block of text
blockPairs = readIn()
n = len(blockPairs)
sBox = addReverse([14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7])

#print(blockPairs)
print(sBox)
print(bin(subOnce(0b0000000100100011, sBox, sBoxCount, 1)))

# for i in range(pow(2,5)):
#    print(bin(blockPairs[-1][-1] & i))
print("afan")