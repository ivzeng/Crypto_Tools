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
import numpy as np


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
def addReverse(forward: list) -> list:
    backward =  [-1 for i in range(len(forward))]
    for i in range(len(forward)):
        backward[forward[i]] = i
    return [forward, backward]

# undo the substitution once 
#   dir =   0 - forward    1 - backward
def subOnce(txt: int, dir: int = 0):
    res = 0
    for order in range(sBoxCount):
        res += (sBox[dir][txt%power])*(power**order)
        txt //= power
    return res

# return whether xors all bits of pi and ui gets 0 
def findLinearRelation(pi, ui):
    res = 1
    while pi != 0:
        res ^= pi%2
        pi >>= 1
    while ui != 0:
        res ^= ui%2
        ui >>= 1
    return res

# counts the number of occurences when the xor result of the 
#   selected bits (1-bit of inBits) of inputs (plaintext)
#   equals to the selected bits (1-bits of outBits) of 
#   outputs (state before the final round of substitution).
def linearRelationCount(pairs: list, inBits: int, outBits: int, finalKey: int) -> int:
    res = 0
    for pair in pairs:
        res += findLinearRelation(pair[0]&inBits, subOnce(pair[1]^finalKey, 1)&outBits)
    return res

# get the absolute value of bias
def getBias(c):
    return abs((c-n/2)/n)

# sets the key, where parts is a list of [sk, i], indicating
#   the value of subkey at i-th sub-block (0-indexed)
def setKey(parts:list):
    k = 0
    for p in parts:
        k += p[0]*pow(power, sBoxCount-p[1])
    return k

# sets the indexes selected and stores them as a binary number
def setSelectedIndexes(idx: list):
    return sum(pow(2,blockSize-i) for i in idx)

# generates a linear approximation table for the s-box
def linearApproxTable(sBox) -> list:
    rng = len(sBox[0])
    lATable = [[0 for i in range(rng)] for j in range(rng)]
    for i in range(rng):
        for j in range(rng):
            for val in range(rng):
                lATable[i][j] += findLinearRelation(val&i, subOnce(val)&j)
    for r in lATable:
        for i in range(rng):
            r[i] -= rng//2
    return lATable

# computes the bias of all possible key based on the selected blocks,
#   returns the each key and the absolute bias, sorted with the 
#   absolute value of the bias.
def possibleKeys(pairs: list, inBits: int, outBits: int, keyBlocks: list):
    def getKeys(res, cur, p):
        if p == len(keyBlocks):
            res += [cur]
            return
        for i in range(power):
            getKeys(res, cur+i**(sBoxCount-keyBlocks[p]), p+1)
    res = []
    getKeys(res, 0, 0)
    return res

# solve
sBoxSize = 4    # number of bit of the input for a s-box
sBoxCount = 4   # number of sub-block in each block of text
blockSize = sBoxSize*sBoxCount
blockPairs = readIn()
n = len(blockPairs)
sBox = addReverse([14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7])
power = len(sBox[0])
inIdx = setSelectedIndexes([5,7,8])
outIdx = setSelectedIndexes([6,8,14,16])
key1 = setKey([[7,2],[6,4]])

# linear approximation of s-box
# print('linear approximation table:')
# print(np.array(linearApproxTable(sBox)))

# occurence of a linear relation and bias
print('input sum:', bin(inIdx))
print('output sum:', bin(outIdx))
print('guessed key:', bin(key1))
occ = linearRelationCount(blockPairs, inIdx, outIdx, key1)
# print('occurences:', occ)
print('bias:', getBias(occ))

# absolute bias of each specified key
print([bin(i) for i in  possibleKeys(blockPairs, inIdx, outIdx, [2,4])])


