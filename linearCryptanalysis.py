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

# sets the indices selected and stores them as a binary number
def setSelectedindices(idx: list):
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
def possibleKeys(pairs: list, inBits: int, outBits: int, keyBlocks: list, cur = 0):
    def getKeys(res, cur, p):
        if p == len(keyBlocks):
            res += [cur]
            return
        for i in range(power):
            getKeys(res, cur+i*power**(sBoxCount-keyBlocks[p]), p+1)
    keys = []
    getKeys(keys, cur, 0)
    keyBiasMap = [[k, getBias(linearRelationCount(pairs, inBits, outBits, k))] for k in keys]
    keyBiasMap.sort(key=lambda row: row[1], reverse=True)
    return keyBiasMap

# returns the string representation of a binary number
def binToStr(bn, wid):
    return bin(bn)[2:].zfill(wid)

# solve
sBoxSize = 4    # number of bit of the input for a s-box
sBoxCount = 4   # number of sub-block in each block of text
blockSize = sBoxSize*sBoxCount
power = 2**sBoxSize
blockPairs = readIn()
n = len(blockPairs)
sBox = addReverse([14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7])
sInIdx = [5,7,8]                        # selected input indices
sOutIdx = [6,8,14,16]                   # selected output indices

inIdx1 = setSelectedindices(sInIdx)
outIdx1 = setSelectedindices(sOutIdx)
key1 = setKey([[0b0111,2],[0b0110,4]])  # set k_6, k_7, k_8, k_14, k_15 to 1

## linear approximation of s-box
# print('linear approximation table:')
# print(np.array(linearApproxTable(sBox)))

## computes occurence of a linear relation and bias under a key guess
print('input indices chosen: ', binToStr(inIdx1, blockSize))
print('output indices chosen:', binToStr(outIdx1, blockSize))
print('guessed key:', binToStr(key1, blockSize))
occ = linearRelationCount(blockPairs, inIdx1, outIdx1, key1)
# print('occurences:', occ)
print('bias:', getBias(occ))

## check absolute bias under each possible final subkey specified,
##   get the value of the second and fourth blocks of the key
##   (the one with largest bias) 
keyBlocks1 = [2,4]
keyBiasMap = possibleKeys(blockPairs, inIdx1, outIdx1, keyBlocks1)
print(power, 'most possible key choices:\n',' '.join(('key: '+ binToStr(k[0], blockSize) + ' bias: ' + str(k[1])) +'\n' for k in keyBiasMap[:power]))
partialKey = keyBiasMap[0][0]

## get the value of remainning parts of the final subkey
keyBlocks2 = [1,3]
sInIdx = [1,4,9,12]                        # selected input indices
sOutIdx = [2,6,10,14]                   # selected output indices
inIdx2 = setSelectedindices(sInIdx)
outIdx2 = setSelectedindices(sOutIdx)
keyBiasMap = possibleKeys(blockPairs, inIdx2, outIdx2, keyBlocks2, partialKey)
finalKey = keyBiasMap[0][0]
print(power, 'most possible key choices:\n',' '.join(('key: '+ binToStr(k[0], blockSize) + ' bias: ' + str(k[1])) +'\n' for k in keyBiasMap[:power]))
print('final key:', binToStr(finalKey, blockSize))


