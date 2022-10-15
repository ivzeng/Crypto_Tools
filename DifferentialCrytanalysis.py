#####       Differential Cryptanalysis for a Simple         ##### 
#####       Substitution-Permutation Network Cipher         #####

## Cipher Reference:  
##  http://www.engr.mun.ca/~howard/Research/Papers/ldc_tutorial.html

## The program produces a Differential cryptanalysis based on 
##  the given collection of distinct plaintext pairs and the
##  respected ciphertext pair, stored in one file with each
##  line containing the two plaintexts and their respected 
##  cipthertexts, separated by commas.

## Enter command like the following to run the program:
## "./DifferentialCryptanalysis.py (textsFile)" 

import sys
import numpy as np


# check input files
if len(sys.argv) != 2:
    print("number of argument not matches, please run the program with two files (plaintexts and ciphertexts)")
    exit()


# reads input files and stored them into a list of decimal numbers
def readIn() -> list: 
    textPairs = []
    input = open(sys.argv[1], 'r')
    line = input.readline()
    while line:
        textPairs += [[int(i, 2) for i in line[:-1].split(',')]]
        line = input.readline()
    return textPairs

# print input file
def printIn(input, f = lambda i : i):
    for tp in input:
        print(f(tp))

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

# returns the string representation of a binary number
def binToStr(bn, wid):
    return bin(bn)[2:].zfill(wid)

# prints a progress bar for fun
def progressBar(progress: int):
    if progress >= 99:
        print('\rdone!',' '*111 ,sep = '', flush=True)
        return 
    face = '^v^'
    if progress >= 80:
        face = '*~*'
    elif progress >= 50:
        face = 'ToT'
    elif progress >= 30:
        face = '-.-'
    print("\r[", ' '*progress, face, ' '*(5+(100-progress)%2), '🔥','$$'*int((100-progress)//2),'] ', f"{progress:.0f}%", sep = '', end = '', flush=True)

# generates a difference distribution table based on the s-box provided
def difDistributionTable(sBox: list[2]):
    inSize = len(sBox[0])
    ddTable = [[0 for i in range(inSize)] for i in range(inSize)]
    for t1 in range(inSize):
        for t2 in range(inSize):
            ddTable[t1^t2][sBox[0][t1]^sBox[0][t2]] += 1
    return ddTable

# prints a table
def printTable(table: list, name: str):
    table = [[i]+table[i] for i in range(len(table))]
    table = [[-1]+ [i for i in range(len(table[0])-1)]] + table
    print(name, ':\n', np.array(table), sep='')

# generate possible key choice at the selected block
def generateKeys(blockIndices, curKey = 0):
    def getKeys(res, cur, p):
        if p == len(blockIndices):
            res += [cur]
            return
        for i in range(power):
            getKeys(res, cur+i*power**(sBoxCount-blockIndices[p]), p+1)
    res = []
    getKeys(res, curKey, 0)
    return res

# sets the indices selected and stores them as a binary number
def setSelectedindices(idx: list):
    return sum(pow(2,blockSize-i) for i in idx)

#  do or undo the substitution once 
#   dir =   0 - forward    1 - backward
def subOnce(txt: int, dir: int = 0):
    res = 0
    for order in range(sBoxCount):
        res += (sBox[dir][txt%power])*(power**order)
        txt //= power
    return res

# get the difference before the last round of s-box based on 
#  the ciphertext pair and the key
def difUndoOnce(ciphertextPair: list, key: int):
    return subOnce(ciphertextPair[0]^key, 1)^subOnce(ciphertextPair[1]^key, 1)


# count the orrcurence of right pairs (that has xor result of the 
#   input pairs of the final s-box matching the expected result) 
#   under a key
def difRelationCount(textPairs, targetRelation, key):
    res = 0
    for tp in textPairs:
        if (targetRelation == difUndoOnce(tp[2:],key)):
            res += 1
    return res

# produces a map bewteen each possible selected key and the number
#   of right pairs respected to the key, sorted based on the number
#   of correct pairs.
def keyDifferenceMap(pairs: list, blockIndices: list, target: int, curKey = 0):
    keys = generateKeys(blockIndices, curKey)
    i = 1
    kl = len(keys)
    keyDifRelationMap = [0 for j in range(kl)]
    progressBar(i)
    for j in range(kl):
        keyDifRelationMap[j] = [keys[j], difRelationCount(pairs, target, keys[j])]
        if 100*j//kl > i:
            i = 100*j//kl
            progressBar(i)
    keyDifRelationMap.sort(key=lambda row: row[1], reverse=True)
    return keyDifRelationMap

# linear cryptanalysis get part of the final key
def differentialCryptanalysis(textPairs:list, target:list, keyBlocks: list,key:int = 0) -> int:
    target = setSelectedindices(target)
    keyDifRelationMap = keyDifferenceMap(textPairs, keyBlocks, target, key)
    print(power//2+1, 'key choices that produces highest occurance:\n',' \n '.join(('key: '+ binToStr(k[0], blockSize) + '              matches: ' + str(k[1])) for k in keyDifRelationMap[:power//2+1]))
    return keyDifRelationMap[0]

###         solve          ###
textPairs = readIn()
n = len(textPairs)
sBoxSize = 4    # number of bit of the input for a s-box
sBoxCount = 4   # number of sub-block in each block of text
blockSize = sBoxSize*sBoxCount
power = 2**sBoxSize
sBox = addReverse([14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7])

## print input details:
# input:
#   printIn(textPairs, lambda tp : [binToStr(i, blockSize) for i in tp])
# len
#   print(n)
# difference between each pair of plaintexts
#   printIn(textPairs, lambda tp : binToStr(tp[0]^tp[1], blockSize))
 

## prints the difference distribution table of the s-box
#   printTable(difDistributionTable(sBox), 'difference distribution table for the selected s-box')

## generates all possible partial subkeys at block 1, 2, 4
#   print(generateKeys([1,2,4]))

## differential cryptanalysis
target = [6,7,14,15]
keyParts = [2,4]
partialKey = differentialCryptanalysis(textPairs, target, keyParts)
print('partial subkey:', binToStr(partialKey[0], blockSize), '   matches:', partialKey[1], '\n\n')

