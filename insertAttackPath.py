import random
import pandas as pd
import pickle
import csv
import math
import timeit
import sys
nz = sys.argv[1]

benPIDS = None
# difference between each edge -> redo timestamp to benign file
inter = 40255518
rowCount = 1
lastPID = None

#Load in the attack file
def getAttackPath(fl):
    attackPath =  pickle.load(open(fl, 'rb'))
    return sorted(attackPath, key=lambda x: x[3])


# load in the set of benign substrcutures
def getBenignFile(fl):
    parsedDf = pd.read_csv(fl,
                           names=["sourceId", "sourceType", "destinationId", "destinationType", "syscal", "program",
                                  "retTime",
                                  "pid", "cmdLineArgs1", "cmdLineArgs2"])
    parsedList = parsedDf.values.tolist()
    global benPIDS
    benPIDS = parsedDf['pid'].values.tolist()
    return parsedDf, parsedList


# find first instance of process attacker will take over
def findInsertPoint(rows, parentProcess, inFront = False, processName = None):
    pid = None
    rowNum = None
    for i in range(len(rows)):
        row = rows[i]
        if inFront:
            if parentProcess in row[0] or parentProcess in row[2]:
                pid = row[7]
                rowNum = i
                break
        else:
            if parentProcess in row[0]:
                pid = row[7]
                rowNum = i
    if pid is None:
        return None

    return (parentProcess, pid, rowNum, processName)

def cleanRow(row):
    for i in range(len(row)):
        if type(row[i]) == str:
            row[i] = row[i].replace('"', " ").strip()
    return row

# take over the process - assume this is part of attacker ability
def takeOver(attackPath, parentP, benDf):
    nameP, namePID, rowP, processName = parentP
    benDf['retTime'] += 2
    rows = benDf.values.tolist()
    rCount = 0
    retCount = None
    newPID =  max(benPIDS) + 1
    while rCount <= rowP:
        row = rows[rCount]
        if int(row[7]) == namePID:
            row[7] = newPID
        if 'clone' in row[4] and int(row[8]) == namePID:
            row[8] = newPID
        row[6] -= 2
        rows[rCount] = row
        rCount += 1
        retCount = row[6]
    srcN, destN, syscal, retTime = attackPath[0]
    attackPath = attackPath[1:]
    # assume process we taking over is created through exev or clone
    rows[rowP][7] = newPID
    benPIDS.append(newPID)
    #connect to process and take over
    newRows = []
    retCount += 1
    newRows.append([srcN[0], srcN[1], nameP, 'process', syscal, f'{processName}', retCount, newPID])
    retCount += 1
    newRows.append([nameP, 'process', nameP, 'process', 'clone', '{processName}', retCount, newPID, namePID])
    assert len(newRows) == 2
    rows = rows[:rowP+1] + newRows + rows[rowP+1:]
    benPIDS.append(max(benPIDS) + 1)
    return rows, attackPath

# insert the attack conducted
def insertAttackPath(attackPath, parentP, rows, tempDir, numberOfClones, inFront = False):
    malNodesMimi = set()
    global rowCount
    global inter
    maxRetTime = rows[-1][6]+1
    global lastPID
    for i in range(numberOfClones):
        rows.append([parentP[0], 'process', parentP[0], 'process', 'clone', 'firefox', maxRetTime, lastPID, max(benPIDS)+i])
        lastPID = max(benPIDS)+i
        maxRetTime = maxRetTime + (inter*rowCount) + random.randint(0,100000)
        rowCount = rowCount + 1
    rows.append([parentP[0], 'process', attackPath[0][1][0], 'process', 'clone', 'firefox', maxRetTime, lastPID, attackPath[0][1][1]])
    pDict = {'mx': lastPID+2,
            attackPath[0][1][1]: attackPath[0][1][1]}
            #attackPath[0][1][1]: lastPID+1}
    PIDS = set()
    transPID = {}
    for i in range(len(rows)):
        row = cleanRow(rows[i])
        rows[i] = row
        if 'process' in row[1]:
            k = row[0]
        else:
            k = row[2]
        pDict[k] = row[5]
        PIDS.add(row[7])

    for row in attackPath:
        #maxRetTime += 1
        maxRetTime = maxRetTime + (inter*rowCount) + random.randint(0,100000)
        rowCount = rowCount + 1
        sName = row[0][0]
        sType = row[0][-1]
        dName = row[1][0]
        dType = row[1][-1]
        if 'tmp/tmp' in sName:
            spl = sName.split('/')
            spl[1]=tempDir[0]
            spl[2]=tempDir[1]
            sName = '/'.join(spl)
            fullName = list(row[0])
            fullName[0] = sName
            malNodesMimi.add(tuple(fullName))
        else:
            malNodesMimi.add(row[0])
        if 'tmp/tmp' in dName:
            spl = dName.split('/')
            spl[1]=tempDir[0]
            spl[2]=tempDir[1]
            dName = '/'.join(spl)
            fullName = list(row[1])
            fullName[0] = dName
            malNodesMimi.add(tuple(fullName))
        else:
            malNodesMimi.add(row[1])

        dPID = None
        sPID = None
        if len(row[0]) == 3:
            sPID = row[0][1]
            if sPID in PIDS:
                if sPID not in pDict:
                    pDict[sPID] = pDict['mx']
                    pDict['mx'] += 1
                sPID = pDict[sPID]
        if len(row[1]) == 3:
            dPID = row[1][1]
            if dPID in PIDS:
                if dPID not in pDict:
                    pDict[dPID] = pDict['mx']
                    pDict['mx'] += 1
                dPID = pDict[dPID]
        syscal = row[2]

        if dPID is not None and sPID is not None:
            if sName not in pDict:
                if '/' in sName:
                    pDict[sName] = sName.split('/')[-1]
                else:
                    pDict[sName] = sName
                #raise Exception(f"{sName} not in benign file")
            rows.append([sName, sType, dName, dType, syscal, pDict[sName], maxRetTime, sPID, dPID])
        else:
            if sPID is not None:
                if sName not in pDict:
                    if '/' in sName:
                        pDict[sName] = sName.split('/')[-1]
                    else:
                        pDict[sName] = sName
                    #raise Exception(f"{sName} not in benign file")
                rows.append([sName, sType, dName, dType, syscal, pDict[sName], maxRetTime, sPID])
            else:
                if dName not in pDict:
                    if '/' in dName:
                        pDict[dName] = dName.split('/')[-1]
                    else:
                        pDict[dName] = dName
                    #raise Exception(f"{dName} not in benign file")
                rows.append([sName, sType, dName, dType, syscal, pDict[dName], maxRetTime, dPID])
    return rows, malNodesMimi

def insertBenSubstructs(benSub, parentP, rows, tempDir, numberOfClones, inFront = False):
    global rowCount
    global inter
    global lastPID
    maxRetTime = rows[-1][6]+1
    if inFront:
        lastPID = max(benPIDS)-1
    else:
        lastPID = parentP[1]
    for i in range(numberOfClones):
        rows.append([parentP[0], 'process', parentP[0], 'process', 'clone', parentP[-1], maxRetTime, lastPID, max(benPIDS)+i])
        lastPID = max(benPIDS)+i
        maxRetTime = maxRetTime + (inter*rowCount) + random.randint(0,100000)
        rowCount = rowCount + 1
    pDict = {'mx': lastPID+1}
    PIDS = set()
    transPID = {}
    for i in range(len(rows)):
        row = cleanRow(rows[i])
        rows[i] = row
        if 'process' in row[1]:
            k = row[0]
        else:
            k = row[2]
        pDict[k] = row[5]
        PIDS.add(row[7])
    cloned = {}
    for row in benSub:
        maxRetTime = maxRetTime + (inter*rowCount) + random.randint(0,100000)
        rowCount = rowCount + 1
        sName = row[0][0]
        sType = row[0][-1]
        dName = row[1][0]
        dType = row[1][-1]
        dPID = None
        sPID = None
        if len(row[0]) == 3:
            sPID = row[0][1]
            if sPID in PIDS:
                if sPID not in pDict:
                    pDict[sPID] = pDict['mx']
                    pDict['mx'] += 1
                sPID = pDict[sPID]
        if len(row[1]) == 3:
            dPID = row[1][1]
            if dPID in PIDS:
                if dPID not in pDict:
                    pDict[dPID] = pDict['mx']
                    pDict['mx'] += 1
                dPID = pDict[dPID]
        syscal = row[2]

        if dPID is not None and sPID is not None:
            if (sName, sPID) not in cloned:
                cloned.add((sName, sPID))
                cloned.add((dName, dPID))
                rows.append([parentP[0], 'process', sName, 'process', 'clone', parentP[-1], maxRetTime, sPID, max(benPIDS)+i])
                maxRetTime = maxRetTime + (inter*rowCount) + random.randint(0,100000)
                rowCount = rowCount + 1
            if sName not in pDict:
                if '/' in sName:
                    pDict[sName] = sName.split('/')[-1]
                else:
                    pDict[sName] = sName
            rows.append([sName, sType, dName, dType, syscal, pDict[sName], maxRetTime, sPID, dPID])
        else:
            if sPID is not None:
                if (sName, sPID) not in cloned:
                    cloned.add((sName, sPID))
                    rows.append([parentP[0], 'process', sName, 'process', 'clone', parentP[-1], maxRetTime, sPID, max(benPIDS)+i])
                    maxRetTime = maxRetTime + (inter*rowCount) + random.randint(0,100000)
                    rowCount = rowCount + 1
                if sName not in pDict:
                    if '/' in sName:
                        pDict[sName] = sName.split('/')[-1]
                    else:
                        pDict[sName] = sName
                rows.append([sName, sType, dName, dType, syscal, pDict[sName], maxRetTime, sPID])
            else:
                if (dName, dPID) not in cloned:
                    cloned.add((dName, dPID))
                    rows.append([parentP[0], 'process', dName, 'process', 'clone', parentP[-1], maxRetTime, dPID, max(benPIDS)+i])
                    maxRetTime = maxRetTime + (inter*rowCount) + random.randint(0,100000)
                    rowCount = rowCount + 1
                if dName not in pDict:
                    if '/' in dName:
                        pDict[dName] = dName.split('/')[-1]
                    else:
                        pDict[dName] = dName
                rows.append([sName, sType, dName, dType, syscal, pDict[dName], maxRetTime, dPID])
    return rows

def saveRows(rows, fileName):
    for i in range(len(rows)):
        row = rows[i]
        j = 0
        while j < len(row):
            if type(row[j])== float and math.isnan(row[j]):
                break
            if type(row[j])== float:
                row[j] = int(row[j])
            j += 1
        if j != len(row):
            rows[i] = row[:j]


    with open(fileName, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(rows)


def findTempDir(rows):
    tempDir = None
    for i in range(len(rows)):
        row = rows[i]
        spl = None
        if 'tmp/tmp' in row[0]:
            spl = row[0].split('/')
        if 'tmp/tmp' in row[2]:
            spl = row[2].split('/')
        if spl is not None:
            tempDir = (spl[1],spl[2])
            break
    return tempDir

def saveMalNodes(nodes, path):
    pickle.dump(nodes, open(path, 'wb'))


def main(attackPath, benignFilePath, benignSubstructs, savePath, inFront = True):
    attack = getAttackPath(attackPath)
    benDF, ben = getBenignFile(benignFilePath)
    benDfSub, ben = getBenignFile(benignSubstructs)
    insertP = findInsertPoint(ben, "/usr/bin/firefox", inFront = inFront, processName = 'firefox')
    tempDir = findTempDir(ben)
    if inFront:
        ben, attack = takeOver(attack, insertP, benDF)
    ben = insertBenSubstructs(benSub, parentP, ben, tempDir, numberOfClones = 1, inFront = inFront)
    rows, malNodes = insertAttackPath(attack, insertP, ben, tempDir, numberOfClones = 1, inFront = inFront)
    saveRows(rows, savePath)


main(f"{attLoc}", f"{benLoc}", f"{saveLoc}")
