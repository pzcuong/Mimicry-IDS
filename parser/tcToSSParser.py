import pandas as pd
import sys
list_of_arguments = sys.argv
inputGraph = list_of_arguments[1]
outputGraph = list_of_arguments[2]
graphID = list_of_arguments[3]

gbMax = 0
def getBenignFile(fl):
    parsedDf = pd.read_csv(fl,
                           names=["sourceId", "sourceType", "destinationId", "destinationType", "syscal", "program",
                                  "retTime",
                                  "pid", "cmdLineArgs1", "cmdLineArgs2"])
    parsedList = parsedDf.values.tolist()
    return parsedDf, parsedList

sysMap = {'process': 'a',
       'thread': 'b',
       'file': 'c',
       'MAP_ANONYMOUS': 'd',
       'socket': 'e',
       'stdin': 'f',
       'stdout': 'g',
       'stderr': 'h',
       'accept': 'i',
       'access': 'j',
       'bind': 'k',
       'chmod': 'l',
       'clone': 'm',
       'close': 'n',
       'connect': 'o',
       'execve': 'p',
       'fstat': 'q',
       'ftruncate': 'r',
       'listen': 's',
       'mmap2': 't',
       'open': 'u',
       'read': 'v',
       'recv': 'w',
       'recvfrom': 'x',
       'recvmsg': 'y',
       'send': 'z',
       'sendmsg': 'A',
       'sendto': 'B',
       'stat': 'C',
       'truncate': 'D',
       'unlink': 'E',
       'waitpid': 'F',
       'write': 'G',
       'writev': 'H',
      }

def getUUID(dic, obj):
    if obj not in dic:
        dic[obj] = dic['mx']
        dic['mx'] += 1
    return dic[obj]

def convertRow(row, processNode, graphID):
    syscal = row[4]
    sPID = row[8]
    dPID = row[7]
    sName = row[0]
    dName = row[2]
    
    if row[1] == 'process' and row[3] == 'process':
        if syscal == 'execve':
            dPID = sPID
        sUUID = getUUID(processNode, (sName, sPID))
        dUUID = getUUID(processNode, (dName, dPID))
    elif row[1].strip() == 'process':
        sUUID = getUUID(processNode, (sName, sPID))
        dUUID = getUUID(processNode, dName)
    elif row[3].strip() == 'process':
        dUUID = getUUID(processNode, (dName, sPID))
        sUUID = getUUID(processNode, sName)
    else:
        import pdb
        pdb.set_trace()
        raise Exception("There is no process in row")
    return [sUUID, sysMap[row[1].strip()], dUUID, sysMap[row[3].strip()], sysMap[syscal.strip()], graphID]

def createDataset(fileName, outPath, graphID):
    global gbMax
    rows = getBenignFile(fileName)[-1]
    processNode = {'mx': gbMax}
    newRows = []
    for row in rows:
        newRow = convertRow(row, processNode, graphID)
        newRows.append(newRow)
    pd.DataFrame(newRows, columns = [0,1,2,3,4,5]).to_csv(outPath, sep='\t', header=False, index=False)
    gbMax = processNode['mx']
    
    
    
createDataset(inputGraph,outputGraph,graphID)

