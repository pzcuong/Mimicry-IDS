import pandas as pd
import copy
import networkx as nx
from itertools import islice
import math
import pickle
from anomalyScore import *
import redis
import numpy as np

def readPandasFile(parsedFile, names =
("sourceId", "sourceType", "destinationId", "destinationType", "syscal", "retTime","graphId", "pid", "cmdLineArgs", "spid"), sep=','):
    parsedDf = pd.read_csv(parsedFile,
                           names=list(names), sep=sep)
    parsedDf['sourceId'] = parsedDf['sourceId'].str.strip('" \n\t')
    parsedDf['destinationId'] = parsedDf['destinationId'].str.strip('" \n\t')
    parsedDf['syscal'] = parsedDf['syscal'].str.strip('" \n\t')
    parsedDf['sourceType'] = parsedDf['sourceType'].str.strip('" \n\t')
    parsedDf['destinationType'] = parsedDf['destinationType'].str.strip('" \n\t')
    parsedList = parsedDf.values.tolist()
    uniqueGraphNames = sorted(list(parsedDf.graphId.unique()))
    return parsedDf, parsedList, uniqueGraphNames
def seperate(df):
    gb = df.groupby('graphId')
    graphs = [gb.get_group(x) for x in gb.groups]
    return graphs
def toList(df):
    return df.values.tolist()
def allOccurancesOfRowProcess(processNode, parsedDf, IN):
    if IN:
        res = parsedDf.loc[(parsedDf['sourceId'] == processNode[0]) & (parsedDf['pid'] == processNode[1])]
    else:
        res = parsedDf.loc[(parsedDf['destinationId'] == processNode[0]) & (parsedDf['pid'] == processNode[1])]
    return res.sort_values(by=['retTime'])['retTime'].tolist()
def partitionFreqDictOut(processNode, parsedDf, M, IN):
    res = allOccurancesOfRowProcess(processNode, parsedDf, IN)
    startTime = res[0]
    endTime = res[-1]
    timeFrame = (endTime - startTime)/M
    stable = 0
    while startTime < endTime:
        i = bisect.bisect_left(res, startTime)
        startTime += timeFrame
        if startTime > endTime:
            if i != len(res):
                stable += 1
                continue
        else:
            j = bisect.bisect_left(res, startTime) - 1
        if i == j:
            stable += 1
    return stable/M
def formatRow (row):
    src = None
    dest = None
    for index in range(len(row)):
        if type(row[index]) == str:
            row[index] = row[index].strip()
    if (row[1] == 'process' or row[1] == 'thread') and (row[3] == 'process' or row[3] == 'thread'):
        if row[4] == 'execve':
            src = (row[0], row[7], 0)
            dest = (row[2], row[7], 0)
        else:
            src = (row[0], row[7], 0)
            dest = (row[2], row[9], 0)
    else:
        if row[1] == 'process' or row[1] == 'thread':
            src = (row[0], row[7], 0)
        if row[1] == 'file' or row[1] == 'stdin' or row[1] == 'stdout' or row[1] == 'stderr':
            src = (cleanFileName(row[0]), 0, 'file')
        if row[1] == 'socket':
            src = (cleanSocketName(row[0]),0)
        if row[3] == 'process' or 'thread':
            dest = (row[2], row[7], 0)
        if row[3] == 'file' or row[3] == 'stdin' or row[3] == 'stdout' or row[3] == 'stderr':
            dest = (cleanFileName(row[2]), 0, 'file')
        if row[3] == 'socket':
            dest = (cleanSocketName(row[2]), 0)
    if src == None:
        flag = 1
    return src, dest
def formatRow_type (row):
    for index in range(len(row)):
        if type(row[index]) == str:
            row[index] = row[index].strip()
    if (row[1] == 'process' or row[1] == 'thread') and (row[3] == 'process' or row[3] == 'thread'):
        src = (row[0], row[7], 'process')
        dest = (row[2], row[9], 'process')
    else:
        if row[1] == 'process' or row[1] == 'thread':
            src = (row[0], row[7], 'process')
        if row[1] == 'file' or row[1] == 'stdin' or row[1] == 'stdout' or row[1] == 'stderr':
            src = (cleanFileName(row[0]), 'file')
        if row[1] == 'socket':
            src = (cleanSocketName(row[0]),"socket")
        if row[3] == 'process' or 'thread':
            dest = (row[2], row[7], 'process')
        if row[3] == 'file' or row[3] == 'stdin' or row[3] == 'stdout' or row[3] == 'stderr':
            dest = (cleanFileName(row[2]), "file")
        if row[3] == 'socket':
            dest = (cleanSocketName(row[2]), "socket")
    return src, dest
def createFreqDict(parsedList, listOfGraphs, graphIndex=6, fRow = True):
    setOfsets = []
    for index in range(len(listOfGraphs)):
        setOfsets.append([set(), set()])
    freqDict = {}
    for row in parsedList:
        setPerTime(row, listOfGraphs, setOfsets, graphIndex, fRow = fRow)
        if fRow:
            src, dest = formatRow(row)
        else:
            src, dest = row[0], row[2]
            if type(src) != str and np.isnan(src):
                src = 'None'
            if type(dest) != str and np.isnan(dest):
                dest = 'None'
        srcRel = (src, row[4])
        if srcRel not in freqDict:
            freqDict[srcRel] = {}
            freqDict[srcRel]['total'] = 0
        if dest not in freqDict[srcRel]:
            freqDict[srcRel][dest] = 0
        freqDict[srcRel][dest] += 1
        freqDict[srcRel]['total'] += 1
    return freqDict, setOfsets
def setPerTime(row, listOfGraphs, setOfsets, graphIndex = 6, fRow = True):
    index = listOfGraphs.index(row[graphIndex])
    if fRow:
        src, dest = formatRow(row)
    else:
        src, dest = row[0], row[2]
        if type(src) != str and np.isnan(src):
            src = 'None'
        if type(dest) != str and np.isnan(dest):
            dest = 'None'

    if src not in setOfsets[index][0]:
        setOfsets[index][0].add(src)
    if dest not in setOfsets[index][1]:
        setOfsets[index][1].add(dest)
def addToAdjList(src, dest, edgeAttributes, adjListForward, adjListBackward):
    if src not in adjListForward:
        adjListForward[src] = {}
    if dest not in adjListBackward:
        adjListBackward[dest] = {}
    if dest not in adjListForward[src]:
        adjListForward[src][dest] = []
    if src not in adjListBackward[dest]:
        adjListBackward[dest][src] = []
    bisect.insort_left(adjListForward[src][dest], edgeAttributes)
    bisect.insort_left(adjListBackward[dest][src], edgeAttributes)
def addToAdjList(src, dest, edgeAttributes, adjListForward, adjListBackward):
    if src not in adjListForward:
        adjListForward[src] = []
    if dest not in adjListBackward:
        adjListBackward[dest] = []
    srcEdge = list(edgeAttributes)
    destEdge = list(edgeAttributes)
    srcEdge.insert(1, dest)
    destEdge.insert(1, src)
    bisect.insort_left(adjListForward[src], tuple(srcEdge))
    bisect.insort_left(adjListBackward[dest], tuple(destEdge))
def createAdjListExec(targetDest, parsedList, setOfsets, freqDict):
    adjListForward = {}
    adjListBackward = {}
    queue = []
    processSet = set()
    targetDestProcessNodes = []
    for row in parsedList:
        src, dest = formatRow(row)
        if row[4] == 'execve':
            if src == targetDest:
                flag = 1
            else:
                flag = 0
            queue = [[src, row[5], row[4], calculateScore((row[-2], src[-1]), (row[-1],dest[-1]), row[4], setOfsets, freqDict), flag]] + queue
            continue
        if len(dest) == 3:
            processSet.add(dest)
        elif src not in processSet and len(queue) > 0:
            execCall = queue.pop()
            addToAdjList(execCall[0], src, tuple(execCall[1:-1]), adjListForward, adjListBackward)
            processSet.add(src)
            if execCall[-1]:
                targetDestProcessNodes.append(src)
        addToAdjList(src, dest, (row[5], row[4], calculateScore(src, dest, row[4], setOfsets, freqDict)), adjListForward, adjListBackward)
    return adjListForward, adjListBackward, targetDestProcessNodes



def createAdjListCleanly(parsedList, setOfsets, freqDict):
    adjListForward = {}
    adjListBackward = {}
    for row in parsedList:
        src, dest = (row[0],row[1], 0), (row[2],row[3], 0)
        if row[1] != 'process':
            dest = (row[2], row[7], row[3], 0)
        elif row[3] != 'process':
            src = (row[0],row[7], row[1], 0)
        else:
            if row[4] == 'execve':
                sPID = row[7]
            else:
                if type(row[8]) != str and type(row[8]) != int:
                    row[8] = str(row[8])
                sPID = int(eval(row[8]))
            src = (row[0],row[7], row[1], 0)
            dest = (row[2], sPID, row[3], 0)
        addToAdjList(src, dest, (row[6], row[4], calculateScore((row[0], row[1]), (row[2], row[3]), row[4], setOfsets, freqDict)), adjListForward, adjListBackward)
    return adjListForward, adjListBackward

def createAdjList(targetDest, parsedList, setOfsets, freqDict):
    adjListForward = {}
    adjListBackward = {}
    queueExec = []
    processSet = set()
    targetDestProcessNodes = set()
    targetSrcProcessNodes = set()
    for row in parsedList:
        src, dest = formatRow(row)
        # Exec Dealt with in Parser Now:
        # deals with execve calls, queue should only be used to track execve calls
        if row[4] == 'execve':
            flag = 0
        if row[4] == 'connect':
            splitRow8 = row[8].split(';')
            if len(splitRow8)>1 and splitRow8[1] == targetDest:
                if src not in targetDestProcessNodes:
                    targetDestProcessNodes.add(clean(dest))
                    targetSrcProcessNodes.add(clean(src))
        addToAdjList(clean(src), clean(dest), (row[5], row[4], calculateScore(src, dest, row[4], setOfsets, freqDict)), adjListForward,
                 adjListBackward)
    return adjListForward, adjListBackward, list(targetDestProcessNodes), list(targetSrcProcessNodes)
def clean(inNode):
    if inNode[-1] == 'file':
        return inNode[:-1]
    else:
        return inNode
def addSinkSource(adjForward, adjBackward):
    source = ('source')
    sink = ('sink')
    startSrc = []
    endDest = []
    for src in adjForward:
        if src not in adjBackward:
            startSrc.append(src)
    for dest in adjBackward:
        if dest not in adjForward:
            endDest.append(dest)
    adjForward[source] = []
    adjBackward[sink] = []
    for src in startSrc:
        adjForward[source].append((src, (-1, '(sycal:source)', 0)))
        adjBackward[src] = [((source),(-1, '(sycal:source)', 0))]
    for dest in endDest:
        adjBackward[sink].append((dest, (-1, '(sycal:sink)', 0)))
        adjForward[dest] = [((sink),(-1, '(sycal:sink)', 0))]
    return adjForward, adjBackward
def addSinkSourceForward(adjForward):
    source = ('source')
    sink = ('sink')
    startSrc = []
    endDest = []
    # find source in for adj, label list as startSrc
    # find sink in for adj, label list as endDest
    adjForward[source] = []
    for src in startSrc:
        adjForward[source].append((-1, '(sycal:source)', src, 0))
    for dest in endDest:
        adjForward[dest] = [(-1, '(sycal:sink)', 'sink', 0)]

    return adjForward
def getInScore(src, setOfsets):
    count = 0
    for index in range(len(setOfsets)):
        nodeSet = setOfsets[index][0]
        if src in nodeSet:
            count += 1
    return count / len(setOfsets)
def getOutScore(dest, setOfsets):
    count = 0
    startIndex = -1
    for index in range(len(setOfsets)):
        nodeSet = setOfsets[index][1]
        if dest in nodeSet:
            if startIndex == -1:
                startIndex = startIndex
            count += 1
    return count / ((len(setOfsets)) - startIndex)
def getFreqScore (src, dest, syscal, freqDict):
    srcRel = (src, syscal)
    if srcRel not in freqDict:
        return 0.001
    if dest not in freqDict[srcRel]:
        return 0.001
    return freqDict[srcRel][dest] / freqDict[srcRel]['total']
def calculateScore(src, dest, syscal, setOfsets, freqDict):
    src = list(src)
    dest = list(dest)
    retVal = None
    if type(src[0]) != str and np.isnan(src[0]):
        retVal = math.log2(0.5)*-1
    if type(dest[0]) != str and np.isnan(dest[0]):
        retVal = math.log2(0.5)*-1
    if retVal is None:
        inScore = getInScore(src[0], setOfsets)
        outScore = getOutScore(dest[0], setOfsets)
        freqScore = getFreqScore(src[0], dest[0], syscal, freqDict)
        if outScore == 0:
            outScore = 1/len(setOfsets)
        if inScore == 0:
            inScore = 1/len(setOfsets)
        retVal = math.log2(inScore*freqScore*outScore)*-1
    return retVal*-1
def convertToScore(adjForward):
    adjMatrixScore = {}
    for src in adjForward:
        if src not in adjMatrixScore:
            adjMatrixScore[src] = []
        for row in adjForward[src]:
            adjMatrixScore[src].append(row)
    return adjMatrixScore
def shortestPath(adjForward, adjBackward):
    adjForward, adjBackward = addSinkSource(adjForward, adjBackward)
    return adjForward
def shortestPathFor(adjForward):
    adjForward = addSinkSourceForward(adjForward)
    adjMatrix = convertToScore(adjForward)
    return adjMatrix
def findKAnomlousPaths(adjMatrix, K, graphName):
    G = nx.DiGraph()
    delNode = ('Socket Thread', 17289, 0)
    if delNode in adjMatrix:
        for index in range(len(adjMatrix[delNode])):
            posNodeTup = adjMatrix[delNode][index]
            if posNodeTup[0] == delNode:
                del adjMatrix[delNode][index]
                break
    for src in adjMatrix:
        for row in adjMatrix[src]:
            G.add_edge(src, row[0], weight=row[1][2], syscal=row[1][1], retTime=row[1][0])
    isDAG = nx.is_directed_acyclic_graph(G)
    if not isDAG:
        raise Exception("Graph Is Not A DAG")
        edgeFormingCycle = nx.find_cycle(G, source='source')
        return edgeFormingCycle
    Kpaths = []
    adj = G.adj
    for path in k_shortest_paths(G, 'source', 'sink', K, weight='weight'):
        Kpath = []
        regularityScore = 0
        for index in range(len(path)-1):
            try:
                ea = (path[index], path[index+1])
                edgeAttrib = adj[ea[0]][ea[1]]
            except:
                print('hello')
            regularityScore += edgeAttrib['weight']
            Kpath.append([ea[0],(edgeAttrib['syscal'], edgeAttrib['retTime']), ea[1]])
        Kpaths.append([Kpath, regularityScore, isDAG])
    return Kpaths
def k_shortest_paths(G, source, target, k, weight=None):
    theta = [p for p in nx.all_shortest_paths(G, source=source, target=target, weight = 'weight', method = 'bellman-ford')]
    return theta[:k]
def makeAdjListDAG(adjListForward, adjListBackward):
    adjListForwardTemp = copy.deepcopy(adjListForward)
    adjListBackwardTemp = copy.deepcopy(adjListBackward)
    count = 0
    srcNotIN = []
    syscall = set()
    for src in adjListForwardTemp:
        if src in adjListBackwardTemp:
            edgesIn = adjListBackward[src]
            edgesOut = adjListForward[src]
            indexI = 0
            indexO = 0
            inEdgesDel = []
            outEdgesDel = []
            srcVal = src
            changeTime = None
            while indexI < len(edgesIn) and indexO < len(edgesOut):
                edgeOut = edgesOut[indexO]
                edgeIn = edgesIn[indexI]
                if changeTime != None and edgeOut[0] > changeTime:
                    while edgeOut[0] < edgeIn[0] and indexO < len(edgesOut):
                        edgeOut = edgesOut[indexO]
                        outEdgesDel.append(indexO)
                        cIndex = adjListBackward[edgeOut[2]].index((edgeOut[0], edgeOut[1], src, edgeOut[3]))
                        temp = list(adjListBackward[edgeOut[2]][cIndex])
                        temp[-1] = srcVal
                        adjListBackward[edgeOut[2]][cIndex] = tuple(temp)
                        if srcVal not in adjListForward:
                            adjListForward[srcVal] = []
                        bisect.insort_left(adjListForward[srcVal], edgeOut)
                        indexO += 1
                elif edgeIn[0] < edgeOut[0]:
                    indexI += 1
                elif changeTime != None and edgeOut[0] < changeTime:
                    indexO += 1
                else:
                    cIndex = adjListForward[edgeIn[2]].index((edgeIn[0], edgeIn[1], src, edgeIn[3]))
                    inEdgesDel.append(indexI)
                    srcVal = copy.deepcopy(srcVal)
                    srcVal = list(srcVal)
                    srcVal[-1] += 1
                    srcVal = tuple(srcVal)
                    adjListBackward[srcVal] = [edgeIn]
                    temp = list(adjListForward[edgeIn[2]][cIndex])
                    temp[-1] = srcVal
                    adjListForward[edgeIn[2]][cIndex] = tuple(temp)
                    changeTime = edgeIn[0]
                    indexI += 1
            while indexO < len(edgesOut):
                if changeTime == None:
                    break
                edgeOut = edgesOut[indexO]
                if edgeOut[0] > changeTime:
                    outEdgesDel.append(indexO)
                    cIndex = adjListBackward[edgeOut[2]].index((edgeOut[0], edgeOut[1], src, edgeOut[3]))
                    temp = list(adjListBackward[edgeOut[2]][cIndex])
                    temp[-1] = srcVal
                    adjListBackward[edgeOut[2]][cIndex] = tuple(temp)
                    if srcVal not in adjListForward:
                        adjListForward[srcVal] = []
                    bisect.insort_left(adjListForward[srcVal], edgeOut)
                indexO += 1
            count = 0
            while indexI < len(edgesIn):
                edgeIn = edgesIn[indexI]
                cIndex = adjListForward[edgeIn[2]].index((edgeIn[0], edgeIn[1], src, edgeIn[3]))
                inEdgesDel.append(indexI)
                if not count:
                    srcVal = copy.deepcopy(srcVal)
                    srcVal = list(srcVal)
                    srcVal[-1] += 1
                    srcVal = tuple(srcVal)
                if srcVal not in adjListBackward:
                    adjListBackward[srcVal] = []
                bisect.insort_left(adjListBackward[srcVal], edgeIn)
                temp = list(adjListForward[edgeIn[2]][cIndex])
                temp[-1] = srcVal
                adjListForward[edgeIn[2]][cIndex] = tuple(temp)
                count += 1
                indexI += 1
            for index in sorted(inEdgesDel, reverse=True):
                del adjListBackward[src][index]
            for index in sorted(outEdgesDel, reverse=True):
                del adjListForward [src][index]
    return adjListForward, adjListBackward
def cleanSocketName(socket):
    return socket
def cleanFileName(fileName):
    return fileName.replace('\"','')
def writeToFile(jsonObjectList, fileName3):
    with open(fileName3, 'wb') as filehandle:
        # store the data as binary data stream
        pickle.dump(jsonObjectList, filehandle)
def readFromFile(fileName3):
    with open(fileName3, 'rb') as filehandle:
        # read the data as binary data stream
        jsonObjectList = pickle.load(filehandle)
    return jsonObjectList
def sortTime(adjDict):
    for key in adjDict:
        adjDict[key] = sorted(adjDict[key])
    return adjDict
def main(filepath):
    df, dfList, graphNames = readPandasFile(filepath)
    freqDict, setOfsets = createFreqDict(dfList, graphNames)
    writeToFile(freqDict, 'freqList.data')
    writeToFile(setOfsets, 'setOfsets.data')
def mainTraining(filepath):
    kPathsPerGraph = []
    df, dfList, graphNames = readPandasFile(filepath)
    freqDict = readFromFile('freqList.data')
    setOfsets = readFromFile('setOfsets.data')
    graphs = seperate(df)
    # targetExec = ('/usr/bin/firefox', 0)
    targetExec = ' 192.168.0.100'
    count = 1
    for graph in graphs:
        count += 1
        graphName = graph['graphId'].iloc[0]
        graph = toList(graph)
        adjListForward, adjListBackward, targetNodesDest, targetNodesSrc = createAdjList(targetExec, dfList, setOfsets, freqDict)
        print("finished up her!")
        adjLists = getPathAnomalyScoreNoEdge(targetNodesDest, targetNodesSrc, adjListForward, adjListBackward)
        filepath = 'adjLists+{}.data'.format(count)
        writeToFile(adjLists, filepath)
    return 0
def makeAdjListDAGFaster(adjListForward):
    forwardEdges = []
    setOfNodes = {}
    dagForAdj = {}
    dagDestAdj = {}
    for src in adjListForward:
        for edge in adjListForward[src]:
            forwardEdges.append((edge[0], src, edge[1], edge[2], edge[3]))
    forwardEdges = sorted(forwardEdges)
    for edge in forwardEdges:
        src = edge[1]
        dest = edge[2]
        edgeAttributes = (edge[0], edge[3], edge[4])
        if dest not in setOfNodes:
            setOfNodes[dest] = 0
        else:
            while setOfNodes.get(dest, 0) == 1:
                dest = list(dest)
                dest[-1] += 1
                dest = tuple(dest)
            setOfNodes[dest] = 0
        if src in setOfNodes:
            while setOfNodes.get(src, 0) == 1:
                src = list(src)
                src[-1] += 1
                src = tuple(src)
            if src in setOfNodes:
                setOfNodes[src] = 1
            else:
                src = list(src)
                src[-1] -= 1
                src = tuple(src)
        else:
            setOfNodes[src] = 1
        dagForAdj.setdefault(src, [])
        dagForAdj[src].append((dest, edgeAttributes))
        dagDestAdj.setdefault(dest, [])
        dagDestAdj[dest].append((src, edgeAttributes))
    return dagForAdj, dagDestAdj


def recurPrune(startPID, graph, time, forward, select):
    graphs = []
    if forward:
        newGraph = graph['sourcePid'] == startPID
        newGraph = newGraph[newGraph['time'] > time]
        nextRows = newGraph.drop_duplicates(subset="destPID").values.tolist()
        nextRows = nextRows[:select]
        nextNodes = [x[2] for x in next]

        secGraph = newGraph[newGraph['destPID'].isin(nextNodes)]

        for nextNode in nextNodes:
            retGraph = recurPrune(nextNode, graph, forward, select)
            graphs += retGraph
    if not forward:
        newGraph = graph['destPID'] == startPID
        nextNodes = newGraph.drop_duplicates(subset="sourcePid",
                                             keep=False, inplace=True).values.tolist()
        nextNodes = nextNodes[:select]
        secGraph = newGraph[newGraph['sourcePid'].isin(nextNodes)]
        for nextNode in nextNodes:
            retGraph = recurPrune(nextNode, graph, forward, select)
            graphs += retGraph
    return graphs + [secGraph]


def pruneGraph(filepath):
    df, dfList, graphNames = readPandasFile(filepath)
    graphs = seperate(df)
    startPID = ''
    for graph in graphs:
        graphName = graph['graphId'].iloc[0]
        graphList = toList(graph)
        adjList = recurPrune(startPID, graph)
    return 0

