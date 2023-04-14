
def createFreqDict(parsedList, listOfGraphs, graphIndex=6):
    setOfsets = []
    for index in range(len(listOfGraphs)):
        setOfsets.append([set(), set()])
    freqDict = {}
    for row in parsedList:
        setPerTime(row, listOfGraphs, setOfsets, graphIndex, fRow = fRow)
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

def setPerTime(row, listOfGraphs, setOfsets, graphIndex = 6):
    index = listOfGraphs.index(row[graphIndex])
    src, dest = row[0], row[2]
    if type(src) != str and np.isnan(src):
        src = 'None'
    if type(dest) != str and np.isnan(dest):
        dest = 'None'
    if src not in setOfsets[index][0]:
        setOfsets[index][0].add(src)
    if dest not in setOfsets[index][1]:
        setOfsets[index][1].add(dest)

def seperate(df):
    gb = df.groupby('graphId')
    graphs = [gb.get_group(x) for x in gb.groups]
    return graphs

def readPandasFile(parsedFile, names = ("sourceId", "sourceType", "destinationId", "destinationType", "syscal", "retTime","graphId", "pid", "cmdLineArgs", "spid"), sep=','):
    parsedDf = pd.read_csv(parsedFile, names=list(names), sep=sep)
    parsedDf['sourceId'] = parsedDf['sourceId'].str.strip('" \n\t')
    parsedDf['destinationId'] = parsedDf['destinationId'].str.strip('" \n\t')
    parsedDf['syscal'] = parsedDf['syscal'].str.strip('" \n\t')
    parsedDf['sourceType'] = parsedDf['sourceType'].str.strip('" \n\t')
    parsedDf['destinationType'] = parsedDf['destinationType'].str.strip('" \n\t')
    parsedList = parsedDf.values.tolist()
    uniqueGraphNames = sorted(list(parsedDf.graphId.unique()))
    return parsedDf, parsedList, uniqueGraphNames

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

def toList(df):
    return df.values.tolist()

def sortTime(adjDict):
    for key in adjDict:
        adjDict[key] = sorted(adjDict[key])
    return adjDict

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

def shortestPath(adjForward, adjBackward):
    adjForward, adjBackward = addSinkSource(adjForward, adjBackward)
    return adjForward

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


def findKAnomlousPaths(adjMatrix, K, graphName):
    G = nx.DiGraph()
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
                import pdb
                pdb.set_trace()
            regularityScore += edgeAttrib['weight']
            Kpath.append([ea[0],(edgeAttrib['syscal'], edgeAttrib['retTime']), ea[1]])
        Kpaths.append([Kpath, regularityScore, isDAG])
    return Kpaths

def k_shortest_paths(G, source, target, k, weight=None):
    theta = [p for p in nx.all_shortest_paths(G, source=source, target=target, weight = 'weight', method = 'bellman-ford')]
    return theta[:k]
