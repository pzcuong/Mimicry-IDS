import bisect
import pickle

def addEdgeToNewAdj(forwardAdjNew, backAdjNew, edge, forward):
    if forward:
        src = edge[0]
        dest = edge[1]
    else:
        src = edge[1]
        dest = edge[0]
    edgeAttributesForward = (edge[2][0], edge[2][1], dest, edge[2][2])
    edgeAttributesBackward = (edge[2][0], edge[2][1], src, edge[2][2])
    if src not in forwardAdjNew:
        forwardAdjNew[src] = set()
    if dest not in backAdjNew:
        backAdjNew[dest] = set()
    if edgeAttributesForward not in forwardAdjNew[src]:
        forwardAdjNew[src].add(edgeAttributesForward)
    if edgeAttributesBackward not in backAdjNew[dest]:
        backAdjNew[dest].add(edgeAttributesBackward)

def dfs(startNode, startTime, adjDict, forward, newForAdj, newBackAdj):
    stack = [(startNode, startTime, [startNode], 0)]
    totalCount = 8
    while stack:
        (vertex, retTime, nodesTravelledTo, nodesTravelled) = stack.pop()
        if vertex not in adjDict:
            continue
        elif nodesTravelled >= totalCount:
            continue
        else:
            nextNodes = set(adjDict[vertex].keys()) - set(nodesTravelledTo)
            if len(nextNodes) == 0:
                continue
            for next in nextNodes:
                if forward:
                    fst, snd, trd = zip(*adjDict[vertex][next])
                    i = bisect.bisect_right(fst, retTime)
                    if i != len(adjDict[vertex][next]):
                        stack.append((next, adjDict[vertex][next][i][0], nodesTravelledTo + [next], nodesTravelled + 1))
                        # while i != len(adjDict[vertex][next]):
                        addEdgeToNewAdj(newForAdj, newBackAdj, (vertex, next, adjDict[vertex][next][i]), forward)
                            # i += 1
                elif not forward:
                    fst, snd, trd = zip(*adjDict[vertex][next])
                    i = bisect.bisect_right(fst, retTime)
                    if i:
                        stack.append(
                            (next, adjDict[vertex][next][i - 1][0], nodesTravelledTo + [next], nodesTravelled + 1))
                        # while i:
                        addEdgeToNewAdj(newForAdj, newBackAdj, (vertex, next, adjDict[vertex][next][i - 1]),
                                            forward)
                        # i -=1

def writeToFile(jsonObjectList, fileName3):
    with open(fileName3, 'wb') as filehandle:
        # store the data as binary data stream
        pickle.dump(jsonObjectList, filehandle)

def combinePath(edge, backwardAdjList, forwardAdjList):
    newForwardAdjList = {}
    newBackwardAdjList = {}
    src = edge[0]
    dest = edge[1]
    edgeAttributesForward = list(edge[2])
    edgeAttributesForward.insert(2, dest)
    edgeAttributesForward = tuple(edgeAttributesForward)
    edgeAttributesBackward = list(edge[2])
    edgeAttributesBackward.insert(2, src)
    edgeAttributesBackward = tuple(edgeAttributesBackward)
    newForwardAdjList[src] = set()
    newForwardAdjList[src].add(edgeAttributesForward)
    newBackwardAdjList[dest] = set()
    newBackwardAdjList[dest].add(edgeAttributesBackward)
    dfs(edge[1], edge[2][0], forwardAdjList, True, newForwardAdjList, newBackwardAdjList)
    dfs(edge[0], edge[2][0], backwardAdjList, False, newForwardAdjList, newBackwardAdjList)
    print("finished her up Part 2")
    writeToFile(newForwardAdjList, 'forwardAdjList.txt')
    writeToFile(newBackwardAdjList, 'backwardAdjList.txt')
    return newForwardAdjList, newBackwardAdjList

def getPathAnomalyScoreNoEdge(targetNodesDest, targetNodesSrc, forwardAdjList,backwardAdjList):
    adjlists = []
    for startingNode in targetNodesDest:
        # sysCall = 'execve'
        sysCall = 'connect'
        execEdges = set()
        edges = backwardAdjList.get(startingNode, None)
        if edges == None:
            raise Exception ("There is no call to starting Node in Graph")
        for edge in edges:
            for call in edges[edge]:
                if call[1] == sysCall and edge in targetNodesSrc:
                    execEdges.add((edge, startingNode, call))
        if len(execEdges) == 0:
            raise Exception("There is no "+str(sysCall)+" call to starting Node in Graph")
        for execEdge in execEdges:
            startNode = execEdge[0]
            destNode = execEdge[1]
            attr = execEdge[2]
            if destNode[0] == 'Null':
                destNode=startNode
            execEdge = (startNode, destNode, attr)
            newforwardAdjList, newbackwardAdjList = combinePath(execEdge, backwardAdjList, forwardAdjList)
            adjlists.append((newforwardAdjList, newbackwardAdjList))
            return adjlists

