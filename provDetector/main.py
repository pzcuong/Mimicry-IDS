from freqDB import *
import os
import sys
# flow of graph
# read in freqDict with readPandasFile
# take parsedList from above call and build freqDict with createFreqDict
# read in graph with readPandasFile
# build adj list with createAdjList, pass in parsedlist from above call
# select an edge from graph and run getPathAnomalyScore to get anomaly score of all paths
# have to specify M for IN and OUT scores
trainFilePath = sys.argv[1]
testFilePath = sys.argv[2]
kname = sys.argv[1]
def main(names = ("sourceId", "sourceType", "destinationId", "destinationType", "syscal","processName", "retTime", "pid", "arg1", "arg2", "graphId")):
    #1. generate a frequency database
    print("reading datasets")
    df_train, dfList_train, graphNames_train = readPandasFile(trainFilePath,names=names, sep=',')
    if not os.path.isfile('freqList.data') or not os.path.isfile('setOfsets.data'): # running this in all cases
        print("generating freq db")
        freqDict, setOfsets = createFreqDict(dfList_train, graphNames_train, 10, fRow=False)
        print("writing freq to file")
        writeToFile(freqDict, 'freqList.data')
        writeToFile(setOfsets, 'setOfsets.data')

    #2. assign a anomaly score to each edge
    print("testing and extracting kpaths")
    kPathsPerGraph = []
    df_test, dfList_test, graphNames_test = readPandasFile(testFilePath, names=names, sep=',')
    freqDict = readFromFile('freqList.data')
    setOfsets = readFromFile('setOfsets.data')
    graphs = seperate(df_test)
    count = 1
    for graph in graphs:
        count += 1
        graphName = graph['graphId'].iloc[0]
        graph = toList(graph)
        adjListForward, adjListBackward= createAdjListCleanly(graph, setOfsets, freqDict)
        adjForward = sortTime(adjListForward)
        forAdj, backAdj = makeAdjListDAGFaster(adjForward)
        adjMatrix = shortestPath(forAdj, backAdj)
        kPaths = findKAnomlousPaths(adjMatrix, 20, graphName)
        kPathsPerGraph.append((graphName, kPaths))
    f_name = kname + '_kpathsTrainingGraphs.data'
    writeToFile(kPathsPerGraph, f_name)
main()
