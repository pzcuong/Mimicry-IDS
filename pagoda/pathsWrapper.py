import pandas as pd
import networkx as nx



def generate(files, freqDB):
        namesDB = {'mx': 1}
        allPaths = []
        newFreqDBList = []
        for fl in files:
                df = pd.read_csv(fl, names = ['srcName', 'srcType', 'destName', \
                        'destType', 'syscal', 'programName', 'retTime', 'PID', 'cmd1', \
                        'cmd2' ])
                srcTyp = df['srcType'].str.strip('" \n\t')
                srcNames = df['srcName'].str.strip('" \n\t')
                dstTyp = df['destType'].str.strip('" \n\t')
                destNames = df['destName'].str.strip('" \n\t')
                PIDS = df['PID']
                secPIDS = df['cmd1']
                srcPairs = list(zip(srcNames, srcTyp))
                dstPairs = list(zip(destNames, dstTyp))
                G = nx.DiGraph()
                newFreqDB = set()
                for i in range(len(srcPairs)):
                        srcPair = srcPairs[i]
                        destPair = dstPairs[i]
                        if srcPair[1] == 'process' and destPair[1] == 'process':
                                uniSrcName = (srcPair[0], int(PIDS[i]))
                                if type(secPIDS[i]) == float:
                                    spid =  int(secPIDS[i])
                                else:
                                    spid = int(PIDS[i])
                                uniDestName = (destPair[0], spid)

                        elif srcPair[1] == 'process':
                                uniSrcName = (srcPair[0], PIDS[i])
                                uniDestName = (destPair[0], None)
                        elif destPair[1] == 'process':
                                uniSrcName = (srcPair[0], None)
                                uniDestName = (destPair[0], PIDS[i])
                        else:
                                raise Exception("One node in edge must be a process")
                        if uniSrcName not in namesDB:
                                namesDB[uniSrcName] = namesDB['mx']
                                namesDB['mx'] += 1
                        if uniDestName not in namesDB:
                                namesDB[uniDestName] = namesDB['mx']
                                namesDB['mx'] += 1
                        G.add_edge(namesDB[uniSrcName], namesDB[uniDestName])
                        if (uniSrcName[0], uniDestName[0]) in freqDB:
                            newFreqDB.add((namesDB[uniSrcName], namesDB[uniDestName]))
                roots = [n for n,d in G.in_degree() if d==0] 
                leaves = [n for n,d in G.out_degree() if d==0] 
                for i in range(len(roots)):
                        root = roots[i]
                        G.add_edge(0, root)
                for i in range(len(leaves)):
                        leaf = leaves[i]
                        G.add_edge(leaf, namesDB['mx'])
                paths = nx.algorithms.simple_paths.all_simple_paths(G, 0, namesDB['mx'])
                allPaths.append(paths)
                newFreqDBList.append(newFreqDB)
        revDict = {v:k for k,v in namesDB.items()}
    
        return allPaths, newFreqDBList

                



