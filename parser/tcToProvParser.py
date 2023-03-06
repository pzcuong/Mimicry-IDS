import pandas as pd
import sys
startOff = int(sys.argv[1])
graphID = int(sys.argv[2])
gbMax = 0
inFileName = 
outFileName = 
def getBenignFile(fl, fl2):
    df = pd.read_csv(fl,
                           names=["sourceId", "sourceType", "destinationId", "destinationType", "syscal", "program"])
    srcNames = df['sourceId'].str.strip('" \n\t')
    destNames = df['destinationId'].str.strip('" \n\t')
    srcTyp = df['sourceType'].str.strip('" \n\t')
    destTyp = df['destinationType'].str.strip('" \n\t')
    program = df['program'].str.strip('" \n\t')
    newSrcNames = []
    newDestNames = []
    pids = []
    spids = []
    for i in range(len(srcTyp)):
        srcName, sPID = srcNames[i].split("~!")
        destName, destPID = destNames[i].split("~!")
        spid = None
        if srcTyp[i] == 'process':
            if destTyp[i] == 'process':
                spid = destPID
            pids.append(sPID)
        else:
            pids.append(destPID)
        spids.append(spid)
        newSrcNames.append(srcName)
        newDestNames.append(destName)
    df["sourceId"] = newSrcNames
    df["destinationId"] = newDestNames
    df["pids"] = pids
    df["program"] = program
    df["arg1"] = spids
    df["arg2"] = ""
    df["graphID"] = graphID
    indx = list(df.index.values)
    indx = [int(x)+startOff for x in indx]
    df['timestamp'] = indx
    df = df[["sourceId", "sourceType", "destinationId", "destinationType", "syscal", "program", "timestamp", "pids", "arg1", "arg2", "graphID"]]
    df.to_csv(fl2, header=False, index = False)

getBenignFile(inFileName, outFileName)
