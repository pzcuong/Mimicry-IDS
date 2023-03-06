import pandas as pd
from collections import Counter



def generate(files):
        freqDB = None
        pairs = []
        df = None
        for fl in files:
                tempDf = pd.read_csv(fl, names = ['srcName', 'srcType', 'destName', \
                        'destType', 'syscal', 'programName', 'retTime', 'PID', 'cmd1', \
                        'cmd2' ])
                if df is None:
                    df = tempDf
                else:
                    df = pd.concat([df, tempDf])
        srcNames = df['srcName'].str.strip('" \n\t')
        destNames = df['destName'].str.strip('" \n\t')
        pairs += list(zip(srcNames, destNames))
        pairs = Counter(pairs)
        pairs = [k for k, c in pairs.items() if c >= 2]
        freqDB = set(pairs)
        return freqDB

