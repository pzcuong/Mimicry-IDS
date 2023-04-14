import pandas 
import glob
import freqDBWrapper
import pathsWrapper
import thresholdWrapper
import calcStatsWrapper
import os
import torch
import sys
benDir = sys.argv[1]
attDir = sys.argv[2]
evDir = sys.argv[3]

benFL = glob.glob(f"{benDir}/*")[:]
attFL = glob.glob(f"{attDir}/*")[:]
evFL = glob.glob(f"{evDir}/*")[:]
if os.path.exists('freqDB.pth'):
    freqDB = torch.load('freqDB.pth')
else:
    freqDB = freqDBWrapper.generate(benFL)
    torch.save(freqDB, 'freqDB.pth')



# get graph threshold
if os.path.exists(f'results.pth'):
    pathThreshold, graphThreshold, benPaths, attPaths, attCaught = torch.load('results.pth')
else:
    benPaths, benFreqDB = pathsWrapper.generate(benFL, freqDB)
    attPaths, attFreqDB = pathsWrapper.generate(attFL, freqDB)
    pathThreshold, graphThreshold, benPaths, attPaths, attCaught = thresholdWrapper.generate(benPaths, attPaths, benFreqDB, attFreqDB)
    torch.save((pathThreshold, graphThreshold, benPaths, attPaths, attCaught), 'results.pth')

evPaths, evFreqDB = pathsWrapper.generate(evFL, freqDB)
evPaths, allEvPaths = thresholdWrapper.getScoreWrapper(evPaths, evFreqDB, 'ev')

evPaths, evCaught = thresholdWrapper.prune(allEvPaths, pathThreshold, evPaths) 

# get auc, evasion
fpr, tpr, evasionRate = calcStatsWrapper.calculate(graphThreshold, benPaths, attPaths, evPaths)


print(f'fpr: {fpr}, tpr: {tpr+attCaught}, evasion: {evasionRate+evCaught}')



