import torch
from multiprocessing import Pool
import multiprocessing as mp
from tqdm import tqdm
import copy
import os

def generate(benGraphsPaths, attGraphsPaths, benFreqDB, attFreqDB):
        benScores, allBenScores = getScoreWrapper(benGraphsPaths, benFreqDB, 'ben')
        attScores, allAttScores  = getScoreWrapper(attGraphsPaths, attFreqDB, 'att')
        pathThreshold = calculatePath(flatten(allBenScores))
        attScores, caught = prune(allAttScores, pathThreshold, attScores)
        graphThreshold = calculate(benScores, attScores)
        return pathThreshold, graphThreshold, benScores, attScores, caught

pbar = None
def getScoreWrapper(graphsPaths, freqDBList, name):
    if os.path.exists(f'scores-{name}.pth') and os.path.exists(f'pathScores-{name}.pth'):
        return torch.load(f'scores-{name}.pth'), torch.load(f'pathScores-{name}.pth')
    else:
        allScores= []
        allGraphScores = []
        count = 0
        for i in range(len(graphsPaths)):
                graphPath = graphsPaths[i]
                freqDB = freqDBList[i]
                global pbar
                pbar = tqdm(total=2000000)
                global result_score
                global result_length
                result_score = []
                result_length = []
                for path in graphPath:
                        log_result(getScores(path, freqDB))
                lengths = torch.FloatTensor(result_length)
                smLen = torch.sum(lengths).item()
                lengths = lengths/smLen
                scores = torch.FloatTensor(result_score)
                scores = lengths * scores 
                scores = scores.tolist()
                allScores.append(sum(scores))
                allGraphScores.append(scores)
                print(f"finished with graph: {count}")
                count += 1
        torch.save(allScores, f'scores-{name}.pth')
        torch.save(allGraphScores, f'pathScores-{name}.pth')
        return allScores, allGraphScores

result_score = []
result_length = []

def log_result(result):
    result_score.append(result[0])
    result_length.append(result[1])
    pbar.update(1)

def getScores(path, freqDB):
        score = 0
        path = [(path[i], path[i+1]) for i in range(len(path)-1)]
        path = path[1:-1]
        for edge in path:
                if edge not in freqDB:
                        score += 1
        return (score/len(path), len(path))

def flatten(listOfLists):
         return [item for sublist in listOfLists for item in sublist]
         
def calculate(benScores, attScores):
        benScoresTen = torch.FloatTensor(benScores)
        benScores = list(sorted(list(set(benScores)), reverse=True))
        benScores = torch.FloatTensor(benScores)
        benScores += 0.0001
        attScoresTen = torch.FloatTensor(attScores)

        scores = []
        diff = []
        for i in range(benScores.shape[0]):
                mask = attScoresTen >= benScores[i]
                sm = torch.sum(mask).item()
                mask2 = benScoresTen <= benScores[i] 
                sm2 = torch.sum(mask2).item()
                diff.append(sm + sm2)
        return benScores[diff.index(max(diff))]

def prune(scoresOfScores, threshold, graphScores):
    caught = 0
    newList = []
    for i in range(len(scoresOfScores)):
        scores = torch.FloatTensor(scoresOfScores[i])
        msk = scores >= threshold
        if torch.sum(msk).item() > 0:
            caught += 1
        else:
            newList.append(graphScores[i])
    if newList == []:
        newList = [[1.0]]
    return newList, caught


def calculatePath(benScores):
    benScoresTen = torch.FloatTensor(benScores)
    uniScores = torch.unique(benScoresTen).tolist()
    uniScores = sorted(uniScores, reverse = True)
    return uniScores[0] + 0.0001

        

