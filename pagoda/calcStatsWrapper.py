import torch

def calculate(threshold, benPaths, attPaths, evPaths, pathThreshold = 2):
        benFlag = calcAnom(benPaths, threshold, pathThreshold)
        attFlag = calcAnom(attPaths, threshold, pathThreshold)
        evFlag = calcAnom(evPaths, threshold, pathThreshold)
        return benFlag, attFlag, evFlag

def calcAnom(paths, threshold, pathThreshold):
        flag = 0
        path = torch.FloatTensor(paths)
        mask = path >= threshold
        flag = torch.sum(mask).item()
        return flag


