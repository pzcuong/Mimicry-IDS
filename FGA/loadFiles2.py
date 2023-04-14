import torch
import json
from pathlib import Path
import os
from itertools import compress
import sys


def loadFilesLarge(data, homePath):
    names = [f'adjMat.pth', f'X.pth', f'names.pth']
    objects = []
    for i in range(len(names)):
        objects.append(torch.load(f'{homePath}/{names[i]}'))
    edges, X, names = tuple(objects)
    data.edge_index = edges
    data.edge_attr = None
    data.x = X
    return data



