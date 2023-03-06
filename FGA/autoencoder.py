import torch
from torch_geometric.datasets import Planetoid
import torch_geometric.transforms as T
from torch_geometric.nn import GCNConv
from torch_geometric.utils import train_test_split_edges
from torch_geometric.nn import GAE
import loadFiles2
from torch.nn import Linear

import torch_geometric.transforms as T
from torch_geometric.datasets import Planetoid
from torch_geometric.nn import ARGVA 

import sys

nz = sys.argv[1]

dataset = Planetoid("\..", "CiteSeer", transform=T.NormalizeFeatures())
dataset.data
data = dataset[0]
data.train_mask = data.val_mask = data.test_mask = None

doc2vec = 'doc2vec'
removeWeird = True
data, classes, names, rootNames = loadFiles2.loadFiles(data, 'all', -1, rootAdj=False,  versioned=False, mimi=False, createAdv=False, isTensor = False, dataSetType = 'EV')
do_train = False
x_mask = torch.Tensor(list(range(data.x.shape[0])))
if do_train:
    start = None
    end = None
    for i in range(len(names)):
        if names[i][-1] == 300:
            if start is None:
                start = i-1
        if names[i][-1] == 374:
            end = i
            break
    src = data.edge_index[0][(data.edge_index[0]<end) & (data.edge_index[0]>start)]
    dest = data.edge_index[1][(data.edge_index[1]<end) & (data.edge_index[1]>start)]
    src = src-start-1
    dest = dest-start-1
    data.edge_index = torch.stack((src,dest), 0)


proc = []
fil = []
soc = []
for i in range(len(names)):
    typ = names[i][0][-1]
    if typ == 'process':
        proc.append(True)
        fil.append(False)
        soc.append(False)
    elif typ == 'socket':
        proc.append(False)
        fil.append(False)
        soc.append(True)
    elif typ == 'file':
        proc.append(False)
        fil.append(True)
        soc.append(False)
proc = torch.BoolTensor(proc)
fil = torch.BoolTensor(fil)
soc = torch.BoolTensor(soc)
proc_feat = torch.ones_like(data.x[0])
fil_feat = torch.ones_like(data.x[0])
soc_feat = torch.ones_like(data.x[0])
proc_feat[proc_feat == 1] = 1
soc_feat[soc_feat == 1] = 2
fil_feat[fil_feat == 1] = 3
data.x[proc] = proc_feat
data.x[fil] = fil_feat
data.x[soc] = soc_feat
# here get in streamspot dataset

class Encoder(torch.nn.Module):
    def __init__(self, in_channels, hidden_channels, out_channels):
        super().__init__()
        self.conv1 = GCNConv(in_channels, hidden_channels)
        self.conv_mu = GCNConv(hidden_channels, out_channels)
        self.conv_logstd = GCNConv(hidden_channels, out_channels)

    def forward(self, x, edge_index):
        x = self.conv1(x, edge_index).relu()
        return self.conv_mu(x, edge_index), self.conv_logstd(x, edge_index)


class Discriminator(torch.nn.Module):
    def __init__(self, in_channels, hidden_channels, out_channels):
        super().__init__()
        self.lin1 = Linear(in_channels, hidden_channels)
        self.lin2 = Linear(hidden_channels, hidden_channels)
        self.lin3 = Linear(hidden_channels, out_channels)

    def forward(self, x):
        x = self.lin1(x).relu()
        x = self.lin2(x).relu()
        return self.lin3(x)
num_features= data.x.shape[1]


def train():
    model.train()
    encoder_optimizer.zero_grad()
    z = model.encode(x, edge_index)
    # We optimize the discriminator more frequently than the encoder.
    for i in range(5):
        discriminator_optimizer.zero_grad()
        discriminator_loss = model.discriminator_loss(z)
        discriminator_loss.backward()
        discriminator_optimizer.step()

    loss = model.recon_loss(z, edge_index)
    loss = loss + model.reg_loss(z)
    loss = loss + (1 / num_nodes) * model.kl_loss()
    loss.backward()
    encoder_optimizer.step()
    return float(loss)

def findEdges(graphID, data):
    start = None
    end = None
    for i in range(len(names)):
        if names[i][-1] == graphID:
            if start is None:
                start = i-1
        if names[i][-1] == graphID+1:
            end = i
            break
        if i == len(names) -1 :
            end = i+1
    src = data.edge_index[0][(data.edge_index[0]<end) & (data.edge_index[0]>start)]
    dest = data.edge_index[1][(data.edge_index[1]<end) & (data.edge_index[1]>start)]
    src = src-start-1
    dest = dest-start-1
    g_edge_index = torch.stack((src,dest), 0)
    return g_edge_index, start, end

epochs = 2000

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
x = data.x.to(device)
if do_train:
    x = x[(x_mask<end) & (x_mask>start)]
    encoder = Encoder(num_features, hidden_channels=64, out_channels=32)
    discriminator = Discriminator(in_channels=32, hidden_channels=64,
                              out_channels=32)
    model = ARGVA(encoder, discriminator).to(device)

    encoder_optimizer = torch.optim.Adam(encoder.parameters(), lr=0.00005)
    discriminator_optimizer = torch.optim.Adam(discriminator.parameters(),
                                           lr=0.00001)
    edge_index = data.edge_index.to(device)
    num_nodes = x.shape[0]
    model = model.to(device)
else:
    model = torch.load('autoencoder2.pth')

embeddings = None


def test(x, edge_index):
    model.eval()
    with torch.no_grad():
        z = model.encode(x, edge_index)
    return z #model.test(z, pos_edge_index)


if do_train:
    for epoch in range(1, epochs + 1):
        loss = train()
        print(loss)
    torch.save(model, 'autoencoder2.pth')
else:
    graphs = list(range(500,700))
    for graph in graphs:
        x = data.x.to(device)
        g_edge_index, start, end = findEdges(graph, data)
        g_edge_index = g_edge_index.to(device)
        x = x[(x_mask<end) & (x_mask>start)]
        z = test(x, g_edge_index).unsqueeze(0).cpu()
        z = torch.mean(z, 1)
        if embeddings is None:
            embeddings = z
        else:
            embeddings = torch.cat((embeddings, z), 0)
    torch.save(embeddings,'evGraphEmbed-{nz}.pth')
