1. Generate the following list of files:
	a. X.pth -> tensor containing all the feature vectors for each node in the graph (if you dont have any, set this to zeros of the desired feature vector length)
	b. edges.pth -> tensor of 2 tensors: the first tensor is all source nodes and the second tensor is all the corresponding destination nodes to describe all the edges in the graph.
		i. for example the edge 1->2 would be given in as [[1],[2]]
	c. names.pth -> the names of each of the node, each name should be a tuple with the last number identifying its graph id. ie: (name of node, graphID)
        d. ensure that your X,edges,names files are in order. ie: edges for graph 1 should occur before edges for graph 2, so on so forth
2. feed into main -> nz, homePath, trainStartGraphID, trainEndGraphID, train, testStartGraphID, testEndGraphID
	a. nz is unique number for the embbedings
	b. homepath is the location where all files (x,edges, names) is located
	c. trainStartGraphID describes when the start of the training graphs, should correspond to number in the names 
	d. trainEndGraphID describes when the end of the training graphs, should correspond to number in the names
	e. train -> whether you should train or not.
	f. testStartGraphID describes when the start of the testing graphs, should correspond to number in the names
	g.testEndGraphID describes when the end of the testing graphs, should correspond to number in the names
3. start off by calling main with nz = 0 and train set to true
4. next, set train to false and recall main but set nz = 0, testStartGraphID = trainStartGraphID, testEndGraphID = trainEndGraphID
5. next, set train to false and recall main but set nz = 1 and set testStartGraphID, testStartGraphID to the actual test graph ids
5. this will generate two files called graphEmbed-0.pth, graphEmbed-1.pth
6. Open up these files with pytorch and use cdist to compare these embeddings. Find the minimum distance and that is your anomaly score. 
