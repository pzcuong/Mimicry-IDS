1. Format all files in the format "sourceId", "sourceType", "destinationId", "destinationType", "syscal","processName", "retTime", "pid", "arg1", "arg2", "graphId"
   a. processName is the name of the process, in case of two processes, it is the name of the source process
   b. arg1 is case of a clone is the PID of the cloned process
   c. arg2 is not needed, can be left blank
   d. graphID is what graph the edge is part of. We assume a single csv containing all graphs within it
2. Pass in a training and testing file to main
   a. Training file should be a series of benign graphs
   b. testing files can be either benign data, attack data, or evasion data
3. Also pass into main a fileName to be assigned to the resulting K anomolous paths from the testing dataset
   a. K = 20, you can change that to more in main.py line 40 if needed
4. ProvDetector will spit out a list of paths compressed with pickle 
