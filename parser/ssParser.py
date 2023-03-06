import os
from Process import processElement
from Descriptor import descElement
from Thread import threadElement
from difflib import get_close_matches
import copy

import sys
list_of_arguments = sys.argv
pathToSS = list_of_arguments[1]


def truncateLine(line):
    # ret_val , ret_time , call_time , process_name , pid , tid , syscall , arg1 , arg2 , ...
    syscal = line.strip().split(', ')
    # print line_num,syscal[0],syscal[1],syscal[2],syscal[3],syscal[4],syscal[5],syscal[6]
    return syscal
def checkSyntax(syscal):
    if len(syscal) < 7:
        return False
    temp1 = syscal[5]
    temp2 = syscal[2]
    temp3 = syscal[4]
    if not syscal[4].isdigit():
        return False
    if not syscal[5].isdigit():
        return False
    if not syscal[2].isdigit():
        return False
    return True

def checkSuccess(syscal):
    if syscal[6] == "socketpair" or syscal[6] == "truncate" or syscal[6] == "ftruncate" or syscal[6] == "chmod" or syscal[6] == "chown" or syscal[6] == "stat" or syscal[6] == "fstat" or syscal[6] == "lstat" or syscal[6] == "fstatat" or syscal[6] == "link" or syscal[6] == "unlink" or syscal[6] == "access" or syscal[6] == "close" or syscal[6] == "bind" or syscal[6] == "execl" or syscal[6] == "execv" or syscal[6] == "execle" or syscal[6] == "execve" or syscal[6] == "execlp" or syscal[6] == "execvp":
        if syscal[0] != "0":
            return False
    if syscal[6] == "socket" or syscal[6] == "open" or syscal[6] == "creat" or syscal[6] == "write" or syscal[6] == "pwrite" or syscal[6] == "writev" or syscal[6] == "pwritev" or syscal[6] == "send" or syscal[6] == "sendto" or syscal[6] == "sendmsg" or syscal[6] == "read" or syscal[6] == "recv" or syscal[6] == "recvfrom" or syscal[6] == "recvmsg":
        if not syscal[0].isdigit() or int(syscal[0]) < 0:
            return False
    if syscal[6] == "connect":
        if syscal[0][0] == '-' and 'EINPROGRESS' not in syscal[0]:
            return False
    return True

def get_descriptor(syscal, d):
    if (syscal[3], syscal[4]) in d[syscal[7]]:
        obj = d[syscal[7]][(syscal[3], syscal[4])]
    else:
        processes = [x[0] for x in d[syscal[7]].keys()]
        closest = get_close_matches(syscal[3], processes)
        if closest == []:
            return None, 0, 0
        idx = processes.index(closest[0])
        obj = d[syscal[7]][list(d[syscal[7]].keys())[idx]]
    return obj
def createFiles(num):
    if os.path.isfile(f"processedFiles/output_ADM-{num}.csv"):
        os.remove(f"processedFiles/output_ADM-{num}.csv")
    output_ADM = open(f"processedFiles/output_ADM-{num}.csv", "w")

    if os.path.isfile(f"processedFiles/process_metadata-{num}.csv"):
        os.remove(f"processedFiles/process_metadata-{num}.csv")
    process_meta = open(f"processedFiles/process_metadata-{num}.csv", "w")
    process_meta.write("graph, id , pid , name , type\n")

    if os.path.isfile(f"processedFiles/file_metadata-{num}.csv"):
        os.remove(f"processedFiles/file_metadata-{num}.csv")
    file_meta = open(f"processedFiles/file_metadata-{num}.csv", "w")
    file_meta.write("graph, id , ppid_fd , path , type\n")
    return output_ADM, process_meta, file_meta

graphIds = {
    "gmail/": 100,
    "youtube/": 0,
    "game/": 200,
    "download/": 400,
    "cnn/": 300,
    "attack/": 500
}

#TODO: handle mmap, access, link, unlink, listen, fstat, truncate, accept
#TODO: Arguements for send, recv, read, write are not being recorded!
#TODO: Figure Out How to Resolve Unknown FD and SD
#TODO: Removed the use of threads; firefox makes threads (like socket thread) to do certain acitivies
# and is therefore not connected to the main graph, current we merge all this to single process, maybe think of
# way to ensure information flows from main processes and threads, cloning of threads will be therefore skipped



for name in ["game/", "youtube/", "gmail/", "download/", "attack/", "cnn/"]:
#for name in {"attack/", "cnn/"}:
    for num in range(0, 100):
        file = name + str(num)
        input = open("{pathToSS}" + file, "r")
        graphId = graphIds[name] + num
        output_ADM, process_meta, file_meta = createFiles(graphId)
        graphId = str(graphId)
        execQueue = {}
        procGT = {}
        revDict = {}
        process = {}
        fd_checkout = {}
        fd ={"0": ("stdin", ['']),
            "1": ("stdout", ['']),
            "2": ("stderr", [''])}
        sd_checkout = {}
        sd ={}
        line_num = 0
        missedSD = 0
        missedFD = 0
        for line in input:
            line_num += 1
            if line_num == 12:
                flag = 1
            syscal = truncateLine(line)
            if (not checkSyntax(syscal)):
                #print("Syntax Error at line:", line_num)
                continue
            if (not checkSuccess(syscal)):
               # print("Unsucessful Syscal at line:", line_num)
                continue

            if syscal[4] in execQueue:
                dirtyBit = -1
                for i in range(len(execQueue[syscal[4]])):
                    ls = execQueue[syscal[4]][i]
                    if str(syscal[3]) in ls[1] or (syscal[3] == 'sh' and '//' not in ls[1]):
                        if syscal[3] == 'sh':
                            pName = 'sh'
                        else:
                            pName = ls[1]
                        if syscal[3] not in procGT:
                            procGT[syscal[3]] = {}
                            procGT[syscal[3]]['0'] = pName
                        if syscal[4] in procGT[syscal[3]] and syscal[4] != '0':
                            raise Exception ("reexecuting a processes that already started")
                        procGT[syscal[3]][syscal[4]] = pName
                        output_ADM.write(
                            ls[0] + ", " + "process" + ", " + pName + ", process" + ", " + "execve" + ", " + ls[
                                3] + ", " +
                            str(ls[2]) + ", " + syscal[4] + "," + syscal[3] + "," + ls[4] + "\n")
                        dirtyBit = i
                        break
                if dirtyBit >= 0:
                    del execQueue[syscal[4]][dirtyBit]
            if syscal[3] in ['Socket Thread', 'Gecko_IOThread', 'Cache I/O', 'DOM Worker', 'URL Classifier',
                             'localStorage DB'] or 'StreamTrans' in syscal[3] \
                    or 'DNS Resolver' in syscal[3] or 'mozStorage' in syscal[3]:
                syscal[3] = 'firefox'
            if syscal[3] in ['Chrome_ChildThr']:
                syscal[3] = 'plugin-containe'
            if syscal[3] == 'dconf worker':
                if (syscal[4], 'firefox') in process and syscal[5] in process[(syscal[4], 'firefox')].thread:
                    syscal[3] = 'firefox'
                elif (syscal[4], 'plugin-containe') in process and syscal[5] in process[(syscal[4], 'plugin-containe')].thread:
                    syscal[3] = 'plugin-containe'
                else:
                    print(num,name)
                    raise Exception ("Anomolous Dconf Worker")
            if (syscal[4], syscal[3]) not in process:
                # if syscal[4] != syscal[5]:
                #     raise Exception(f"New Processes Created with PID != TID, Line {line_num}")
                process[(syscal[4], syscal[3])] = processElement()
                if syscal[3] != 'stapio':
                    if (syscal[3]) not in procGT:
                        #print(f"new process {(syscal[4], syscal[3])} did not have a parent")
                        procGT[syscal[3]] = {}
                        procGT[syscal[3]]['0'] = syscal[3]
                        procGT[syscal[3]][syscal[4]] = syscal[3]
                else:
                    procGT[syscal[3]] = {}
                    procGT[syscal[3]]['0'] = 'usr/bin/systemTap'
                    procGT[syscal[3]][syscal[4]] = 'usr/bin/systemTap'
                if syscal[4] not in procGT[syscal[3]]:
                    procGT[syscal[3]][syscal[4]] = procGT[syscal[3]]['0']
                processName = procGT[syscal[3]][syscal[4]]

                process[(syscal[4], syscal[3])].thread[syscal[5]] = threadElement("process", processName)
                process[(syscal[4], syscal[3])].descriptor["0"] = descElement("stdin", 0)
                process[(syscal[4], syscal[3])].descriptor["1"] = descElement("stdout", 1)
                process[(syscal[4], syscal[3])].descriptor["2"] = descElement("stderr", 2)

                #(f"new process found: {(syscal[4], syscal[3])} at line:{line_num}")

            if syscal[5] not in process[(syscal[4], syscal[3])].thread:
                if len(process[(syscal[4], syscal[3])].thread) != 0:
                    process[(syscal[4], syscal[3])].thread[syscal[5]] = copy.deepcopy(process[(syscal[4], syscal[3])].thread[list(process[(syscal[4], syscal[3])].thread.keys())[0]])

                else:
                    raise Exception(f"There exists a thread ID:{syscal[5]} for PID {syscal[4]} "
                                    f"that has not been initialized on line {line_num}")

            if syscal[6] == "fork" or (syscal[6] == "clone" and not "THREAD" in syscal[7]):
                if (syscal[0], syscal[3]) in process:
                    raise Exception(f"Error: {syscal[3]} is creating an already existed process: {syscal[0]} "
                                    f"at line: {line_num}")
                process[(syscal[0], syscal[3])] = processElement()
                process[(syscal[0], syscal[3])].descriptor.update(process[(syscal[4], syscal[3])].descriptor)
                if syscal[4] not in procGT[syscal[3]]:
                    procGT[syscal[3]][syscal[4]] = procGT[syscal[3]]['0']
                processName = procGT[syscal[3]][syscal[4]]
                process[(syscal[0], syscal[3])].thread[syscal[0]] = threadElement("process", processName)
                sysArgs = ' '.join(syscal[7:]).replace('\"', '').replace("|", ";").replace(" ", ";")
                sysArgs = f'[{sysArgs}]'
                output_ADM.write(str(process[(syscal[4], syscal[3])].thread[syscal[5]].id) + ", " +
                                 process[(syscal[4], syscal[3])].thread[syscal[5]].type + ", " + str(
                    process[(syscal[0], syscal[3])].thread[syscal[0]].id) + ", process" + ", " + syscal[
                                     6] + ", " + str(syscal[3]) + "," + syscal[1] + ", " + syscal[4] + "," + syscal[
                                     0] + "," + sysArgs + "\n")

            elif syscal[6] == "clone" and "THREAD" in syscal[7]:
                if syscal[0] in process[(syscal[4], syscal[3])].thread:
                    raise Exception(f"Error:{syscal[4]} is creating an already existed thread: {syscal[0]} "
                                    f"at line: {line_num}")
                if syscal[4] not in procGT[syscal[3]]:
                    procGT[syscal[3]][syscal[4]] = procGT[syscal[3]]['0']
                processName = procGT[syscal[3]][syscal[4]]
                process[(syscal[4], syscal[3])].thread[syscal[0]] = threadElement("process", processName)
                sysArgs = ' '.join(syscal[7:]).replace('\"', '').replace("|", ";").replace(" ", ";")
                sysArgs = f'[{sysArgs}]'

                # output_ADM.write(str(process[(syscal[4], syscal[3])].thread[syscal[5]].id) + ", " +
                #                  process[(syscal[4], syscal[3])].thread[syscal[5]].type + ", " + str(
                #     process[(syscal[4], syscal[3])].thread[syscal[0]].id) + ", thread" + ", " + syscal[
                #                      6] + ", " + str(syscal[3]) + ", " + syscal[1] + ", " + syscal[4] + "," +
                #                  'None' + "," + sysArgs + "\n")

            elif syscal[6] == "waitpid":
                if (syscal[7], syscal[3]) in process:
                    output_ADM.write(str(process[(syscal[4], syscal[3])].thread[syscal[5]].id) + ", " +
                                     process[(syscal[4], syscal[3])].thread[syscal[5]].type + ", " + str(
                        process[(syscal[7], syscal[3])].thread[syscal[7]].id) + ", " +
                                     process[(syscal[7], syscal[3])].thread[syscal[7]].type + ", " + syscal[
                                         6] + ", " + str(syscal[3]) + ", " + syscal[1] + ", " + syscal[4] + "," +
                                 syscal[0] + "," + ' '.join(syscal[8:]) + "\n")


            elif syscal[6] == "open" or syscal[6] == "creat":
                # if syscal[0] in fd and (syscal[3], syscal[4]) in fd[syscal[0]]:
                    # raise Exception(f"{syscal[3], syscal[4]} is creating an already existed descriptor (file): "
                    #                 f"{syscal[0]} at line: {line_num}")
                    # print(f"Warning: {syscal[4]} is creating an already existed descriptor (file): "
                    #                 f"{syscal[0]} at line: {line_num}")
                if syscal[0] not in fd:
                    fd[syscal[0]] = {}
                if syscal[0] in ["0", "1", "2"]:
                    continue
                else:
                    fd[syscal[0]][(syscal[3], syscal[4])] = (syscal[7], syscal[8:])
            elif syscal[6] == "socket":
                raise Exception (f"Not Implemented Handler For Socket, Line {line_num} contains it")

            elif syscal[6] == "connect" or syscal[6] == "accept" or syscal[6] == "bind":
                # if syscal[7] in sd and (syscal[3], syscal[4]) in sd[syscal[7]]:
                #     raise Exception(f"{syscal[3], syscal[4]} is creating an already existed descriptor (socket): "
                #                     f"{syscal[0]} at line: {line_num}")
                if syscal[6] == "connect":
                    id = syscal[9] if syscal[9][-1] != "}" else syscal[9][:-1]
                    typ = syscal[8][1:]

                elif syscal[6] ==  "bind":
                    id = syscal[8][1:]
                    typ = syscal[9]
                elif syscal[6] ==  "accept":
                    typ = None
                    id = None
                else:
                    typ = None
                    id = None
                if syscal[7] not in sd:
                    sd[syscal[7]] = {}
                if len(syscal) == 11:
                    sd[syscal[7]][(syscal[3], syscal[4])] = (id, typ, syscal[10])
                elif len(syscal) == 12:
                    sd[syscal[7]][(syscal[3], syscal[4])] = (id, typ, syscal[10][:-1] + ',' + syscal[11])
                else:
                    continue

            elif syscal[6] == "send" or syscal[6] == "sendto" or syscal[6] == "sendmsg" or \
                syscal[6] == "recv" or syscal[6] == "recvfrom" or syscal[6] == "recvmsg":
                if syscal[7] not in sd:
                    # print(f"Process {syscal[3]}, PID {syscal[4]} tried IO on SD {syscal[7]} "
                    #                 f"but it was not conected to on line {line_num}")
                    missedSD += 1
                    continue

                    # raise Exception()
                obj = get_descriptor(syscal, sd)
                objectId = obj[0]
                objectType = "socket"
                arguments = obj[1] + obj[2]
                if objectId is None:
                    continue
                tail = syscal[8:]
                if type(arguments) != list:
                    arguments = [str(arguments)]
                if type(syscal[8:]) != list:
                    tail = [str(syscal[8:])]
                retArg = str(arguments + tail)
                if syscal[6] == "recv" or syscal[6] == "recvfrom" or syscal[6] == "recvmsg":
                    output_ADM.write(objectId + ", " + objectType + ", " + str(
                        process[(syscal[4], syscal[3])].thread[syscal[5]].id) + ", " +
                                     process[(syscal[4], syscal[3])].thread[syscal[5]].type + ", " + syscal[
                                         6] + ", " + str(syscal[3]) + ", " + syscal[1] + ", " + syscal[4] + "\n")
                if syscal[6] == "send" or syscal[6] == "sendto" or syscal[6] == "sendmsg":
                    output_ADM.write(str(process[(syscal[4], syscal[3])].thread[syscal[5]].id) + ", " +
                                     process[(syscal[4], syscal[3])].thread[
                                         syscal[5]].type + ", " + objectId + ", " +
                                     objectType + ", " + syscal[6] + ", " + syscal[3] + ", " + syscal[1] + ", " +
                                     syscal[4] + "\n")
            elif syscal[6] == "close":
                if syscal[7] not in fd and syscal[7] not in sd:
                    continue
                    # raise Exception(f"Process {syscal[3]}, PID {syscal[4]} tried to close on FD/SD {syscal[7]} "
                    #                 f"but it was never opened on line {line_num}")
                if syscal[7] in ["0", "1", "2"]:
                    continue
                key = (syscal[3], syscal[4])
                if (syscal[7] in fd and key not in fd[syscal[7]]) or (syscal[7] in sd and key not in sd[syscal[7]]):
                    continue
                else:
                    if syscal[7] in fd:
                        if key in fd[syscal[7]]:
                            del fd[syscal[7]][(syscal[3], syscal[4])]
                            if len(fd[syscal[7]]) == 0:
                                del fd[syscal[7]]
                    else:
                        if key in sd[syscal[7]]:
                            del sd[syscal[7]][(syscal[3], syscal[4])]
                            if len(sd[syscal[7]]) == 0:
                                del sd[syscal[7]]
            elif syscal[6] == "listen":
                continue
            elif syscal[6] == "fstat" or syscal[6] == "ftruncate" or syscal[6] == "stat":
                continue
            elif syscal[6] == "read" or syscal[6] == "write" or syscal[6] == "pwrite" or syscal[6] == "writev" or \
                    syscal[6] == "pwritev":
                if syscal[7] not in fd:
                    # print(f"Process {syscal[3]}, PID {syscal[4]} tried IO on FD {syscal[7]} "
                    #                  f"but it was not opened on line {line_num}")
                    missedFD += 1
                    continue
                    #raise Exception ()
                if syscal[7] in ["0", "1", "2"]:
                    obj = fd[syscal[7]]
                else:
                    obj = get_descriptor(syscal, fd)
                objectId = obj[0]
                if objectId is None:
                    continue
                objectType = "file"
                arguments = obj[1]
                tail = syscal[8:]
                if type(arguments) != list:
                    arguments = [str(arguments)]
                if type(syscal[8:]) != list:
                    tail = [str(syscal[8:])]
                retArg = str(arguments + tail)
                if syscal[6] == "read":
                    output_ADM.write(objectId + ", " + objectType + ", " + str(
                        process[(syscal[4], syscal[3])].thread[syscal[5]].id) + ", " +
                                     process[(syscal[4], syscal[3])].thread[syscal[5]].type + ", " + syscal[
                                         6] + ", " + str(syscal[3]) + ", " + syscal[1] + ", " + syscal[4] + "\n")
                elif syscal[6] == "write" or syscal[6] == "pwrite" or syscal[6] == "writev" or syscal[6] == "pwritev":
                    output_ADM.write(str(process[(syscal[4], syscal[3])].thread[syscal[5]].id) + ", " +
                                     process[(syscal[4], syscal[3])].thread[
                                         syscal[5]].type + ", " + objectId + ", " +
                                     objectType + ", " + syscal[6] + ", " + syscal[3] + ", " + syscal[1] + ", " +
                                     syscal[4] + "\n")
            elif syscal[6] == "chmod" or syscal[6] == "chown":
                output_ADM.write(str(process[(syscal[4], syscal[3])].thread[syscal[5]].id) + ", " +
                                 process[(syscal[4], syscal[3])].thread[syscal[5]].type + ", " + str(
                    syscal[7]) + ", file" + ", " + syscal[6] + ", " + str(syscal[3]) + ", " + syscal[1] + ", " +
                                 syscal[4] + "\n")
            elif syscal[6] == "execl" or syscal[6] == "execv" or syscal[6] == "execle" or syscal[6] == "execve" or \
                    syscal[6] == "execlp" or syscal[6] == "execvp":
                if syscal[4] not in execQueue:
                    execQueue[syscal[4]] = []
                sysArgs = ' '.join(syscal[8:]).replace('\"', '').replace(',', ' ').replace("]", "];")[:-1]
                sysArgs = f'[{sysArgs}]'
                execQueue[syscal[4]].append((process[(syscal[4], syscal[3])].thread[syscal[5]].id, syscal[7],
                                             syscal[1], syscal[3], sysArgs))
        print((f"Missed {missedFD} FD and {missedSD} SD for file {graphId}"))
        input.close()
        output_ADM.close()
        process_meta.close()
        file_meta.close()
