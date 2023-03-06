# good reference:
# https://github.com/jallen89/theia-cdm-samples
import json
import pickle
import logging
import rglob
import multiprocessing as mp
from os import listdir
from os.path import isfile, join
from itertools import islice
import pandas as pd
import redis
import sys
import os
from attackNodes import attackNodes 

import redisdl

import sys
list_of_arguments = sys.argv
inputDir = list_of_arguments[1]
outputDir = list_of_arguments[2]


db = None
db0 = redis.Redis(db=8)


def runRocks(id):
    return


def runRedis(id):
    db = redis.Redis(db=id)
    db.flushdb()
    return db


def startLogging(filename):
    LOG_FILENAME = filename
    logging.basicConfig(filename=LOG_FILENAME, filemode='w', level=logging.DEBUG)


def getFileList(mypath):
    onlydirfiles = [join(mypath, f) for f in listdir(mypath) if isfile(join(mypath, f))]
    onlyfiles = [f for f in listdir(mypath) if isfile(join(mypath, f))]
    return onlyfiles, onlydirfiles




from datetime import datetime


def readInFile(filename):
    with open(filename) as json_file:
        data = json.load(json_file)
    return data


def prependBrackets(filename, filename2):
    a_file = open(filename, "r")
    logging.debug("opened file to append brackets")
    list_of_lists = []
    for line in a_file:
        stripped_line = line.strip()
        list_of_lists.append(stripped_line)
    a_file.close()
    logging.debug("stripped the file to be formatted correctly")
    with open(filename2, 'w') as f:
        f.write("[\n")
        for item in list_of_lists[:-1]:
            f.write("%s,\n" % item)
        f.write("%s\n]" % list_of_lists[-1])
    logging.debug("append brackets to file")


def event(edge):
    if edge['type'] == 'EVENT_BOOT':
        return 0
    else:
        ty = edge['type'].strip()
        edgeUUID = edge.get("uuid", None)
        if ty == "EVENT_CLONE":
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            return [src, dest, 'clone', timestamp, edgeUUID]
        elif ty == "EVENT_UNIT":
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            return [src, dest, 'clone', timestamp, edgeUUID]
        elif ty == "EVENT_EXECUTE":
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            return [src, dest, 'execve', timestamp, edgeUUID]
        elif ty == 'EVENT_CHANGE_PRINCIPAL':
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            return 0
        elif ty == 'EVENT_MMAP': #and edge['name']['string'] == 'mmap':
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            return 0
        elif ty == 'EVENT_MMAP': #and edge['name']['string'] == 'munmap':
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            return 0
        elif ty == 'EVENT_MPROTECT':
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            return 0
        elif ty == 'EVENT_OPEN':
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            return 0
        elif ty == 'EVENT_UNLINK':
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            return 0
        elif ty == 'EVENT_READ' or ty == 'EVENT_READ_SOCKET_PARAMS':
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            return [dest, src, 'read', timestamp, edgeUUID]
        elif ty == 'EVENT_WRITE' or ty == 'EVENT_WRITE_SOCKET_PARAMS':
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            return [src, dest, 'write', timestamp, edgeUUID]
        elif ty == 'EVENT_CREATE_OBJECT':
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            return 0
        elif ty == 'EVENT_ACCEPT':
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            return 0
        if ty == 'EVENT_CONNECT':
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            return 0
        elif ty == 'EVENT_SEND':
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            return [src, dest, 'send', timestamp, edgeUUID]
        elif ty == 'EVENT_SENDTO':
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            return [src, dest, 'send', timestamp, edgeUUID]
        elif ty == 'EVENT_SENDMSG':
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            return [src, dest, 'send', timestamp, edgeUUID]
        elif ty == 'EVENT_RECV':
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            return [dest, src, 'recv', timestamp, edgeUUID]
        elif ty == 'EVENT_RECVFROM':
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            return [dest, src, 'recv', timestamp, edgeUUID]
        elif ty == 'EVENT_RECVMSG':
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            return [dest,src, 'recv', timestamp, edgeUUID]
        elif ty == 'EVENT_FCNTL':
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            return 0
        elif ty == 'EVENT_MOUNT':
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            return 0
        elif ty == 'EVENT_SHM':
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            return 0
        elif ty == 'EVENT_MODIFY_FILE_ATTRIBUTES':
            src = edge.get('subject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            dest = edge.get('predicateObject', {}).get('com.bbn.tc.schema.avro.cdm18.UUID', None)
            timestamp = edge.get('timestampNanos', None)
            name = edge.get('t', {}).get('string', 'CHOWN: UNKNOWN')
            return 0
        else:
            try:
                logging.debug(
                "Found Event Type: \'" + ty + "\', and name: \'" + edge['name']['string'] + "\'; both do not belong")
            except:
                logging.debug("Found Event Type: \'" + ty)
def subject(edge):
    try:
        prop = edge['properties']['map']['name']
    except:
        prop = 'NoProcName'
    return prop

def objFile(edge):
    try:
        properties = edge['baseObject']['properties']['map']['path']
    except:
        properties = 'NoFileName'
    return properties

def objMem(edge):
    memAdi = edge.get('memoryAddress', 'NoMemAdi')
    return memAdi

def objNet(edge):
    remoteAdi = edge.get('remoteAddress', 'NoNetAdi')
    return remoteAdi

def writeToFile(jsonObjectList, fileName3):
    with open(fileName3, 'wb') as filehandle:
        pickle.dump(jsonObjectList, filehandle)

def readFromFile(fileName3):
    with open(fileName3, 'rb') as filehandle:
        # read the data as binary data stream
        jsonObjectList = pickle.load(filehandle)
    return jsonObjectList

def lineType(ty, eventJson):
    uuid = eventJson.get('uuid', None)
    if ty == "Event":
        return False, None, None, None
    elif ty == "Subject":
        return True, subject(eventJson), uuid, 'process'
    elif ty == "FileObject":
        return True, objFile(eventJson), uuid, 'file'
    elif ty == "NetFlowObject":
        return True, objNet(eventJson), uuid, 'file'
    elif ty == "MemoryObject":
        return True, objMem(eventJson), uuid, 'file'
    else:
        return False, None, None, None

def lineType2(ty, eventJson):
    uuid = eventJson.get('uuid', None)
    if ty == "Event":
        edge = event(eventJson)
        if edge:
            return False, edge, None
        else:
            return False, None, None
    elif ty == "Subject":
        return True, None, uuid
    elif ty == "FileObject":
        return True, None, uuid
    elif ty == "NetFlowObject":
        return True, None, uuid
    elif ty == "MemoryObject":
        return True, None, uuid
    else:
        return True, None, None

def extractNodes(jsonObjectsList, base, graphFile, graphID, rocks):
    file1 = open(graphFile, "a")
    count = 0
    for jsonObj in jsonObjectsList:
        jsonObj = jsonObj[0]
        if count + 1 % 1000 == 0:
            logging.debug("finished pre-processing:" + str(base + count) + "json objects")
        datum = str(next(iter(jsonObj)))
        ty = datum.split('.')[-1]
        store, name, uuid = lineType2(ty, jsonObj[datum])
        if store:
            if uuid != None:
                if db.get(uuid) != None:
                    continue
                countx = db.get(graphID)
                uuid = bytes(str(uuid), 'utf-8')
                if rocks:
                    db.put(uuid, countx)
                else:
                    db.set(uuid, countx)
                countx = int(countx.decode("utf-8"))
                countx += 1
                countx = bytes(str(countx), 'utf-8')
                if rocks:
                    db.put(graphID, countx)
                else:
                    db.set(graphID, countx)
        else:
            if name != None:
                file1.write(str(name))
                file1.write('\n')
        count += 1
    file1.close()

def extractName(jsonObjectsList, rocks):
    for jsonObj in jsonObjectsList:
        jsonObj = jsonObj[0]
        datum = str(next(iter(jsonObj)))
        ty = datum.split('.')[-1]
        store, name, uuid, typ = lineType(ty, jsonObj[datum])
        if store:
            if uuid != None:
                if db0.get(uuid) != None:
                    continue
                uuid = bytes(str(uuid), 'utf-8')
                val = f'{name}~!{typ}'
                val = bytes(str(val), 'utf-8')
                if rocks:
                    db0.put(uuid, val)
                else:
                    db0.set(uuid, val)

def preProcessGraph(filename2, filename3, graphID, N, rocks):
    chunks = pd.read_json(filename2, lines=True, chunksize=N)
    logging.debug("read in the json file")
    graphIDkey = 'max' + str(graphID)
    graphIDkey = bytes(str(graphIDkey), 'utf-8')
    if rocks:
        db.put(graphIDkey, b"0")
        logging.debug("read in the json file: " + str(graphIDkey))
    else:
        db.set(graphIDkey, b"0")
        logging.debug("max key set: " + str(graphIDkey))
    count = 0
    for chunk in chunks:
        graph = chunk.values.tolist()
        extractNodes(graph, count, filename3, graphIDkey, rocks)
        count += N

def fillNames (filename2, rocks, N):
    chunks = pd.read_json(filename2, lines=True, chunksize=N)
    for chunk in chunks:
        graph = chunk.values.tolist()
        extractName(graph, rocks)

def generateAttackNodes(fileName, rocks):
    f = open(fileName, 'w')
    for uniUUID in attackNodes:
        vals = [None, None]
        uniUUIDx = bytes(str(uniUUID), 'utf-8')
        dbVal2 = db0.get(uniUUIDx)
        if dbVal2 != None:
            val[0] = (dbVal2).decode("utf-8")
        dbVal = db.get(uniUUIDx)
        if dbVal != None:
            val[1] = (dbVal).decode("utf-8")
        f.write(f"{vals}\n")
    f.close()
    
fAttackID = []
def formatAttackID():
    global fAttackID
    for i in range(len(attackNodes)):
        el = attackNodes[i].upper()
        uniUUID = f"{el[:8]}-{el[8:12]}-{el[12:16]}-{el[16:20]}-{el[20:]}"
        fAttackID.append(uniUUID)

attackNodesNames = []
def writeAttackNodes(fileName):
    f = open(fileName, 'w')
    for uniUUID in attackNodesNames:
        f.write(f"{uniUUID}\n")
    f.close()

def formatGraph(df, filename2, graphID, rocks):
    df_unique_src = df.src.unique().tolist()
    df_unique_dest = df.dest.unique().tolist()
    uniqueUUIDs = set(df_unique_dest + df_unique_src)
    malNode = False
    flag = 1
    global attackNodesNames
    for uniUUID in uniqueUUIDs:
        if str(uniUUID) in fAttackID:
            malNode = True
        uniUUIDx = bytes(str(uniUUID), 'utf-8')
        val = [None, None]
        dbVal2 = db0.get(uniUUIDx)
        if dbVal2 != None:
            val[0] = (dbVal2).decode("utf-8")
        else:
            val[0] = 'None~!file'
        dbVal = db.get(uniUUIDx)
        if dbVal != None:
            val[1] = (dbVal).decode("utf-8")
        else:
            graphIDkey = 'max' + str(graphID)
            graphIDkey = bytes(str(graphIDkey), 'utf-8')
            # going to assume for now, missing UUID is a file
            countx = db.get(graphIDkey).decode("utf-8")
            val[1] = int(countx)
            uuid = bytes(str(uniUUID), 'utf-8')
            tempV = bytes(str(val[1]), 'utf-8')
            if rocks:
                db.put(uuid, tempV)
            else:
                db.set(uuid, tempV)
            countx = int(countx)
            countx += 1
            countx = bytes(str(countx), 'utf-8')
            if rocks:
                db.put(graphIDkey, countx)
            else:
                db.set(graphIDkey, countx)
        # print(val)
        val = str(tuple(val))
        if malNode:
            if flag:
                flag = 0
            attackNodesNames.append((val, filename2))
        df = df.replace(uniUUID, val)
    df_list = df.values.tolist()
    df_list_new = []
    for indexFlow in range(len(df_list)):
        row = df_list[indexFlow]
        # print(row)
        src, stype = eval(row[0])
        dest, dtype = eval(row[1])
        if type(dtype) == str and not dtype.isnumeric():
            print(dtype)
            raise Exception("dtype is off")

        src = src.split('~!')
        src, srcType = src
        dest = dest.split('~!')
        dest, destType = dest
        if type(src) == str and src.isnumeric():
            continue
        if type(dest) == str and dest.isnumeric():
            continue
        if src == 'None' or dest == 'None':
            continue
        if src == 'NA' or dest == 'NA':
            continue
        if srcType == 'process':
            label = src.split('/')[-1]
        elif destType == 'process':
            label = dest.split('/')[-1]
        else:
            logging.debug("there is a file on file happening")
            continue
        src = f'{src}~!{stype}'
        dest = f'{dest}~!{dtype}'
        df_list_new.append([src, srcType, dest, destType, row[2], label, row[3], row[4]])
    try:
        df = pd.DataFrame(df_list_new, columns=['src', 'srcType', 'dest', 'destType', 'syscal', 'label', 'retTime', 'uuid'])
        df.to_csv(filename2, header=False, index=False, sep=',', mode='a')
    except:
        flag = 1


def makeStreamSpotFormat(filename, filename2, graphID, N, rocks):
    with open(filename) as f:
        while True:
            next_n_lines = list(islice(f, N))
            if not next_n_lines:
                break
            i = []
            for i in range(len(next_n_lines)):
                next_n_lines[i] = eval(next_n_lines[i])
            df = pd.DataFrame(next_n_lines, columns=['src', 'dest', 'syscal', 'rettime', 'UUID'])
            formatGraph(df, filename2, graphID, rocks)
    f.close()

def main(params):
    filename1, filename2, filename3, filename4, graphID, N, rocks = params
    print(filename1, filename2, filename3, filename4)
    cleanFiles([filename2, filename3, filename4])
    print('starting parsing')
    startLogging(filename4)
    logging.debug("start of the program!")
    preProcessGraph(filename1, filename2, graphID, N, rocks)
    logging.debug("finished parsing")
    print("finished parsing")
    logging.debug("preprocess complete, converting to Streamspot Format")
    logging.debug("formatting graph")
    print("formatting graph")
    makeStreamSpotFormat(filename2, filename3, graphID, N, rocks)
    logging.debug("done formatting")
    print("done formatting")

def cleanFiles(ls):
    for filename in ls:
        file = open(filename, "w")
        file.close()

def main3(dir, dir2):
    print("starting run")
    global db
    rocks = False
    count = 0
    files = rglob.rglob(dir, "*")
    for file in files:
       fillNames(file, rocks, 100000)

    dbCount = 9
    files = rglob.rglob(dir, "*")
    for file in files:
        if rocks:
            db = runRocks(dbCount)
        else:
            db = runRedis(dbCount)
        sfile = file.split('/')[-1].split('.')
        if len(sfile) == 2: sfile.append(0)
        if int(sfile[-1]) not in filesToParse:
            continue
        saveDir = dir2 + '/' + str(sfile[0]) + '/'
        fFileName = '{}-{}.{}.{}'
        count += 1
        main((file, saveDir + fFileName.format(sfile[0], '2-pre', 'txt', sfile[2]),
                   saveDir + fFileName.format(sfile[0], '2-post', 'txt', sfile[2]),
                   saveDir + fFileName.format(sfile[0], '2-log', 'log', sfile[2]),
                   2,
                   100000,
                   rocks))
        if not rocks:
            with open(dir2+'/'+fFileName.format(sfile[0], 'redis', 'pkl', sfile[2]), 'w+') as f:
                redisdl.dump(f, db=dbCount)
                #dbCount += 1   

main3(inputDir, outputDir)
