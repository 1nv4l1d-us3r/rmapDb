#!/usr/bin/python3
import sys 
import socket
from pymongo.mongo_client import MongoClient
import random 
import threading
import re
import logging
import time
logging.getLogger("scapy").propagate=False
from warnings import filterwarnings
filterwarnings("ignore")
from scapy.all import *

class tryAgain(Exception):
    pass

class noTargets(Exception):
    pass



timeout=1
socket.setdefaulttimeout(timeout)

password='xyz'
uri = "xyz"  //  Add MongoDb Atlas Uri

# Create a new client and connect to the server
client = MongoClient(uri)
db=client['scanningDb']
collection=db['targets']

def connect(ttarget,tport):
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    result=False
    try:
        s.connect((ttarget,int(tport)))
    except (ConnectionRefusedError,socket.timeout):
        pass
    except socket.gaierror:
        return False
    except ConnectionResetError:
        result=True
    else:
        result=True
    finally:
        s.close()
    return result



def syn(ttarget,tport):
    result=False
    x=False
    try:
        x=sr1(IP(dst=ttarget)/TCP(dport=int(tport),flags='S'),verbose=False,timeout=timeout)
    except PermissionError:
        print("SYN scan Not permitted without root permission. run as sudo ")
        exit()
    except :
        result=False
    if(x):
        result=True
    return result



if '-s' in sys.argv:
    scan=syn
else:
    scan=connect

verbose=False
if '-v' in sys.argv:
    verbose=True

noOfThreads=5
if '-t' in sys.argv:
    try:
        noOfThreads=sys.argv[sys.argv.index('-t')+1]
    except:
            pass


if '-i' in sys.argv:
    try:
        ips=set(open('targets.txt','r').read().split())
        ports=set(open('ports.txt','r').read().split())
        targets=[x.strip() for x in ips]
        ports=[ p.strip() for p in ports]
    except:
        print('Error reading targets.txt or ports.txt from current directory')
    else:
        data=[ {'ip':ip,'ports':ports,'open':[]} for ip in targets]
        collection.insert_many(data)
        print('Enteries inserted')
    exit()




def get_random_doc():
    pipeline=[
        {'$match':{'round_done':{'$ne':True},'ports':{'$ne':[]}}},
        {'$sample':{'size':1}}
    ]
    res=collection.aggregate(pipeline)
    try:
        doc=list(res)[0]
        ports=doc['ports']
    except:
        if(len(list(collection.find({'ports':{'$ne':[]}})))==0):
            raise noTargets
        else:
            collection.update_many({},{'$set':{'round_done':False}})
            raise tryAgain
    else:
        return doc['ip'],ports[random.randrange(len(ports))]

def mark_done(ip,port,open=False):
    
    if open:
        change={'$set':{'round_done':True},'$pull':{'ports':port},'$push':{'open':port}}
        
    else:
        change={'$set':{'round_done':True},'$pull':{'ports':port}}
    collection.update_many({'ip':ip},change)




def scan_random():
    try:
        ip,port=get_random_doc()
    except noTargets:
        global targestAvailable
        targestAvailable=False
        return
    except tryAgain:
        return
    else:

        portOpen=scan(ip,port)
        print(ip,':',port,"\t"*5,portOpen,end='\r')
        mark_done(ip,port,portOpen)


targestAvailable=True
while(targestAvailable):
    thread_pool=[]
    for _ in range(noOfThreads+1):
        thread=threading.Thread(target=scan_random)
        thread_pool.append(thread)
        thread.start()
        time.sleep(0.01)
    
    for thread in thread_pool:
        thread.join()
