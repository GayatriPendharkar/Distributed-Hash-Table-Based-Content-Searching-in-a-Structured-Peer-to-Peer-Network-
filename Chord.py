import socket, argparse, thread, sys, hashlib, collections,random,time
import numpy as np

def NodeServer():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((IP, PORT))
    s.listen(20)
    while True:
        connection, addr = s.accept()
        message = connection.recv(4096)
        logfile.write(message+' request received at '+time.ctime()+' from '+str(addr)+'\n')
        if message.split(' ')[1] == 'UPFIN':
            if message.split(' ')[2] == '0':
                if message.split(' ')[5] in HashedPeerIDs:
                    pass
                else:
                    HashedPeerIDs[message.split(' ')[5]] = message.split(' ')[3]+' '+message.split(' ')[4]
                    UpdateFT(message)
            elif message.split(' ')[2] == '1':
                if message.split(' ')[5] in HashedPeerIDs:
                    del HashedPeerIDs[message.split(' ')[5]]
                    FillFT(HashedPeerIDs)

def hash_function(value):
    h = hashlib.sha1()
    h.update(value)
    val = h.hexdigest()[:m]
    hashed_key = int(val,16)
    return hashed_key

def NodeClient(host,Port,msg):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    Port = int(Port)
    s.connect((host,Port))
    s.settimeout(5)
    #print 'connected to BS'
    s.send(msg)
    try:
        reply = s.recv(1024)
    except socket.timeout:
        reply = 'Connection failed, ERROR 9 NODE is busy or non existent'
    s.close()
    return reply

def Gencommand(command):

    if command == "UPFIN 0":
        length = len('UPFIN')+len('0')+len(IP)+len(str(PORT))+len(str(node_ID))+4
        message = str(length).zfill(4)+' '+'UPFIN'+' '+'0'+' '+IP+' '+str(PORT)+' '+str(node_ID)
    elif command == "REGISTER":
        length = len('REG')+len(IP)+len(str(PORT))+len(username)+4
        message = str(length).zfill(4)+' '+'REG'+' '+IP+' '+str(PORT)+' '+username
    elif command == "DELETEIP":
        length = len('DEL')+len('IPADDRESS')+len(IP)+len(str(PORT))+len(username)+4
        message = str(length).zfill(4)+' '+'DEL IPADDRESS'+' '+IP+' '+str(PORT)+' '+username
    elif command == "DELETE UNAME":
        length = len('DEL')+len('UNAME')+len(username)+4
        message = str(length).zfill(4)+' '+'DEL UNAME'+' '+username
    elif command == "GET KEY":
        length = len('GETKY')+len(str(node_ID))+4
        message = str(length).zfill(4)+' '+'GETKY'+' '+str(node_ID)
    elif command == "GETIPLIST":
        length = len('GET IPLIST')+len(username)+4
        message = str(length).zfill(4)+' GET IPLIST '+username

    return message

def FillFT(peers):
    i = 1
    sorted_peerids = sorted(peers)
    while i <= m:
        finger_positions.append((node_ID+2**(i-1))%(2**m))
        i += 1
    for j in range(len(finger_positions)):
        pointed_fingers.append(min(filter(lambda x: x>=finger_positions[i],sorted_peerids)))
        FingerTable[min(filter(lambda x: x>=finger_positions[i],sorted_peerids))]=peers[min(filter(lambda x: x>=finger_positions[i],sorted_peerids))]
    print FingerTable

def GenEntry(number): #to generate entries from resources for the node
    f = open('resources.txt','rb')
    res = f.readlines()
    i = 0
    while i<len(res):
        if res[i].startswith('#'):
            res.pop(i)
        else:
            i = i+1
    resources = random.sample(res,number)
    for i in range(len(resources)):
        resources[i]=resources[i].lower()
    return resources

def UpdateFT(msg):
    key = int(msg.split(' ')[5])
    nearest_finger = max(filter(lambda x: x<=key,finger_positions))
    if key < pointed_fingers[finger_positions.index(nearest_finger)]:
        del FingerTable[pointed_fingers[finger_positions.index(nearest_finger)]]
        FingerTable[key] = msg.split(' ')[3]+' '+msg.split(' ')[4]

if __name__=="__main__":
    '''parser = argparse.ArgumentParser()
    parser.add_argument('-b','--bootstrap_ip',help = 'Bootstap server IP address',required=True)
    parser.add_argument('-p','--portnumber',help = 'port number of node',required=True)
    parser.add_argument('-m', '--size', help= 'size of the network',required=True)
    parser.add_argument('-n','--bootstrap_port',help= 'Bootstrap port number',required=True)
    parser.add_argument('-a','--action',help= 'REG for register and DEL',required=True)
    args = vars(parser.parse_args())'''
    key_table = []
    finger_positions = []
    pointed_fingers = []
    files = []

    IP = socket.gethostbyname(socket.getfqdn())
    #PORT = abs(int(args['portnumber']))
    PORT = 18000
    #BootStrapIP = args['bootstrap_ip']
    BootStrapIP= '129.82.46.190'
    BootStrapPort= 30000
    #BootStrapPort = abs(int(args['bootstrap_port']))
    ipandport = IP+' '+str(PORT)
    username = 'GAYATRI'
    m = 16
    HashedPeerIDs = {}
    FingerTable = {}
    action = 'REG'
    logfilename = IP+str(PORT)+'.log'
    logfile = open(logfilename,'wb')

    if action == 'REG':
        if len(FingerTable) == 0:
            reg_message = Gencommand("REGISTER")
            reply = NodeClient(BootStrapIP,BootStrapPort,reg_message)
            node_ID = hash_function(ipandport)
            if int(reply.split(' ')[3])==9999:
                print 'Error in registering, try again'
                sys.exit()
            elif int(reply.split(' ')[3])==9998:
                print 'Already registered, unregister first'
                unregister = raw_input('Do you want to unregister? Y/N: ')
                if unregister == 'Y':
                    delip_message = Gencommand("DELETEIP")
                    request = NodeClient(BootStrapIP,BootStrapPort,delip_message)
                    print request
                    sys.exit()
                elif unregister=='N':
                    sys.exit()
                else:
                    print 'Invalid input, Please try again later'
                    sys.exit()
            elif 0<=int(reply.split(' ')[3])<9998:
                for i in range(int(reply.split(' ')[3])):
                    HashedPeerIDs[hash_function(reply.split(' ')[(2*(i+1))+2]+' '+reply.split(' ')[(2*(i+1))+3])] = reply.split(' ')[(2*(i+1))+2]+' '+reply.split(' ')[(2*(i+1))+3]
                FillFT(HashedPeerIDs)
            for i in range(len(FingerTable)):
                print NodeClient(FingerTable[FingerTable.keys()[i]].split(' ')[0],FingerTable.keys()[i].split(' ')[1],Gencommand('UPFIN 0'))
            num_entries = 8
            available_resourcelist = GenEntry(num_entries)
            available_resource_hash = []
            for i in range(len(available_resourcelist)):
                available_resource_hash.append(hash_function(available_resourcelist[i]))


