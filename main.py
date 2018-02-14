#!/usr/bin/env python
#-*- coding: utf-8 -*-

'''
Created on 11 jan. 2017

@author: Cyril Freby
'''

"""The objective of this program is to provide a way for a distributed system to reach a
convergence of local databases without any particular synchronisation or consensus. To
reach such a convergence, we use the CRDT (Conflict-free Replicated Data Type) technology,
allowing each site to apply updates in any order and to still reach the same results.

In this program, we imagine an Snort-like Intrusion Detection System (IDS) distributed on various
sites. Each site uses a local databases containing Snort rules and monitores the network to detect
patterns and prevent intrusions.

When a new type of attack is detected, a node will create a new rule and append it to its database,
then transmit the update to the other nodes. Depending on the network conditions, updates may not be 
received in the same order on each site, and the objective here is to make sure that this doesn't prevent
the nodes from reaching a same order of rules, so that a same attack will be treated identically on
each site.

Each update follows this structure: *port* *position* *rule*
where port is used as an identifier to solve conflicts, position is the position of the rule in the
database of the sender (should be at the end of the list) and rule is the Snort-like rule.
If two rules are inserted at the same position, the port is used as an identifier of the sending node
so that a priority can be attributed between the rules.
"""

import crdtSnort
import snortRule
import sys
import re # regular expressions
from threading import Thread, Lock
import socket
import time
import random

""" THREADING FUNCTIONS """

lock = Lock() # If two threads need to access the same object

class WaitForConnection(Thread):
    """ This thread opens a socket waiting for a connection from another node.
        Once a connection request is received, data of an update is analyzed and added to the output file."""

    def __init__(self):
        Thread.__init__(self)

    def run(self):
        global myAddress
        global myPort
        global myCrdt

        # UDP Connection
        mainConnection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        mainConnection.bind((myAddress, myPort))
                
        while True:
            message, remoteAddress = mainConnection.recvfrom(1024) #remoteAddress unused for now     
            message = message.decode() # "message" contains port, position and snort rule
            """message = *port* *position* *rule*"""
            # Retrieving node port (id used for disambiguation)
            index = 0
            remotePort = ""
            while(message[index]!=" "):
                remotePort+=message[index]
                index += 1
            remotePort = int(remotePort)
            message = message[(index+1):]
            
            # Retrieving wanted position
            index = 0
            position = ""
            while(message[index]!=" "):
                position+=message[index]
                index += 1
            position = int(position)
            message = message[(index+1):]
            
            rule = snortRule.SnortRule()
            rule.strToRule(message)
            with lock:
                myCrdt.insert(rule, remotePort, position)
                myCrdt.displaySorted()
                myCrdt.listOrdering()

class NewValue(Thread):
    """This thread will randomly create a new rule and append it to the database if it was not added yet"""

    def __init__(self):
        Thread.__init__(self)

    def run(self):
        """In my simulation, each nodes randomly picks n values, appends it to its database and sends it 
        to the other nodes. The program then freezes to show the convergence of the first rules and the
        divergence caused by the most recent updates."""
        global myCrdt
        global myPort
        global addressList
        global portList
        pickedValues = 0
        
        
        """ List of random parameters for the snort rules"""
        snortType = ["alert", "log"]
        snortProtocole = ["tcp", "udp", "ip", "icmp", "any"]
        snortAddress = ["127.0.0.1", "any", "192.168.0.0/16", "137.142.44.101"]
        snortPort = ["any", "80", "1024-", "3000-3010", "0-1024"]
        snortMsg = ["logged", "connexion", "message", "test", "error", ""]
        snortContent = ["virus", "exe", "alert", "malware", "free", "application", ""]
        
        while(pickedValues < 4):
            """ Random creation of a snort rule"""
            srcAddress = random.choice(snortAddress)
            destAddress = random.choice(snortAddress)
            # if source and destination need to be different:
            while(destAddress == srcAddress):
                destAddress = random.choice(snortAddress)
            rule = snortRule.SnortRule(random.choice(snortType), random.choice(snortProtocole),
                                       srcAddress, random.choice(snortPort),
                                       destAddress, random.choice(snortPort),
                                       random.choice(snortMsg), random.choice(snortContent))
            
            position = myCrdt.getLength() # rules appened to the list
            with lock:
                isNew = myCrdt.insert(rule, myPort, position) # checks if rule already exists
                myCrdt.displaySorted()
                myCrdt.listOrdering()
            if(isNew):
                # Propagation of the update
                connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                index = 0
                message = str(myPort) + " " + str(position) + " " + rule.showRule()
                message = message.encode()
                """To simulate network delays, we randomize the propagation of the updates so that each nodes receives them in a
                different order. To achieve this, we randomly select destination nodes and we pause the thread between each transmission."""
                indexList = []
                destinations = len(addressList)
                while(destinations>0):
                    destinations -= 1
                    indexList.append(destinations)
                while(index<len(addressList)):
                    random_int = random.randint(0,len(indexList)-1) # An index is randomly picked
                    connection.sendto(message, (addressList[indexList[random_int]], portList[indexList[random_int]])) # Message sent to random destination
                    del indexList[random_int] # Chosen index is taken out so we can't send message twice to same destination
                    index += 1
                    # Random sleep of 0 to 2 seconds (average 1 sec)
                    sleepTime = 2*random.random()
                    time.sleep(sleepTime)

            pickedValues += 1
            

""" CHECKING ARGUMENTS """

addressRegex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"

if(len(sys.argv)<3):
    print("Not enough arguments.")
    print("python main.py address port")
    sys.exit(0)

myAddress = sys.argv[1]
if not (re.match(addressRegex, myAddress) or myAddress=="localhost"):
    print("Address should be \"localhost\" or standard IPv4 format (1-255.1-255.1-255.1-255)")
    sys.exit(0)
if(myAddress == "127.0.0.1"):
    myAddress = "localhost" # might reverse it later
try:
    myPort = int(sys.argv[2])
except ValueError:
    print("port should be an integer")
    sys.exit(0)

myCrdt = crdtSnort.CrdtSnort()
addressList = []
portList = []
running = True

""" READING INPUT FILE """

with open("nodelist.txt", "r") as inputFile:
    for line in inputFile:
        (address, port) = line.split(" ")
        addressList.append(address)
        portList.append(int(port))

# Now, to detect our own address and port in the list:
index = 0
while(index<len(addressList)):
    if(myAddress == addressList[index] and myPort == portList[index]):
        del(addressList[index])
        del(portList[index])
        break
    index += 1
try:
    updateFromRemote = WaitForConnection()
    localProcess = NewValue()
    
    updateFromRemote.daemon=True #Mandatory for the threads to stop when the main program is over
    localProcess.daemon=True
    
    updateFromRemote.start()
    time.sleep(5) #This will let time for other nodes to start
    localProcess.start()
    while True: #Program will stop when an interruption is received
        pass
except(KeyboardInterrupt, SystemExit):
    print("Received Keyboard Interrupt, quitting program")
    with lock:
        myCrdt.outputToFile((str(myPort) + " output.txt"), (str(myPort) + " outputSorted.txt"))
    sys.exit()