#!/usr/bin/env python
#-*- coding: utf-8 -*-

'''
Created on 11 jan. 2017

@author: Cyril Freby
'''

import os
   
class CrdtSnort:
    """This class will implement crdt objects working on Snort-like rules."""
    
    def __init__(self):
        self.list = [] # the original list, where numbers are sorted by time of addition
        self.sortedList = [] # the sorted list, allowing easier browsing and convergence test
                
    def insert(self, rule, port, position):
        """Inserts a rule in the list if it was not present before."""
        absent = True
        for i in self.list:
            if i.showRule() == rule.showRule():
                absent = False
        if absent == True:
            self.list.append(rule)
            self.sortedList.insert(position,[rule,port, position])
        return absent
            
    def listOrdering(self):
        """Sorts the database. When a conflict is detected (two rules with same position),
        the node id is used for disambiguation. With this convergence algorithm, updates are
        commutative and every node reaches the same order of rules."""
        index = 0
        while( index < len(self.sortedList)-1):
            if(self.sortedList[index][2] > self.sortedList[index+1][2]): # positions in wrong order
                self.sortedList[index], self.sortedList[index+1] = self.sortedList[index+1], self.sortedList[index] # switch
            if(self.sortedList[index][2] == self.sortedList[index+1][2]): # Position conflict
                if(self.sortedList[index][1] <= self.sortedList[index+1][1]): # Already ordered by id
                    self.sortedList[index+1][2] += 1 # position altered for second rule
                else:
                    self.sortedList[index][2] += 1
                    self.sortedList[index], self.sortedList[index+1] = self.sortedList[index+1], self.sortedList[index] # switch
            index += 1
        
    
    def display(self):
        """Prints the list ordered by time of addition."""
        os.system('cls')
        index = 0
        for i in self.list:
            print(str(index) + " " + i.showRule())
            index += 1
            
    def displaySorted(self):
        """Prints the list sorted by position and node id."""
        os.system('cls')
        for i in self.sortedList:
            print(str(i[2]) + ": " + i[0].showRule())

    def outputToFile(self, file, fileSorted):
        """Sends the lists to given output files."""
        output = open(file, 'w')
        for i in self.list:
            output.write(i.showRule() + "\n")
        output.close()
        outputSorted = open(fileSorted, 'w')
        for i in self.sortedList:
            outputSorted.write(i[0].showRule() + "\n")
        outputSorted.close()
        
    def getLength(self):
        """Returns the amount of rules in the list. Usually used to know
        where to insert a new rule in the database."""
        return len(self.list)
    