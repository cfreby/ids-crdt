#!/usr/bin/env python
#-*- coding: utf-8 -*-

'''
Created on 17 janv. 2018

@author: Cyril Freby
'''

class SnortRule:
    """ This class implements pseudo-snort rules."""
    def __init__(self, ruleType="log", protocole="any", sourceIp="any", sourcePort="any", destIp="any", destPort="any", msg="", content=""):
        self.ruleType = ruleType
        self.protocole = protocole
        self.sourceIp = sourceIp
        self.sourcePort = sourcePort
        self.destIp = destIp
        self.destPort = destPort
        self.msg = msg
        self.content = content
                
    def showRule(self):
        """Convers the rule object into a string that can be sent to other nodes."""
        rule = self.ruleType + " " + self.protocole + " " +self.sourceIp + ":" + self.sourcePort + " -> " + self.destIp + ":" + self.destPort
        if(self.msg=="" and self.content==""):
            return rule
        rule += " ("
        if(self.msg!=""):
            rule += "msg=\"" + self.msg + "\";"
        if(self.content!=""):
            rule += "content=\"" + self.content + "\";"
        rule += ")"
        return(rule)
    
    def strToRule(self, rule):
        """ Turns a string (usually comming from another node) into a snort rule"""
        parameters = rule.split(" ")
        if(len(parameters)<5):
            print("Error : the snort rule is invalid")
            return(-1)
        self.ruleType = parameters[0]
        self.protocole = parameters[1]
        source = parameters[2]
        self.sourceIp, self.sourcePort = source.split(":")
        destination = parameters[4]
        self.destIp, self.destPort = destination.split(":")
        msg = ""
        content = ""
        if(len(parameters)>5):
            arguments = parameters[5].split(";")
            if("msg=" in arguments[0]):
                msg = arguments[0]
                msg = msg[6:][:-1]
                if(len(arguments)>2):
                    content = arguments[1]
                    content = content[9:][:-1]
            elif("content=" in arguments[0]):
                content = arguments[0]
                content = content[9:][:-1]    
        self.msg = msg
        self.content = content
