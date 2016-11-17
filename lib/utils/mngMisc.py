#!/usr/bin/env python

###
#
#   ### -----< Misc Functions >-----
#   isIPv4(),       return boolean      #Tests received String, check if is IPv4 format
#   isIPv6(),       return boolean      #Tests received String, check if is IPv6 format
#   isFQDN(),       return boolean      #Tests received String, check if is FQDN format
#   isTLD(),        return boolean      #Tests received String, check if is TLD format
#   isNumber(),     return boolean      #Tests received String, check if is Number
#
#   ### -----< Misc Classes >-----
#   
###

from mngMSG import sndMSG

### -----< Unitlity Functions >-----

def isIPv4(sData):
    sFuncName = 'isIPv4'
    import socket
    try:      
        socket.inet_pton(socket.AF_INET, sData)
        return(True)
    except socket.error:
        sTxt = "InValid_IPAddr " + sData
        #sndMSG(sTxt,"ERROR",sFuncName)
        return(False)
    return(False)

def isIPv6(sData):
    sFuncName = 'isIPv6'
    import socket
    try:
        socket.inet_pton(socket.AF_INET6, sData)
        return(True)
    except socket.error:
        sTxt = "InValid_IPAddr " + sData
        #sndMSG(sTxt,"ERROR",sFuncName)
        return(False)
    return(False)

def isFQDN(sData):
    #TODO: Needs test logic
    return(True)

def isTLD(sData):
    #TODO: Needs test logic
    return(True)

def isNumber(sData):
    try:
        float(sData)
        return True
    except ValueError:
        return False        
    
#EOF    
