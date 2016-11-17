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

### -----< Unitlity Functions >-----

def isIPv4(data):
    import socket
    try:      
        socket.inet_pton(socket.AF_INET, data)
        return True

    except socket.error as e:
        return False

def isIPv6(data):
    import socket
    try:
        socket.inet_pton(socket.AF_INET6, data)
        return True

    except socket.error:
        return False

def isFQDN(data):
    #TODO: Needs test logic
    return True

def isTLD(data):
    #TODO: Needs test logic
    return True

def isNumber(data):
    try:
        float(data)
        return True
    except ValueError:
        return False        
    
#EOF    
