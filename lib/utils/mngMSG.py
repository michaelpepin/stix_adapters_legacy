
###
#
#   ### -----< Message Managment Functions >-----
#   sndMSG(),   return None
#   sendMail(), return None || status
#
###

# -----< Message Managment Functions >-----

import os
import sys
from datetime import datetime


def sndMSG(sData,sType=None,sSrc=None):
    """
    :param sData:
    :param sType:
    :param sSrc:
    :return: None
    """
    
    bDISPLAY_MSG = True
    if sType == None:
        sType = "INFO"
    
    if sSrc == None:
        sSrc = ''

    sDate = str(datetime.now())
    sMSG_Header = "|" + sDate + " |" + sType + " |" + sSrc + " |"

        
    if bDISPLAY_MSG:
        print sMSG_Header +  str(sData) 

    if sType == 'ERROR':
        #sendMail(sMSG_Header +  str(sData),sSub='ErrorMsg')
        print "send mail disabled"
    
    return None


def sendMail(sMsg,sSub='ErrorMsg'):
    sendmail_location = "/usr/sbin/sendmail" # sendmail location
    p = os.popen("%s -t" % sendmail_location, "w")
    p.write("From: %s\n" % "root@hailataxii.com")
    p.write("To: %s\n" % "michael.pepin@gmail.com")
    p.write("Subject: " + sSub + "\n")
    p.write("\n") # blank line separating headers from body
    p.write(sMsg)
    status = p.close()
    if status != 0:
           print "Sendmail exit status", status
           return(status)
    return(None)