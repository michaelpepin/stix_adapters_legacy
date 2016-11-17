
import sys
import datetime
import uuid
import traceback
import getpass
import pycurl
import cStringIO
#from datetime import datetime
#import xml.etree.ElementTree as ET

from lxml   import etree
from xml.parsers.expat import ExpatError
from random import randint

sys.path.insert(0, '../../')
from lib.utils.msg     import sndMSG

def main():

    conn_cred = {}
    conn_cred['taxiiURL'] = "http://172.16.167.241/STIX/taxii/taxii.wsgi"
    #conn_cred['taxiiURL'] = "http://adjunct.fsisac.com/STIX/taxii/taxii.wsgi"
    conn_cred['usrName']  = 'jdoe'
    conn_cred['usrPass']  = 'Mikky123'
    conn_cred['crtName']  = ''
    conn_cred['crtPass']  = ''
    
    connter(conn_cred,getFile_XML('equ_mod.xml'),bTAXIIWrp=True,sTrg=None)
    #Connector(conn_cred,getFile_XML('STIX_openbl.xml'),bTAXIIWrp=True,sTrg=None)

    return(0);
    
def connecter(conn_cred,stixData,bTAXIIWrp=True,sTrg=None):
    sFuncName = "connector.connecter()"
    sTxt = "Trying to send to TAXII API : " + conn_cred['taxiiURL']
    sndMSG(sTxt,'INFO',sFuncName);
    
    if bTAXIIWrp == True:
        stixData = addTAXIIWrapper(stixData);
    
    sHdr = genHeader_TAXII(stixData,isSSL=False)
    bFlag = _connecterTAXII(conn_cred,sHdr,stixData,sFileName,isSSL=False)

    if bFlag == True and not sTrg == None:
        import os
        sTxt = "Attemping to delete file: " + sTrg
        sndMSG(sTxt,'INFO',sFuncName);
        os.remove(sTrg)

    return(0);
    
def connecter_wQue(que, conn_cred,stixData,bTAXIIWrp=True,sTrg=None):
    import Queue
    sFuncName = "connector.connecter_wQue()"
    sTxt = "Trying to send to TAXII API : " + conn_cred['taxiiURL']
    sndMSG(sTxt,'INFO',sFuncName);
    
    #print "Attemping to delete file: " + str(sTrg)
    if bTAXIIWrp == True:
        stixData = addTAXIIWrapper(stixData);
    
    lstTmp = sTrg.split("/");
    sFileName = lstTmp[(len(lstTmp)-1)]
    sHdr = genHeader_TAXII(stixData,isSSL=False)
    bFlag = _connecterTAXII(conn_cred,sHdr,stixData,sFileName,isSSL=False)
    #que.put(connTAXII_api(conn_cred,sHdr,stixData,sFileName,isSSL=False));
    #s = que.get()
    #print s
    #if not sTrg == None:
    if bFlag == True and not sTrg == None:
        import os
        sendMSG("Attemping to delete file: " + sTrg)
        os.remove(sTrg)
    #sendMSG("NOTE Connector is temp diabled : ")
    return(0);

def _connecterTAXII(conn_cred,headers,xml,sFileName,isSSL=True ):
    buf = cStringIO.StringIO()
    
    conn = pycurl.Curl()
    conn.setopt(pycurl.VERBOSE, False)
    conn.setopt(pycurl.URL, conn_cred['taxiiURL'])
    conn.setopt(pycurl.USERPWD, conn_cred['usrName'] + ':' + conn_cred['usrPass'])
    conn.setopt(pycurl.HTTPHEADER, headers)
    conn.setopt(pycurl.POST, 1)
    conn.setopt(pycurl.TIMEOUT, 999999)
    conn.setopt(pycurl.WRITEFUNCTION, buf.write)
    conn.setopt(pycurl.POSTFIELDS, xml)
    
    if isSSL:
        conn.setopt(pycurl.SSLVERSION, 3)
        conn.setopt(pycurl.SSLCERT, conn_cred['crtName'])
        conn.setopt(pycurl.SSLKEYPASSWD, conn_cred['crtPass'])
        conn.setopt(pycurl.SSL_VERIFYPEER, 0)
        conn.setopt(pycurl.SSL_VERIFYHOST, 0)
    
    conn.perform()
    
    traceback.print_exc()
    sendMSG("----< " + sFileName + ">-----")
    sMsg = buf.getvalue()[:500] + "..."
    sendMSG(sMsg);
    if "FAILURE" in sMsg:
        bFlag = False
    elif "SUCCESS" in sMsg:
        bFlag = True
    else:
        bFlag = None;
        
    
    buf.close()

    return(bFlag);

def getFile_XML(sFile):
    objFile = open(sFile,"r")
    xml = objFile.read()
    objFile.close()
    return(xml);

def genHeader_TAXII(xml,isSSL=True):
    headers = []
    headers.append("Content-Type: application/xml")
    headers.append("Content-Length: " + str(len(xml)))
    headers.append("User-Agent: TAXII Client Application")
    headers.append("Accept: application/xml")
    
    headers.append("X-TAXII-Accept: urn:taxii.mitre.org:message:xml:1.0")
    headers.append("X-TAXII-Content-Type: urn:taxii.mitre.org:message:xml:1.0")
    if isSSL == True:
        headers.append("X-TAXII-Protocol:urn:taxii.mitre.org:protocol:https:1.0")
    else:
        headers.append("X-TAXII-Protocol:urn:taxii.mitre.org:protocol:http:1.0")
        
    #headers.append("X-TAXII-Accept: TAXII_1.0/TAXII_XML_BINDING_1.0")
    #headers.append("X-TAXII-Content-Type: TAXII_1.0/TAXII_XML_BINDING_1.0")
    #headers.append("X-TAXII-Protocol: TAXII_HTTPS_BINDING_1.0")
    
    return(headers)
    
def addTAXIIWrapper(xml):
    import random;
    # 1564343186463486
    
    if len(xml) < 2:
        return(None)
        
    msgID = str(random.randrange(100000000000000,999999999999999));
    sHdr = "<?xml version='1.0' encoding='UTF-8'?><taxii:Inbox_Message xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xmlns:taxii='http://taxii.mitre.org/messages/taxii_xml_binding-1' message_id='" + msgID + "'><taxii:Content_Block><taxii:Content_Binding>urn:stix.mitre.org:xml:1.0</taxii:Content_Binding><taxii:Content>";
    sFtr = "</taxii:Content></taxii:Content_Block></taxii:Inbox_Message>";
    

    xml = sHdr + '\n' + xml + '\n' + sFtr
    return(xml)
    
if __name__ == "__main__":
    main();

#eof

