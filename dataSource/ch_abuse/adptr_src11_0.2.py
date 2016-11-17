#!/usr/bin/env python

import os    
import sys
from datetime import datetime

sys.path.insert(0, '../../')
### Generally required for all Adpters
from lib.utils.mngMSG      import sndMSG
from lib.utils.mngSources  import clsDataSource
from lib.utils.mngFiles    import getFile_JSON2Dict
from lib.utils.mngRmtObjs  import getRmt_File
from lib.utils.mngFiles    import sndFile_Dict2JSON, sndFile
from lib.utils.mngDateTime import getUTCTime
from lib.conns.curlTAXII   import sndTAXII

from stix.utils                         import set_id_namespace as stix_set_id_namespace
from stix.indicator                     import Indicator
from stix.core                          import STIXPackage, STIXHeader
from stix.data_marking                  import Marking, MarkingSpecification
from stix.extensions.marking.tlp        import TLPMarkingStructure
from stix.extensions.marking.simple_marking import SimpleMarkingStructure
from stix.extensions.marking.terms_of_use_marking import TermsOfUseMarkingStructure

from cybox.utils                        import set_id_namespace as obs_set_id_namespace
from cybox.utils                        import Namespace

### Specifically requried for this Adpater
from lib.utils.mngFiles                 import trimFile_btwn
from lib.utils.cnvtFiles                import cnvt_XML2Dict
from lib.utils.mngMisc                  import isIPv4, isIPv6, isFQDN, isTLD

from stix.ttp                           import TTP, Behavior
from stix.ttp.behavior                  import MalwareInstance

from cybox.core.observable              import ObservableComposition, Observables, Observable
from cybox.objects.address_object       import Address
from cybox.objects.domain_name_object   import DomainName
from cybox.objects.uri_object           import URI
from cybox.objects.file_object          import File
from cybox.common                       import Hash



def main():
    sSOURCEID = 'src_11'

    ### Setup for running as Main and template for use of adptr function
    tmpJSON = getFile_JSON2Dict('../../data/openSourceList.json');
    tmpDict = None;
    
    for sKey in tmpJSON:
        if tmpJSON[sKey]['srcIndex'] == sSOURCEID:
            tmpDict = tmpJSON[sKey]
            
    
    ### Without a valide Source Meta data this function will exit
    if tmpDict == None:
        retrun(False);
    
    ### This infomation is only require if you wish upload this data
    ###     to a TAXII Server
    
    dstCreds = {
        "URI"    :"http://www.hailataxii.com/taxii-discovery-service",
        "usrName":"abuse.ch",
        "usrPass":"Z*.xQ^?rD7~5`$f",
        "crtName":"",
        "crtPass":""
    };        
    dstCreds = {
        "URI"    :"http://172.16.167.147/taxii-discovery-service",
        "usrName":"admin",
        "usrPass":"avalanche",
        "crtName":"",
        "crtPass":""
    }; 

    ### The adpter function requires clsDataSource object populated
    ###     with a minimum of data 
    srcData = clsDataSource(isDebugOn=True);
    srcData.from_dict(tmpDict);
    srcData.chnkSize = 500;  # This version does not make use of the chucking capability  
    srcData.dstCreds = dstCreds;
    srcData.filePath = os.path.dirname(os.path.abspath(__file__)) + '/'
    
    ### Extract(src2Dict) Transform(dict2STIX) Load(sndTAXII)
    dictObj  = adptr_src2Dict(srcData, True);
    if not dictObj == False:
        stixObj  = adptr_dict2STIX(srcData, dictObj);
        if not stixObj == False:
            taxiiMsg = sndTAXII(srcData.dstCreds,stixObj.to_xml(),True)
    
    return(0);
    
def adptr_src2Dict(srcData, isUpdateNewDataOnly):
    sNAMEFUNC = 'adptr_src2Dict()'
    sTxt = "Called... " 
    sndMSG(sTxt,'INFO',sNAMEFUNC)
    
    ### Input Check    
    if srcData == None:
        #TODO: Needs error msg: Missing srcData Object
        return(False)
        
    sName       = srcData.fileName
    locDataFile = 'db_' + srcData.fileName.split('.')[0] + '.json'

    ### fetch from Source location for newest version
    #srcData.getSrcData();   #TODO: This function in the clsDataSource is not completed
    # so this getRmt_File is used until class is completed
    
    if not getRmt_File(srcData.srcCreds,
                       srcData.filePath + 
                       srcData.fileName) == True:
       # if no source data is found, this script will exit
       return(False)



    dstData = getFile_JSON2Dict(locDataFile)
    if not dstData:
        dstData = {};

    newData = {}; 
    
    ### Here the code become specific (unique) this data source
    ###     in time I hope to refactor out as much unique as possible
    
    
    trimFile_btwn(srcData.filePath + srcData.fileName,
              '<?xml version="1.0" encoding="ISO-8859-1" ?>',
              '</rss>')

    srcDict = cnvt_XML2Dict(srcData.filePath + srcData.fileName);

    srcData.pkgTitle  = srcDict['rss']['channel']['title']
    srcData.pkgDscrpt = srcDict['rss']['channel']['description']
    srcData.pkgLink   = srcDict['rss']['channel']['link']

    for col in srcDict['rss']['channel']['item']:
        sKey = col['guid']
        
        sCol= col['title']
        sDateVF = sCol.split('(')[1]
        sDateVF = sDateVF[0:-1]
        dSrt = datetime.strptime(sDateVF, "%Y-%m-%d") 
        sDateVF = dSrt.strftime("%Y-%m-%dT%H:%M:%SZ")
       
        sCol= col['description']
        lstAttrib = sCol.split(',')
        sURI = lstAttrib[0][4:]

        dictAttrib = {
            "dateVF"  :cleanString(sDateVF),
            "URI"     :cleanString(sURI),
            "status"  :cleanString(lstAttrib[1].split(':')[1]),
            "version" :cleanString(lstAttrib[2].split(':')[1]),
            "hash"    :cleanString(lstAttrib[3].split(':')[1]),
            "title"   :cleanString(col['title']),
            "link"    :cleanString(col['link']),
            "dscrpt"  :cleanString(col['description']),
            "fileName":"",
            "ipAddr"  :"",
            "domain"  :""
            }
            
        if len(sURI) > 0:
            tmpList = sURI.split("/")
            if len(tmpList) > 1:
                idx = len(tmpList) - 1
                dictAttrib.update({"fileName":cleanString(tmpList[idx])})
                if tmpList[2][0:1].isdigit():
                    dictAttrib.update({"ipAddr":cleanString(tmpList[2])})
                else:
                    dictAttrib.update({"domain":cleanString(tmpList[2])})    
                    
        if sKey in dstData:
            dstData[sKey]['cnt'] += 1
            dstData[sKey]['dateDL'] = getUTCTime() 
            dstData[sKey]['status'] = dictAttrib['status']
                
            #TODO:Check If Exist Element's inactive status changed
            
        else:
            ### Add new Data to local Database
            dstData[sKey] = {'cnt':1,'dateDL':getUTCTime()}
            dstData[sKey]['attrib'] = dictAttrib
            
            ### Generate list of new data only for STIX output
            newData[sKey] = dstData[sKey]        

    sndFile_Dict2JSON(dstData,locDataFile); 
    
    if isUpdateNewDataOnly == False:
        newData = dstData
    
    if len(newData) > 0:
        sTxt = "Found " + str(len(newData)) + " new data elements";
        sndMSG(sTxt,'INFO',sNAMEFUNC);
        
    else:
        sTxt = "Found no new data";
        sndMSG(sTxt,'INFO',sNAMEFUNC);   
        newData = False;
    
    return(newData);
    
def adptr_dict2STIX(srcObj, data):
    sTxt = "Called... "
    sndMSG(sTxt,'INFO','adptr_dict2STIX()')
    stixObj = None
    
    ### Input Check
    if srcObj == None or data == None:
        #TODO: Needs error msg: Missing srcData Object
        return(False)

    ### Generate NameSpace id tags
    STIX_NAMESPACE = {"http://hailataxii.com" : "opensource"}
    OBS_NAMESPACE = Namespace("http://hailataxii.com", "opensource")
    stix_set_id_namespace(STIX_NAMESPACE)
    obs_set_id_namespace(OBS_NAMESPACE)
    
    ### Building STIX Wrapper
    stix_package = STIXPackage();
    objIndicator = Indicator();

    ### Bulid Object Data
    for sKey in data:
        objIndicator = Indicator();
        listOBS = []
        
        ### Parsing IP Address
        sAddr = data[sKey]['attrib']['ipAddr']
        if len(sAddr) > 0:
            objAddr = Address();
            objAddr.is_source = True
            objAddr.address_value = sAddr
            objAddr.address_value.condition = 'Equals'
            if isIPv4(sAddr):
                objAddr.category = 'ipv4-addr'
            elif isIPv6(sAddr):
                objAddr.category = 'ipv6-addr'
            else:
                continue;  
           
            obsAddr = Observable(objAddr)
            objAddr = None;
            obsAddr.sighting_count = 1
            obsAddr.title = 'IP: ' + sAddr
            sDscrpt = 'IPv4' + ': ' + sAddr + " | "
            sDscrpt += "isSource: True | "
            obsAddr.description = "<![CDATA[" + sDscrpt + "]]>"
            listOBS.append(obsAddr)
            obsAddr = None;
            objIndicator.add_indicator_type("IP Watchlist") 

        ### Parsing Domain
        sDomain = data[sKey]['attrib']['domain']
        if len(sDomain) > 0:
            objDomain = DomainName();
            objDomain.value = sDomain;
            objDomain.value.condition = 'Equals'
            if isFQDN(sDomain):
                objDomain.type = 'FQDN'
            elif isTLD(sDomain):
                objDomain.type = 'TLD'
            else:
                continue; 
                
            obsDomain = Observable(objDomain)   
            objDomain = None;
            obsDomain.sighting_count = 1
            obsDomain.title = 'Domain: ' + sDomain
            sDscrpt = 'Domain: ' + sDomain + " | "
            sDscrpt += "isFQDN: True | "
            obsDomain.description = "<![CDATA[" + sDscrpt + "]]>" 
            listOBS.append(obsDomain)
            obsDomain = None;
            objIndicator.add_indicator_type("Domain Watchlist")
            
        #Parser URI
        sURI = data[sKey]['attrib']['URI']
        if len(sURI) > 0:
            objURI = URI();
            objURI.value = sURI
            objURI.value.condition = 'Equals'
            objURI.type_ = URI.TYPE_URL
            obsURI = Observable(objURI)   
            objURI = None;
            obsURI.sighting_count = 1
            obsURI.title = 'URI: ' + sURI
            sDscrpt = 'URI: ' + sURI + " | "
            sDscrpt += "Type: URL | "
            obsURI.description = "<![CDATA[" + sDscrpt + "]]>" 
            listOBS.append(obsURI)
            obsURI = None;
            objIndicator.add_indicator_type("URL Watchlist")
            
        #Parser File Hash
        sHash = data[sKey]['attrib']['hash'];
        if len(sHash) > 0:  
            objFile = File()
            sFileName = data[sKey]['attrib']['fileName']
            if len(sFileName) > 0:
                objFile.file_name   = sFileName
                objFile.file_format = sFileName.split('.')[1]
                
            objFile.add_hash(Hash(sHash, exact=True))
            obsFile = Observable(objFile)   
            objFile = None;
            obsFile.sighting_count = 1
            obsFile.title = 'File: ' + sFileName
            sDscrpt = 'FileName: ' + sFileName + " | "
            sDscrpt += "FileHash: " + sHash + " | "
            obsFile.description = "<![CDATA[" + sDscrpt + "]]>" 
            listOBS.append(obsFile)
            obsFile = None;
            objIndicator.add_indicator_type("File Hash Watchlist")
        

        ### Add Generated observable to Indicator
        objIndicator.observables = listOBS  
        objIndicator.observable_composition_operator = 'OR'
                    
        #Parsing Producer
        sProducer = srcObj.Domain;
        if len(sProducer) > 0:
            objIndicator.set_producer_identity(sProducer);
        
        objIndicator.set_produced_time(data[sKey]['attrib']['dateVF']);
        objIndicator.set_received_time(data[sKey]['dateDL']);
        
        ### Old Title / Description Generator
        #objIndicator.title = data[sKey]['attrib']['title'];
        #objIndicator.description = "<![CDATA[" + data[sKey]['attrib']['dscrpt'] + "]]>";
        
        ### Generate Indicator Title based on availbe data
        sTitle = 'ZeuS Tracker (' + data[sKey]['attrib']['status'] + ')| ' + data[sKey]['attrib']['title']
        if len(sAddr) > 0:
            sAddLine = "This IP address has been identified as malicious"
        if len(sDomain) > 0:
            sAddLine = "This domain has been identified as malicious"
        if len(sAddLine) > 0:
            sTitle = sTitle + " | " + sAddLine
        if len(srcObj.Domain) > 0:
            sTitle = sTitle + " by " + srcObj.Domain
        else:
            sTitle = sTitle + "." 
        if len(sTitle) > 0:         
            objIndicator.title = sTitle;
        
        #Generate Indicator Description based on availbe data
        sDscrpt = ""
        if len(sAddr) > 0:
            sAddLine = "This IP address " + sAddr 
        if len(sDomain) > 0:
            sAddLine = "This domain " + sDomain
        if len(sAddr) > 0 and len(sDomain) > 0:
            sAddLine = "This domain " + sDomain + " (" + sAddr + ")"  
        if len(sAddLine) > 0:
            sDscrpt = sDscrpt + sAddLine

        sDscrpt = sDscrpt + " has been identified as malicious"        
        if len(srcObj.Domain) > 0:
            sDscrpt = sDscrpt + " by " + srcObj.Domain
        else:
            sDscrpt = sDscrpt + "." 
        sDscrpt = sDscrpt + ". For more detailed infomation about this indicator go to [CAUTION!!Read-URL-Before-Click] [" + data[sKey]['attrib']['link'] + "]."   
        
        if len(sDscrpt) > 0:        
            objIndicator.description = "<![CDATA[" + sDscrpt + "]]>";

        #Parse TTP
        objMalware = MalwareInstance()
        objMalware.add_name("ZeuS")
        objMalware.add_name("Zbot")
        objMalware.add_name("Zeus")
        objMalware.add_type("Remote Access Trojan")
        objMalware.short_description = "Zeus, ZeuS, or Zbot is Trojan horse computer malware effects Microsoft Windows operating system"
        objMalware.description = "Zeus, ZeuS, or Zbot is Trojan horse computer malware that runs on computers running under versions of the Microsoft Windows operating system. While it is capable of being used to carry out many malicious and criminal tasks, it is often used to steal banking information by man-in-the-browser keystroke logging and form grabbing. It is also used to install the CryptoLocker ransomware.[1] Zeus is spread mainly through drive-by downloads and phishing schemes. (2014(http://en.wikipedia.org/wiki/Zeus_%28Trojan_horse%29))"
        
        objTTP = TTP(title="ZeuS")
        objTTP.behavior = Behavior()
        objTTP.behavior.add_malware_instance(objMalware)
        objIndicator.add_indicated_ttp(objTTP)
        #objIndicator.add_indicated_ttp(TTP(idref=objTTP.id_))   
        #stix_package.add_ttp(objTTP)    
        
        stix_package.add_indicator(objIndicator);
        objIndicator = None;    
        
    ### STIX Package Meta Data 
    stix_header = STIXHeader();   
    stix_header.title = srcObj.pkgTitle;
    stix_header.description = "<![CDATA[" + srcObj.pkgDscrpt + "]]>";
    
    ### Understanding markings http://stixproject.github.io/idioms/features/data-markings/
    marking_specification = MarkingSpecification()
    
    classLevel = SimpleMarkingStructure()
    classLevel.statement = "Unclassified (Public)"
    marking_specification.marking_structures.append(classLevel)
    
    objTOU = TermsOfUseMarkingStructure()
    sTOU = open('tou.txt').read()
    objTOU.terms_of_use = sProducer + " | " +  sTOU
    marking_specification.marking_structures.append(objTOU)
    
    tlp = TLPMarkingStructure()
    tlp.color = "WHITE"
    marking_specification.marking_structures.append(tlp)
    marking_specification.controlled_structure = "//node()"
    
    handling = Marking()
    handling.add_marking(marking_specification)
    stix_header.handling = handling
    
    stix_package.stix_header = stix_header
    stix_header  = None;
    
    ### Generate STIX XML File
    locSTIXFile = 'STIX_' + srcObj.fileName.split('.')[0] + '.xml'
    sndFile(stix_package.to_xml(),locSTIXFile);
        
    return(stix_package)
    
def cleanString(sData):
    sData = str(sData)
    sData = sData.strip(' \t\n\r')
    return(sData)    
    

# def trimFile_btwn(sFile,string_srt,string_end):
#     sNAMEFUNC = 'trimFile_btwn'
#     sTxt = "Called... " 
#     sndMSG(sTxt,'INFO',sNAMEFUNC)

#     iCnt = 0
#     iSrt = 0
#     iEnd = 0
#     with open(sFile,'r+') as data:
#         lines = data.readlines()

#         data.seek(0)
#         for line in lines:
#             if string_srt in line:
#                 iSrt = iCnt;
#             if string_end in line:
#                 iEnd = iCnt;
#             iCnt += 1
  
#         data.truncate()
#         for i in range(iSrt,iEnd+1):
#             data.write(lines[i])

#         lines = None    
#         data.close()

#     return(False)

if __name__ == "__main__":
    main()    
    
#EOF    
