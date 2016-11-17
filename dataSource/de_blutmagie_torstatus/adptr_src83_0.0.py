#!/usr/bin/env python

import os    
import sys
import hashlib
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
from lib.utils.data                     import dictCC2CN
from lib.utils.cnvtFiles                import cnvt_CSV2Dict
from lib.utils.mngFiles                 import clsCSVDialect 
from lib.utils.mngMisc                  import isIPv4, isIPv6, isFQDN, isTLD, isNumber

from stix.common                        import InformationSource, Identity
from stix.ttp                           import TTP, Behavior
from stix.ttp.behavior                  import MalwareInstance

from cybox.core.observable              import ObservableComposition, Observables, Observable
from cybox.objects.domain_name_object   import DomainName
from cybox.objects.address_object       import Address
from cybox.objects.port_object          import Port

def main():
    sSOURCEID = 'src_83'

    ### Setup for running as Main and template for use of adptr function
    tmpJSON = getFile_JSON2Dict('../../data/openSourceList.json');
    tmpDict = None;
    
    if tmpJSON:
        for sKey in tmpJSON:
            if tmpJSON[sKey]['srcIndex'] == sSOURCEID:
                tmpDict = tmpJSON[sKey]
    else:
        return(0)            
    
    ### Without a valide Source Meta data this function will exit
    if tmpDict == None:
        retrun(False);
    
    ### This infomation is only require if you wish upload this data
    ###     to a TAXII Server
  

    dstCreds = {
        "URI"    :"http://www.hailataxii.com/taxii-discovery-service",
        "usrName":"blutmagie_de",
        "usrPass":"#gthggW+8f2pKr2",
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
    srcData.chnkSize = 250;  # This version does not make use of the chucking capability  
    srcData.dstCreds = dstCreds;
    srcData.filePath = os.path.dirname(os.path.abspath(__file__)) + '/'

    srcData.pkgTitle  = "Tor 'Exit Point' router IP/Host list"
    srcData.pkgDscrpt = "torstatus.blutmagie.de idenitifes the following IP/Host as Tor network 'Exit Point' routers"
    srcData.pkgLink   = "http://torstatus.blutmagie.de/query_export.php/Tor_query_EXPORT.csv"

    #print "------< NOT UPDATING >------" 

    if not getRmt_File(srcData.srcCreds,  srcData.filePath + srcData.fileName) == True:
        # if no source data is found, this script will exit
        return(False)

    ### Extract(src2Dict) Transform(dict2STIX) Load(sndTAXII)
    dictObj  = adptr_src2Dict(srcData, True);
    
    if not dictObj == False:
        iCnt = 0
        tmpDict = {}
        if len(dictObj) > srcData.chnkSize:
            for sKey in dictObj:
                if not dictObj[sKey] == None:
                    tmpDict[sKey] = dictObj[sKey]
                if iCnt == srcData.chnkSize:
                    stixObj = adptr_dict2STIX(srcData, tmpDict);
                    tmpDict = {}
                    iCnt = 0
                    if not stixObj == False:
                        taxiiMsg = sndTAXII(srcData.dstCreds,stixObj.to_xml(),True)
                iCnt += 1

        else:
            stixObj = adptr_dict2STIX(srcData, dictObj);
            if not stixObj == False:
                taxiiMsg = sndTAXII(srcData.dstCreds,stixObj.to_xml(),True)

    
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

    ### Parse Source File in to a Dictionary Object
    dstData = getFile_JSON2Dict(locDataFile)
    if not dstData:
        dstData = {}; 
        
    oDialect = clsCSVDialect()
    oDialect.from_dict(srcData.parsearg)
    oDialect.delimiter = ','
    srcDict = cnvt_CSV2Dict(srcData.filePath + srcData.fileName,dialect=oDialect)
    
    newData = {};
    #metaData = 
    for col in srcDict:
        # {0: u'', 1: u'20161231', 2: u'38zu.cn', 3: u'attackpage', 4: u'safebrowsing.google.com', 5: u'20140703', 6: u'20140302', 7: u'20130325', 8: u'20120426', 9: u'20110715', 10: u'relisted'}
        if len(srcDict[col]) < 1:
            continue;

        sKey = srcDict[col]['IP Address']
        dictAttrib = {}
        dictAttrib['Flags'] = {}
        dictAttrib['Ports'] = {}

        for item in srcDict[col]:
            if 'Flag' in item:
                if srcDict[col][item].isdigit():
                    dictAttrib['Flags'].update({item:int(srcDict[col][item])})
                else:
                    dictAttrib['Flagss'].update({item:None})   
            elif 'Port' in item:
                if srcDict[col][item].isdigit():
                    dictAttrib['Ports'].update({item:int(srcDict[col][item])})
                else:
                    dictAttrib['Ports'].update({item:None})
            elif 'Uptime' in item:
                if srcDict[col][item].isdigit():
                    dictAttrib.update({item:int(srcDict[col][item])})
                else:
                    dictAttrib.update({item:None})                  
            elif 'Bandwidth' in item:
                if srcDict[col][item].isdigit():
                    dictAttrib.update({item:int(srcDict[col][item])})
                else:
                    dictAttrib.update({item:None})   
            else:
                dictAttrib.update({item:srcDict[col][item]})


        if dictAttrib['Hostname'] == dictAttrib['IP Address']:
            dictAttrib['Hostname'] = None      

        # tmpHash = hashlib.md5(str(dictAttrib)).hexdigest()

        if sKey in dstData:
            dstData[sKey]['meta']['cnt'] += 1
            dstData[sKey]['meta']['dateDL'] = getUTCTime()
            # if not tmpHash ==  dstData[sKey]['meta']['attribHash']:
            #     dstData[sKey]['meta']['hasChanged'] = True
            #     print '---< Found Change >--- ' + sKey
            #     dstData[sKey]['meta']['attribHash'] = tmpHash    
                         
        else:
            dstData[sKey] = {}
            dstData[sKey]['meta'] = {'cnt':1,'dateDL':getUTCTime(),'IDs':{},'hasChanged':False,'attribHash':0x0}
            #dstData[sKey]['meta']['attribHash'] = tmpHash
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
    OBS_NAMESPACE  = Namespace("http://hailataxii.com", "opensource")
    stix_set_id_namespace(STIX_NAMESPACE)
    obs_set_id_namespace(OBS_NAMESPACE)
    
    ### Building STIX Wrapper
    stix_package = STIXPackage();
    objIndicator = Indicator();

    ### Bulid Object Data
    for sKey in data:
        objIndicator = Indicator();
        # if 'indicator' in data[sKey]['meta']['IDs']:
        #     objIndicator.id_ = data[sKey]['meta']['IDs'].key
        # else: 
        #     data[sKey]['meta']['IDs'].update({objIndicator.id_:'indicator'}) 
        
        listOBS = []
        
        ### Parsing IP Address
        sAddr = data[sKey]['attrib']['IP Address']
        if sAddr:
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
            # if 'address"' in data[sKey]['meta']['IDs']:
            #     obsAddr.id_ = data[sKey]['meta']['IDs'].key
            # else:
            #     data[sKey]['meta']['IDs'].update({objIndicator.id_:'address'})

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
        sDomain = data[sKey]['attrib']['Hostname']
        if sDomain:
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
            # if 'domain' in data[sKey]['meta']['IDs']:
            #     obsDomain.id_ = data[sKey]['meta']['IDs'].key
            # else:
            #     data[sKey]['meta']['IDs'].update({obsDomain.id_:'domain'})

            objDomain = None;
            obsDomain.sighting_count = 1
            obsDomain.title = 'Domain: ' + sDomain
            sDscrpt = 'Domain: ' + sDomain + " | "
            sDscrpt += "isFQDN: True | "
            obsDomain.description = "<![CDATA[" + sDscrpt + "]]>" 
            listOBS.append(obsDomain)
            obsDomain = None;
            objIndicator.add_indicator_type("Domain Watchlist")

        ### Parsing Port Number
        sPortList = data[sKey]['attrib']['Ports']
        for item in sPortList:
            if sPortList[item]: 
                objPort = Port();
                sPort = sPortList[item]
                objPort.port_value = int(sPort)
                objPort.port_value.condition = 'Equals'
                objPort.layer4_protocol = 'TCP'
                obsPort = Observable(objPort)
                objPort = None
                obsPort.sighting_count = 1
                obsPort.title = 'Port: ' + str(sPort)
                sDscrpt = 'PortNumber: ' + str(sPort) + " | "
                sDscrpt += "Protocol: TCP | "
                obsPort.description = "<![CDATA[" + sDscrpt + "]]>"     
                listOBS.append(obsPort)
         
        ### Add Generated observable to Indicator 
        objIndicator.observable_composition_operator = 'OR'    
        objIndicator.observables = listOBS    
        
        #Parsing Producer
        infoSrc = InformationSource(identity=Identity(name=srcObj.Domain))
        #infoSrc.add_contributing_source(data[sKey]['attrib']['ref'])
        objIndicator.producer = infoSrc;


        # if data[sKey]['attrib']['lstDateVF']:
        #     objIndicator.set_produced_time(data[sKey]['attrib']['lstDateVF'][0]);
        objIndicator.set_received_time(data[sKey]['meta']['dateDL']); 

        ### Generate Indicator Title based on availbe data
        lstContainng = []
        lstIs = []
        sTitle =  ' This'
        if data[sKey]['attrib']['Hostname']: 
            sTitle += ' domain ' + data[sKey]['attrib']['Hostname'] 
        else:
            sTitle += ' ipAddress ' + sKey

        sTitle += ' has been identified as a TOR network "Exit Point" router'
        objIndicator.title = sTitle;

        ### Generate Indicator Description based on availbe data 
        sDscrpt = ' torstatus.blutmagie.de has identified this'
        if data[sKey]['attrib']['Hostname']: 
            sDscrpt += ' domain ' + data[sKey]['attrib']['Hostname'] 
        else:
            sDscrpt += ' ipAddress ' + sKey

        # sDscrpt += ' with a router name of "' + data[sKey]['attrib']['Router Name'] + '"'   

        # if data[sKey]['attrib']['Ports']['ORPort']: 
        #     sDscrpt += ' using ORPort: ' + str(data[sKey]['attrib']['Ports']['ORPort'])

        # if data[sKey]['attrib']['Ports']['DirPort']: 
        #     sDscrpt += ' and DirPort: ' + str(data[sKey]['attrib']['Ports']['DirPort'])     

        sDscrpt += ' as a TOR network "Exit Point" router'    

        if data[sKey]['attrib']['Country Code']:
            sCntry_code = data[sKey]['attrib']['Country Code']
            if sCntry_code in dictCC2CN:
                sCntry_name = dictCC2CN[sCntry_code]
            sDscrpt += ', which appears to be located in ' + sCntry_name

        sDscrpt += '. \n\n RawData: ' + str(data[sKey]['attrib'])
        objIndicator.description = "<![CDATA[" + sDscrpt + "]]>";
                
        #Parse TTP
        # objMalware = MalwareInstance()
        # objMalware.add_type("Remote Access Trojan")

        # ttpTitle = data[sKey]['attrib']['type'] 
        # objTTP = TTP(title=ttpTitle)
        # objTTP.behavior = Behavior()
        # objTTP.behavior.add_malware_instance(objMalware)
        # objIndicator.add_indicated_ttp(objTTP)
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
    
    tlp = TLPMarkingStructure()
    tlp.color = "WHITE"
    marking_specification.marking_structures.append(tlp)
    marking_specification.controlled_structure = "//node()"
    
    objTOU = TermsOfUseMarkingStructure()
    sTOU = open('tou.txt').read()
    objTOU.terms_of_use = srcObj.Domain + " | " +  sTOU
    marking_specification.marking_structures.append(objTOU)
    
    handling = Marking()
    handling.add_marking(marking_specification)
    stix_header.handling = handling
    
    stix_package.stix_header = stix_header
    stix_header  = None;
    
    ### Generate STIX XML File
    locSTIXFile = 'STIX_' + srcObj.fileName.split('.')[0] + '.xml'
    sndFile(stix_package.to_xml(),locSTIXFile);

    # locDataFile = 'db_' + srcObj.fileName.split('.')[0] + '.json'
    # sndFile_Dict2JSON(data,locDataFile); 
    # data = None   
    return(stix_package)
    
def cleanString(sData):
    sData = str(sData)
    sData = sData.strip(' \t\n\r')
    return(sData)    
    
if __name__ == "__main__":
    main()    
    
#EOF    

