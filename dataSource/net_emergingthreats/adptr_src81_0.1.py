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
from lib.utils.cnvtFiles                import cnvt_CSV2Dict
from lib.utils.mngFiles                 import clsCSVDialect 
from lib.utils.mngMisc                  import isIPv4, isIPv6, isFQDN, isTLD

from stix.ttp                           import TTP, Behavior
from stix.ttp.behavior                  import MalwareInstance

from cybox.core.observable              import ObservableComposition, Observables, Observable
from cybox.objects.address_object       import Address
from cybox.objects.port_object          import Port



def main():
    sSOURCEID = 'src_81'

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
        "usrName":"emergingthreats.net",
        "usrPass":"fgyLdf&x7U9TbU8",
        "crtName":"",
        "crtPass":""
    };  
    dstCreds = {
        "URI"    :"http://172.16.167.139/taxii-discovery-service",
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
    dictObj  = adptr_src2Dict(srcData, False);
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
    
    ### Parse Source File in to a Dictionary Object
    dstData = getFile_JSON2Dict(locDataFile)
    if not dstData:
        dstData = {};

        
    newData = {};    
    
    oDialect = clsCSVDialect()
    oDialect.from_dict(srcData.parsearg)
    oDialect.delimiter = '\n'
    
    srcDict = cnvt_CSV2Dict(srcData.filePath + srcData.fileName,dialect=oDialect)
    
    srcData.pkgTitle  = "SNORT Rule by Emergingthreats | Block Botnet Command and Control"
    srcData.pkgDscrpt = "Emerging Threats Botnet Command and Control drop rules.  These are generated from the EXCELLENT work done by the Shadowserver team and the abuse.ch folks. All Volunteers, we're grateful for their dedication! http://www.shadowserver.org; https://spyeyetracker.abuse.ch; https://palevotracker.abuse.ch; https://zeustracker.abuse.ch. More information available at www.emergingthreats.net"
    srcData.pkgLink   = "http://rules.emergingthreats.net/blockrules/emerging-botcc.portgrouped.rules"
    
        
    for col in srcDict:
        # {0: u'alert tcp $HOME_NET any -> 50.116.1.225 22 (msg:"ET CNC Shadowserver Reported CnC Server Port 22 Group 1"; flags:S; reference:url,doc.emergingthreats.net/bin/view/Main/BotCC; reference:url,www.shadowserver.org; threshold: type limit, track by_src, seconds 360, count 1; classtype:trojan-activity; flowbits:set,ET.Evil; flowbits:set,ET.BotccIP; sid:2405000; rev:3570;)'}

        sKey    = srcDict[col][0]
        strTmp  = sKey.split("(")
        
        tmpList = strTmp[0].split(" ")
        ipProt = None
        if tmpList[1]:
            ipProt = tmpList[1]
            
        ipList = None    
        if tmpList[5]:  
            if "[" in tmpList[5]:
                tmpList[5] = tmpList[5][1:-1]
            ipList = tmpList[5].split(",")      
        
        ipPort = None
        if tmpList[6]:
            ipPort = tmpList[6]
        
        attrList = strTmp[1].split(";")[:-1]

        tmpDict = {}
        for i in range(len(attrList)):
            attrList[i] = cleanString(attrList[i])
            tmpKey = attrList[i].split(':')[0]
            tmpVal = attrList[i].split(':')[1]
            
            if tmpKey in tmpDict:
                tmpDict[tmpKey] += "|" + tmpVal
            else:
                tmpDict.update({tmpKey:tmpVal})
       
        dictAttrib = tmpDict
        dictAttrib.update({'ipAddrList':ipList,
                           'rule':sKey,
                           'ipPort':ipPort,
                           'ipProt':ipProt
                         })

        if sKey in dstData:
            dstData[sKey]['cnt'] += 1
            dstData[sKey]['dateDL'] = getUTCTime() 
                         
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
        for sAddr in data[sKey]['attrib']['ipAddrList']:
            if len(sAddr) > 0:
                objAddr = Address();
                objAddr.is_destination = True
                objAddr.address_value = sAddr
                #objAddr.address_value.operator = 'Equals'
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
                sDscrpt += "isDestination: True | "
                obsAddr.description = "<![CDATA[" + sDscrpt + "]]>" 
                listOBS.append(obsAddr)
                obsAddr = None;
         
        
        
        ### Parsing Port Number
        sPort = data[sKey]['attrib']['ipPort']
        if len(sPort) > 0:   
            objPort = Port();
            objPort.port_value = int(sPort)
            objPort.port_value.condition = 'Equals'
            sProtocol = data[sKey]['attrib']['ipProt']
            if len(sProtocol) > 0:
                objPort.layer4_protocol = sProtocol.upper()
            
            obsPort = Observable(objPort)
            objPort = None;
            obsPort.sighting_count = 1
            obsPort.title = 'Port: ' + sPort
            sDscrpt = 'PortNumber' + ': ' + sPort + " | "
            sDscrpt += "Protocol: " + sProtocol.upper() + " | "
            obsPort.description = "<![CDATA[" + sDscrpt + "]]>"     
            listOBS.append(obsPort)
        
        ### Add Generated observable to Indicator 
        objIndicator.add_indicator_type("IP Watchlist")
        objIndicator.observable_composition_operator = 'OR'    
        objIndicator.observables = listOBS    
        
                 
        from stix.extensions.test_mechanism.snort_test_mechanism import SnortTestMechanism
        from stix.common import InformationSource, Identity
        testMech = SnortTestMechanism()
        testMech.rules = [data[sKey]['attrib']['rule']] 
        testMech.efficacy = "Unknown"
        
        infoSrc = InformationSource(identity=Identity(name=srcObj.Domain))
        infoSrc.add_contributing_source("http://www.shadowserver.org")
        infoSrc.add_contributing_source("https://spyeyetracker.abuse.ch")
        infoSrc.add_contributing_source("https://palevotracker.abuse.ch")
        infoSrc.add_contributing_source("https://zeustracker.abuse.ch")
        
        testMech.producer = infoSrc
        
        lstRef = data[sKey]['attrib']['reference'].split('|')
        testMech.producer.references = lstRef
          
        objIndicator.test_mechanisms = [testMech]         
                 
                    
        #Parsing Producer
        sProducer = srcObj.Domain;
        if len(sProducer) > 0:
            objIndicator.set_producer_identity(sProducer);
        
        #objIndicator.set_produced_time(data[sKey]['attrib']['dateVF']);
        objIndicator.set_received_time(data[sKey]['dateDL']);
        
        ### Title / Description Generator
        objIndicator.set_received_time(data[sKey]['dateDL']);
        
        sTitle = "sid:" + data[sKey]['attrib']['sid'] + " | "
        sTitle += data[sKey]['attrib']['msg'] + " | "
        sTitle += "rev:" + data[sKey]['attrib']['rev'] 
        objIndicator.title = sTitle;
        
        sDscrpt = "SNORT Rule by Emergingthreats | " + data[sKey]['attrib']['rule']
        objIndicator.description = "<![CDATA[" + sDscrpt + "]]>";
        

        #Parse TTP
        objMalware = MalwareInstance()
        nameList = data[sKey]['attrib']['flowbits']
        if len(nameList) > 0:
            nameList = nameList.split("|")
            for sName in nameList:
                sName = sName.split(",")[1]
                objMalware.add_name(sName)
                
        #objMalware.add_type("Remote Access Trojan")
        objMalware.short_description = data[sKey]['attrib']['msg']

        ttpTitle = data[sKey]['attrib']['classtype'] + " | " + data[sKey]['attrib']['msg']
        objTTP = TTP(title=ttpTitle)
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
    
    tlp = TLPMarkingStructure()
    tlp.color = "WHITE"
    marking_specification.marking_structures.append(tlp)
    marking_specification.controlled_structure = "//node()"
    
    objTOU = TermsOfUseMarkingStructure()
    sTOU = open('tou.txt').read()
    objTOU.terms_of_use = sProducer + " | " +  sTOU
    marking_specification.marking_structures.append(objTOU)
    
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
    
if __name__ == "__main__":
    main()    
    
#EOF    
