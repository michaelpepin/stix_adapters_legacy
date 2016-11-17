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
from lib.utils.mngMisc                  import isIPv4, isIPv6, isFQDN, isTLD, isNumber

from stix.common                        import InformationSource, Identity
from stix.ttp                           import TTP, Behavior
from stix.ttp.behavior                  import MalwareInstance

from cybox.core.observable              import ObservableComposition, Observables, Observable
from cybox.objects.domain_name_object   import DomainName

def main():
    sSOURCEID = 'src_36'

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
        "usrName":"lehigh_edu",
        "usrPass":"KWR6=&hj6FHhU*t",
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

    srcData.pkgTitle  = "Domain Block list by MalwareDomain from Lehigh University"
    srcData.pkgDscrpt = "A list of domains that are known to be used to propagate malware are listed in Bind and Windows zone files. The domains are loaded onto an internal DNS server. When a computer requests a URL or file from one of these domains, a fake reply is sent, thus preventing many malware installs from occuring"
    srcData.pkgLink   = "http://malwaredomains.lehigh.edu/files/"

    print "------< NOT UPDATING >------" 

    if not getRmt_File(srcData.srcCreds,  srcData.filePath + srcData.fileName) == True:
       # if no source data is found, this script will exit
       return(False)
 
    
    ### Extract(src2Dict) Transform(dict2STIX) Load(sndTAXII)
    dictObj  = adptr_src2Dict(srcData, True);
    
    if not dictObj == False:
        iCnt = 0
        tmpDict = {}
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

    ### Parse Source File in to a Dictionary Object
    dstData = getFile_JSON2Dict(locDataFile)
    if not dstData:
        dstData = {}; 
        
    oDialect = clsCSVDialect()
    oDialect.from_dict(srcData.parsearg)
    oDialect.delimiter = '\t'
    
    srcDict = cnvt_CSV2Dict(srcData.filePath + srcData.fileName,dialect=oDialect)
    
    newData = {};
    for col in srcDict:
        # {0: u'', 1: u'20161231', 2: u'38zu.cn', 3: u'attackpage', 4: u'safebrowsing.google.com', 5: u'20140703', 6: u'20140302', 7: u'20130325', 8: u'20120426', 9: u'20110715', 10: u'relisted'}
        if len(srcDict[col]) < 6:
            continue;
        else:    
            sKey    = srcDict[col][2]
    
        lstDateVF = []
        for idx in range(5, len(srcDict[col])):
            if len(srcDict[col][idx]) > 0 and isNumber(srcDict[col][idx][1]):
                sDateVF = srcDict[col][idx]
                try:
                    dSrt = datetime.strptime(sDateVF, "%Y%m%d") 
                    sDateVF = dSrt.strftime("%Y-%m-%dT%H:%M:%SZ")
                    lstDateVF.append(sDateVF)
                except:
                    pass;
                    
        #nextvalidation	domain	type	original_reference-why_it_was_listed	dateverified
        dictAttrib = {
            "domain"    :cleanString(srcDict[col][2]),
            "type"      :cleanString(srcDict[col][3]),
            "ref"       :cleanString(srcDict[col][4]),
            "lstDateVF" :lstDateVF
            }
           
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
    OBS_NAMESPACE  = Namespace("http://hailataxii.com", "opensource")
    stix_set_id_namespace(STIX_NAMESPACE)
    obs_set_id_namespace(OBS_NAMESPACE)
    
    ### Building STIX Wrapper
    stix_package = STIXPackage();
    objIndicator = Indicator();

    ### Bulid Object Data
    for sKey in data:
        objIndicator = Indicator();
        listOBS = []
        
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
         
        ### Add Generated observable to Indicator 
        objIndicator.observable_composition_operator = 'OR'    
        objIndicator.observables = listOBS    
        
        #Parsing Producer
        infoSrc = InformationSource(identity=Identity(name=srcObj.Domain))
        infoSrc.add_contributing_source(data[sKey]['attrib']['ref'])
        if len(srcObj.Domain) > 0:
            objIndicator.producer = infoSrc;

        if data[sKey]['attrib']['lstDateVF']:
            objIndicator.set_produced_time(data[sKey]['attrib']['lstDateVF'][0]);
        objIndicator.set_received_time(data[sKey]['dateDL']); 

        ### Generate Indicator Title based on availbe data
        lstContainng = []
        lstIs = []
        sTitle =  'This domain ' + data[sKey]['attrib']['domain'] + ' has been identified as malicious'
        if len(data[sKey]['attrib']['ref']):
            sTitle += ' by ' + data[sKey]['attrib']['ref']

        if len(data[sKey]['attrib']['type']) > 0:
            sTitle += ', via this vector [' + data[sKey]['attrib']['type'] + '].'
        else:
            sTitle += '.'
        objIndicator.title = sTitle;

        ### Generate Indicator Description based on availbe data 
        sDscrpt = 'Lehigh.edu site has added this domain ' + data[sKey]['attrib']['domain'] 
        sDscrpt += ' to recommend block list.'
        sDscrpt += ' This site has been identified as malicious'
        sDscrpt += ' by ' + data[sKey]['attrib']['ref']
        sDscrpt += ' and was still attive on the following dates ' + str(data[sKey]['attrib']['lstDateVF']) + "."
        objIndicator.description = "<![CDATA[" + sDscrpt + "]]>";
                
        #Parse TTP
        objMalware = MalwareInstance()
        objMalware.add_type("Remote Access Trojan")

        ttpTitle = data[sKey]['attrib']['type'] 
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
        
    return(stix_package)
    
def cleanString(sData):
    sData = str(sData)
    sData = sData.strip(' \t\n\r')
    return(sData)    
    
if __name__ == "__main__":
    main()    
    
#EOF    
