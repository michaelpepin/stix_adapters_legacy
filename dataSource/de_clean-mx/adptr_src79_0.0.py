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
from lib.utils.cnvtFiles                import cnvt_XML2Dict
from lib.utils.data                     import dictCC2CN
from lib.utils.mngMisc                  import isIPv4, isIPv6, isFQDN, isTLD

from stix.ttp                           import TTP, Behavior
from stix.ttp.behavior                  import MalwareInstance

from cybox.core.observable              import ObservableComposition, Observables, Observable
from cybox.objects.address_object       import Address, EmailAddress
from cybox.objects.domain_name_object   import DomainName
from cybox.objects.uri_object           import URI



def main():
    sSOURCEID = 'src_79'

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
        "usrName":"clean_mx_de",
        "usrPass":"n9GM=mykh8U$CE$",
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

    #print "------< Not Updating >------"
    
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
    
    srcDict = cnvt_XML2Dict(srcData.filePath + srcData.fileName);    
    
    srcData.pkgTitle  = "Clean MX Phishing URL Block List "
    srcData.pkgDscrpt = ""
    srcData.pkgLink   = "http://support.clean-mx.de/clean-mx/phishing.php"
    

    for item in srcDict['output']['entries']['entry']:
        sKey = item['id']
        
        if item['first'] == "0":
            item['first'] = None;
        else:    
            item['first'] = datetime.fromtimestamp(int(item['first'])).strftime('%Y-%m-%dT%H:%M:%SZ');
        
        if item['last'] == "0":
            item['last'] = None;
        else:    
            item['last'] = datetime.fromtimestamp(int(item['last'])).strftime('%Y-%m-%dT%H:%M:%SZ');

        dictAttrib = item 
        
        lstNS = [];
        for i in range(1, 5):
            if dictAttrib['ns' + str(i)]:
                lstNS.append(dictAttrib['ns' + str(i)])  
        
        dictAttrib.update({"nsList":lstNS})

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
        
        oObsSrcData = genObsSrcData(srcObj, data[sKey])
        ### Parsing IP Address
        sAddr = data[sKey]['attrib']['ip']
        if len(sAddr) > 0:
            objAddr = Address();
            objAddr.is_destination = True
            objAddr.address_value = sAddr
            objAddr.address_value.condition = 'Equals'
            if isIPv4(sAddr):
                objAddr.type = 'ipv4-addr'
            elif isIPv6(sAddr):
                objAddr.type = 'ipv6-addr'
            else:
                continue; 
           
            obsAddr = Observable(objAddr)
            objAddr = None;
            obsAddr.sighting_count = 1
            oObsSrcData.sighting_count   = 1
            obsAddr.observable_source.append(oObsSrcData)
            
            sTitle = 'IP: ' + sAddr
            obsAddr.title = sTitle 
            sDscpt = 'ipv4-addr' + ': ' + sAddr + " | "
            sDscpt += "is_destination: True | "
            if data[sKey]['attrib']['first']:
                sDscpt += "firstSeen: " +  data[sKey]['attrib']['first'] + " | "
            if data[sKey]['attrib']['last']:
                sDscpt += "lastSeen: " +  data[sKey]['attrib']['last'] + " | "
            obsAddr.description = "<![CDATA[" + sDscpt + "]]>" 
            listOBS.append(obsAddr)
            obsAddr = None;
        
        ### Parsing Network Address
        sAddr = data[sKey]['attrib']['inetnum']
        if sAddr:
            objAddr = Address();
            objAddr.is_destination = True
            sAddrNet = sAddr.split("-")
            objAddr.address_value = sAddrNet[0].strip() + "##comma##" + sAddrNet[1].strip()
            objAddr.address_value.condition = 'InclusiveBetween'
            
            objAddr.category = 'ipv4-net'
           
            obsAddr = Observable(objAddr)
            objAddr = None;
            obsAddr.sighting_count = 1
            oObsSrcData.sighting_count   = 1
            obsAddr.observable_source.append(oObsSrcData)
            
            sTitle = 'NETWORK_range: ' + sAddr
            obsAddr.title = sTitle 
            sDscpt = 'ipv4-net' + ': ' + sAddr + " | "
            if data[sKey]['attrib']['netname']:
                sDscpt += 'netName' + ': ' + data[sKey]['attrib']['netname'] + " | "
            obsAddr.description = "<![CDATA[" + sDscpt + "]]>" 
            listOBS.append(obsAddr)
            obsAddr = None;
         
        ### Parsing Email Address
        sEMAIL = data[sKey]['attrib']['email']
        if sEMAIL:
            objEmail = EmailAddress();
            #objEmail.is_source = True
            objEmail.address_value = sEMAIL
            objEmail.address_value.condition = 'Equals'
            
            objEmail.category = 'e-mail'
           
            obsEmail = Observable(objEmail)
            objEmail = None;
            obsEmail.sighting_count = 1
            oObsSrcData.sighting_count = 1
            if len(data[sKey]['attrib']['source']) > 0:
                oObsSrcData.name = data[sKey]['attrib']['source']
            obsEmail.observable_source.append(oObsSrcData)
            
            sTitle = 'REGISTRAR_email: ' + sEMAIL
            obsEmail.title = sTitle
            sDscrpt = 'REGISTRAR_email: ' + sEMAIL
            if data[sKey]['attrib']['descr']:
                sDscrpt += " | REGISTRAR_name: " + data[sKey]['attrib']['descr'] + " | "
                        
            obsEmail.description = "<![CDATA[" + sDscrpt + "]]>"
            listOBS.append(obsEmail)
            obsEmail = None;
            
        ### Parsing Domain
        sDomain = data[sKey]['attrib']['domain']
        if len(sDomain) > 0:
            objDomain = DomainName();
            objDomain.value = sDomain;
            objDomain.value.condition = 'Equals'
            objDomain.is_destination = True
            if isFQDN(sDomain):
                objDomain.type = 'FQDN'
            elif isTLD(sDomain):
                objDomain.type = 'TLD'
            else:
                continue; 
            
            obsDomain = Observable(objDomain)   
            objDomain = None;
            obsDomain.sighting_count = 1
            oObsSrcData.sighting_count   = 1
            obsDomain.observable_source.append(oObsSrcData)
            obsDomain.title = 'Domain: ' + sDomain
            sDscpt = 'Domain: ' + sDomain + " | "
            sDscpt += "isDestination: True | "
            if data[sKey]['attrib']['first']:
                sDscpt += "firstSeen: " +  data[sKey]['attrib']['first'] + " | "
            if data[sKey]['attrib']['last']:
                sDscpt += "lastSeen: " +  data[sKey]['attrib']['last'] + " | "
            
            #if     
            obsDomain.description = "<![CDATA[" + sDscpt + "]]>"
            listOBS.append(obsDomain)
            obsDomain = None;
            objIndicator.add_indicator_type("Domain Watchlist")
            
        #Parser URI
        sURI = data[sKey]['attrib']['url']
        if len(sURI) > 0:
            objURI = URI();
            objURI.value = sURI
            objURI.value.condition = 'Equals'
            objURI.type_ = URI.TYPE_URL
            obsURI = Observable(objURI)   
            objURI = None;
            obsURI.sighting_count = 1
            oObsSrcData.sighting_count   = 1
            obsURI.observable_source.append(oObsSrcData)
            obsURI.title = 'URI: ' + sURI
            sDscpt = 'URI: ' + sURI + " | "
            sDscpt += "Type: URL | "
            obsURI.description = "<![CDATA[" + sDscpt + "]]>" 
            listOBS.append(obsURI)
            obsURI = None;
            objIndicator.add_indicator_type("URL Watchlist")
        
        sDscrpt       = None
        sCntry_code   = None
        sCntry_name   = None
        sRgstra_email = None
        sRgstra_name  = None
        
        # add Phishing Email Target
        # add Phishing email Details phishtank_ID
        

        if data[sKey]['attrib']['country']:
            sCntry_code = data[sKey]['attrib']['country']
            if sCntry_code in dictCC2CN:
                sCntry_name = dictCC2CN[sCntry_code]

        if data[sKey]['attrib']['email'] > 0:
            sRgstra_email =  data[sKey]['attrib']['email']

        if data[sKey]['attrib']['descr']:
            sRgstra_name =  data[sKey]['attrib']['descr']    
        
        sDscrpt = " clean-mx.de has identified this "
        if isIPv4(data[sKey]['attrib']['domain']):
            sDscrpt += "ip address " + data[sKey]['attrib']['domain'] + " "
        else:
            sDscrpt += "domain " + data[sKey]['attrib']['domain'] + " "   

        sDscrpt += "as malicious "
        if data[sKey]['attrib']['target']:    
            sDscrpt +=  "and uses phishing email(s) targeting " + data[sKey]['attrib']['target'] + " users with " 
        else:
            sDscrpt +=  "and sent out "
 
        sDscrpt +=  "email containg this url <-Do Not Connect-> {"+ data[sKey]['attrib']['url'] +"} <-Do Not Connect-> link. "
        
        if data[sKey]['attrib']['phishtank']:
            sDscrpt +=  "For more detail on the specific phisihing email use this phishtank ID ["+ data[sKey]['attrib']['phishtank'] +"]. "

        if sCntry_code:
            sDscrpt += " This url appears to originated in " + sCntry_code 
            if sCntry_name:
                sDscrpt += " (" + sCntry_name + ")"      
        if sCntry_code and (sRgstra_email or sRgstra_name):
            sDscrpt += " and is "   
        if sRgstra_email:
            sDscrpt += "register to " + sRgstra_email 
        if sRgstra_email and sRgstra_name:
            sDscrpt += " of "  + sRgstra_name  
        elif sRgstra_name: 
            sDscrpt += "register to " + sRgstra_name               
        sDscrpt += "."     

        if sCntry_code or sRgstra_email or sRgstra_name:    
            objIndicator.description = "<![CDATA[" + sDscrpt + "]]>";    
        
        sTitle = 'Phishing ID:' + sKey + " "
        if data[sKey]['attrib']["target"]:
            sTitle += "Target: " + data[sKey]['attrib']["target"] + " "     
        
        if data[sKey]['attrib']["url"]:
            sTitle += "URL: " + data[sKey]['attrib']["url"] + " "
        
        objIndicator.title = sTitle 
                
        ### Add Generated observable to Indicator 
        objIndicator.add_indicator_type("IP Watchlist")
        objIndicator.observable_composition_operator = 'OR'    
        objIndicator.observables = listOBS    
 
        #Parsing Producer
        sProducer = srcObj.Domain;
        if len(sProducer) > 0:
            objIndicator.set_producer_identity(sProducer);
        
        objIndicator.set_produced_time(data[sKey]['attrib']['first']);
        objIndicator.set_received_time(data[sKey]['dateDL']);
 
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
    #sTOU = open('tou.txt').read()
    objTOU.terms_of_use = sProducer + " | " + srcObj.srcTOU
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
    
def genObsSrcData(srcObj, data):

    ### Add object Contributor
    from cybox.common.contributor                import Contributor
    oContributor        = Contributor()
    #oContributor.role     = 'testRole'
    #oContributor.name     = 'testName'
    #oContributor.email    = 'testEmail'
    #oContributor.phone    = 'testPhone'
    oContributor.organization = srcObj.Domain
    
    from cybox.common.daterange                  import DateRange
    oContributor.date = DateRange()
    oContributor.date.start_date = data['attrib']['first']
    #oContributor.date.end_date   = data['attrib']['dateRange'].split(" - ")[1]

    ### Add object MeasureSource
    from cybox.common.measuresource              import MeasureSource
    oMeasureSource = MeasureSource()
    oMeasureSource.description      =  "<![CDATA[" + srcObj.pkgTitle + "]]>"
    #oMeasureSource.sighting_count  = int(['attrib']['Attacks'])
    oMeasureSource.source_type      = "Information Source"
    oMeasureSource.name             = srcObj.pkgLink 
    
    from cybox.common.contributor                import Personnel
    oMeasureSource.contributors = Personnel()
    oMeasureSource.contributors.append(oContributor)
    

        
    return(oMeasureSource);
    
def cleanString(sData):
    sData = str(sData)
    sData = sData.strip(' \t\n\r')
    return(sData)    
    
if __name__ == "__main__":
    main()    
    
#EOF    
