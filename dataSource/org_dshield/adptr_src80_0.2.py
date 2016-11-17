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
from datetime                           import timedelta

from lib.utils.data                     import dictCC2CN
from lib.utils.cnvtFiles                import cnvt_CSV2Dict
from lib.utils.mngFiles                 import clsCSVDialect 
from lib.utils.mngFiles                 import getFile_lineByValue
from lib.utils.mngMisc                  import isIPv4, isIPv6

from stix.ttp                           import TTP, Behavior
from stix.ttp.behavior                  import MalwareInstance

from cybox.core.observable              import ObservableComposition, Observables, Observable
from cybox.objects.address_object       import Address, EmailAddress
from cybox.objects.whois_object         import WhoisRegistrar, WhoisContact, WhoisEntry


def main():
    sSOURCEID = 'src_80'

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
        "usrName":"dshield.org",
        "usrPass":"e(G%->5N>S>4Kvs",
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

    #print "------< No Remote Data >------"
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
    oDialect = clsCSVDialect()
    oDialect.from_dict(srcData.parsearg)
    oDialect.delimiter = '\t'
    #oDialect.header = True
    
    srcDict = cnvt_CSV2Dict(srcData.filePath + srcData.fileName,dialect=oDialect)
    
    srcData.pkgTitle  = "DShield.org Recommended Block List "
    srcData.pkgDscrpt = "This list summarizes the top 20 attacking class C (/24) subnets over the last three days. The number of 'attacks' indicates the number of targets reporting scans from this subnet."
    srcData.pkgLink   = "http://feeds.dshield.org/block.txt"
    
     
    sDateVF = None;
    s3daysAgo = None;
    try:
        sDateVF = getFile_lineByValue(srcData.filePath + srcData.fileName, "updated:")[0].split("updated:")[1].strip()
        sDateVF = datetime.strptime(sDateVF, "%a %b %d %H:%M:%S %Y %Z")
        s3daysAgo = sDateVF + timedelta(days=-3)
        if sDateVF:  
            sDateVF = sDateVF.strftime("%Y-%m-%dT%H:%M:%SZ")
            s3daysAgo = s3daysAgo.strftime("%Y-%m-%dT%H:%M:%SZ")
            srcData.pkgDscrpt = srcData.pkgDscrpt.replace('last three days.', ('last three days (' + s3daysAgo + " - " + sDateVF + ')'))
    except:
        pass;
      
    for col in srcDict:
        if 'End' in srcDict[col]:
            sKey    = srcDict[col]['Start'] + "##comma##" + srcDict[col]['End']
        else:
            continue

        dictAttrib = srcDict[col]
        if sDateVF:
            dictAttrib.update({"dateVF":str(sDateVF)})
        if s3daysAgo:    
            dictAttrib.update({"dateRange":str(s3daysAgo) + " - " + str(sDateVF)}) 
        if 'noemail' in srcDict[col]['email']:
            dictAttrib.update({"email":None})    
     
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
        sAddr = sKey
        if len(sAddr) > 0:
            objAddr = Address();
            objAddr.is_source = True
            objAddr.address_value = sAddr
            objAddr.address_value.condition = 'InclusiveBetween'
            
            objAddr.category = 'ipv4-net'
           
            obsAddr = Observable(objAddr)
            objAddr = None;
            obsAddr.sighting_count = int(data[sKey]['attrib']['Attacks'])
            oObsSrcData.sighting_count   = int(data[sKey]['attrib']['Attacks'])
            obsAddr.observable_source.append(oObsSrcData)
            
            
            sTitle = 'NETWORK_range: ' + sAddr
            obsAddr.title = sTitle 
            sDscpt = 'ipv4-net' + ': ' + sAddr + " | "
            sDscpt += "is_source: True | "
            sDscpt += "Attack_Count: " +  data[sKey]['attrib']['Attacks'] + " | "
            sDscpt += "Attack_DateRange: " +  data[sKey]['attrib']['dateRange'] + " | "
            obsAddr.description = sDscpt 
            listOBS.append(obsAddr)
            obsAddr = None;
         
        ### Parsing Registrar Information
        if data[sKey]['attrib']['email']:
            objEmail = EmailAddress()
            objEmail.address_value = data[sKey]['attrib']['email']
            objEmail.address_value.condition = 'Equals'
            objEmail.category = 'e-mail'
            
            
            objWhoisReg = WhoisRegistrar();
            if len(data[sKey]['attrib']['Name']) > 1:
                objWhoisReg.name = data[sKey]['attrib']['Name']
            objWhoisReg.email_address = objEmail
            objEmail = None;
            
            objWhois = WhoisEntry()
            objWhois.registrar_info = objWhoisReg
            
            obsWhois = Observable(objWhois)
            #print obsWhois.id_
            objWhois = None;
            obsWhois.sighting_count = 1

            sTitle = 'REGISTRAR_email: ' + data[sKey]['attrib']['email']
            if len(data[sKey]['attrib']['Name']) > 0:
                sTitle += " | REGISTRAR_name: " + data[sKey]['attrib']['Name'] + " | "
            obsWhois.title = sTitle
            obsWhois.description = sTitle
            listOBS.append(obsWhois)
            obsWhois = None;
        
        sDscrpt       = None
        sCntry_code   = None
        sCntry_name   = None
        sRgstra_email = None
        sRgstra_name  = None

        if len(data[sKey]['attrib']['Country']) > 0:
            sCntry_code = data[sKey]['attrib']['Country']
            if sCntry_code in dictCC2CN:
                sCntry_name = dictCC2CN[sCntry_code]

        if 'email' in data[sKey]['attrib']:
            sRgstra_email =  data[sKey]['attrib']['email']

        if len(data[sKey]['attrib']['Name']) > 0:
            sRgstra_name =  data[sKey]['attrib']['Name']    
        
        sDscrpt = "This IP block appears to have "
        if sCntry_code:
            sDscrpt += "originated in " + sCntry_code 
            if sCntry_name:
                sDscrpt += "(" + sCntry_name + ")"      
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
            
        objIndicator.title = sAddr.replace('##comma##',' - ') + " | " + srcObj.pkgTitle 

                
        ### Add Generated observable to Indicator 
        objIndicator.add_indicator_type("IP Watchlist")
        objIndicator.observable_composition_operator = 'OR'    
        objIndicator.observables = listOBS    
 
        #Parsing Producer
        sProducer = srcObj.Domain;
        if len(sProducer) > 0:
            objIndicator.set_producer_identity(sProducer);
        
        objIndicator.set_produced_time(data[sKey]['attrib']['dateVF']);
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
    if 'dateRange' in data['attrib']:
        oContributor.date.start_date = data['attrib']['dateRange'].split(" - ")[0]
        oContributor.date.end_date   = data['attrib']['dateRange'].split(" - ")[1]

    ### Add object MeasureSource
    from cybox.common.measuresource              import MeasureSource
    oMeasureSource = MeasureSource()
    oMeasureSource.description      = srcObj.pkgTitle
    #oMeasureSource.sighting_count  = int(['attrib']['Attacks'])
    oMeasureSource.source_type      = "Aggregator - OpenSource"
    oMeasureSource.name             = srcObj.pkgLink 
    
    from cybox.common.contributor                import Personnel
    oMeasureSource.contributors = Personnel()
    oMeasureSource.contributors.append(oContributor)
    
    ### Generating InformationSourceType()
    from cybox.common.measuresource              import InformationSourceType
    oMeasureSource.information_source_type = InformationSourceType()
    oMeasureSource.information_source_type.value = "website - OpenSource"
    oMeasureSource.information_source_type.condition = 'Equals'
    #oMeasureSource.information_source_type.value = ''
    #oMeasureSource.information_source_type.vocab_reference =
    
    #from cybox.common.tools              import ToolType
    #oMeasureSource.tool_type.value = "website - OpenSource"
    #oMeasureSource.tool_type.condition = 'Equals'

    #from cybox.common.tools              import ToolType
    #oMeasureSource.tools           = cybox.TypedField("Tools", ToolInformationList)
    
    #oTime = Time()
    #oMeasureSource.time            = cybox.TypedField("Time", Time)
    
    #oMeasureSource.platform        = cybox.TypedField("Platform", PlatformSpecification)
    #oMeasureSource.system          = cybox.TypedField("System", ObjectProperties)
    #oMeasureSource.instance        = cybox.TypedField("Instance", ObjectProperties)
        
    return(oMeasureSource);
    
def cleanString(sData):
    sData = str(sData)
    sData = sData.strip(' \t\n\r')
    return(sData)    
    
if __name__ == "__main__":
    main()    
    
#EOF    
