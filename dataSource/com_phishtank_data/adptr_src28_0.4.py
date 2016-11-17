
import os    
import sys
import hashlib
from datetime import datetime


### This is add to handle the libraies sent in this Package, in your envroment this would typically be vary differnt
sys.path.insert(0, '../../')
### Generally required for all Adpters
from lib.utils.mngMSG   import sndMSG
from stix.utils         import set_id_namespace as stix_set_id_namespace
from cybox.utils        import set_id_namespace as cybox_set_id_namespace
from cybox.utils        import Namespace
from xml.sax.saxutils   import escape

STIX_NAMESPACE = {"http://www.hailataxii.com" : "opensource"}
CYBOX_NAMESPACE  = Namespace("http://www.hailataxii.com", "opensource")
stix_set_id_namespace(STIX_NAMESPACE)
cybox_set_id_namespace(CYBOX_NAMESPACE)

def main():
    from lib.utils.mngFiles         import getFile_Source2Dict
    from lib.utils.mngSources_r01   import clsDataSource

    dstCreds = {
        "URI"    :"http://www.hailataxii.com/taxii-discovery-service",
        "usrName":"phishtank_com",
        "usrPass":"hXtk-YL?Zfh-G6v",
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

    srcData = clsDataSource(iID=28);
    srcData.chnkSize  = 250; 
    srcData.pkgTitle  = "PhishEmail URL "
    srcData.pkgDscrpt = "List of embed URI found in suspected Phishing Emails "
    srcData.pkgLink   = "http://www.phishtank.com/"
    srcData.from_dict(getFile_Source2Dict('../../data/db_sourceList.json',srcData.ID));
    srcData.dstCreds  = dstCreds;
    srcData.filePath  = os.path.dirname(os.path.abspath(__file__)) + '/'
    
    sndMSG('---[ Start: Src_' + str(srcData.ID) + ' ]---','INFO')
    #sndMSG('---< NOT UPDATING >--- ','INFO')
    getRmt_data(srcData)
    
    ### Extract / Transform / Load 
    dictObj = adptrExtract_asDict(srcData, True);

    subDict = {'data':{},'source':{}}
    if len(dictObj):
        iSize_Total = len(dictObj['data'])
        iSize_Sent = 0
        for sKey in dictObj['data']:
            subDict['data'][sKey] =  dictObj['data'][sKey]

            if len(subDict['data']) > srcData.chnkSize:
                iSize_Sent += len(subDict['data'])
                subDict['source'].update(dictObj['source'])
                bFlag = adptrLoad_asXML(srcData, subDict)
                sndMSG('Sent: ' + str(iSize_Sent) + " of " + str(iSize_Total),'INFO')
                subDict = None
                subDict = {'data':{},'source':{}}

        if len(subDict):
            iSize_Sent += len(subDict['data'])
            subDict['source'].update(dictObj['source'])
            bFlag = adptrLoad_asXML(srcData, subDict)
            sndMSG('Sent: ' + str(iSize_Sent) + " of " + str(iSize_Total),'INFO')

    sndMSG('---[ Finsh: Src_' + str(srcData.ID) + ' ]---','INFO')

    return(0)

############################################
### ---[ ETL Functions ]---

def adptrExtract_asDict(srcData, isUpdateNewDataOnly=True):
    sNAMEFUNC = 'adptrExtract_asDict()'
    sndMSG('Called...','INFO',sNAMEFUNC)
    if not srcData: return(None); #srcData can not be empty

    ### Generally required for all Adpters
    from lib.utils.mngDateTime  import getUTCTime

    ### Get Localy Data - Used to Remove duplicates
    data = getDB_local(srcData);
    srcDict = cnvt_csv2dict(srcData)

    localData = data
    from lib.utils.mngFiles     import getFile_JSON2Dict
    newData = getFile_JSON2Dict('db_pattern.json')

    ### From srcDict ; look for duplicated data
    for item in srcDict:
        sKey = srcDict[item]['phish_id']
        if localData['data'].has_key(sKey):
            #TODO: Check if hash is diffrent, 
            #      if so, created updated STIX Doc
            #      Use smae GUID as original
            pass;
        else:
            localData['data'][sKey] = {'src':srcDict[item]}
            localData['data'][sKey]['meta'] = {'md5':genHash_md5(srcDict[item])}
            localData['data'][sKey]['meta'].update({'dateDL':getUTCTime()})
            newData['data'][sKey] = localData['data'][sKey]

    if isUpdateNewDataOnly == False:
        newData = localData

    if len(newData['data']):
        sTxt = "Found " + str(len(newData['data'])) + " new data elements";
        sndMSG(sTxt,'INFO',sNAMEFUNC);
    else:
        sTxt = "Found no new data";
        sndMSG(sTxt,'INFO',sNAMEFUNC); 
        newData = {}

    setDB_local(localData,srcData);
    return(newData);

def adptrTransform_Dict2Obj(srcData, data=None):
    sNAMEFUNC = 'adptrTransform_Dict2Obj'
    sndMSG('Called...','INFO',sNAMEFUNC)
    if not srcData: return(None); #srcData can not be empty

    from stix.core          import STIXPackage
    from stix.common        import InformationSource, Identity
    from stix.data_marking  import Marking
    from stix.ttp           import TTP

    ### Build Package
    objMarkingSpecification = genObject_MarkingSpecification(data)
    objMarkingSpecification.controlled_structure = "//node()"

    objHdr = genData_STIXHeader(data)
    objHdr.handling = Marking(objMarkingSpecification)
    objHdr.information_source = InformationSource(identity=Identity(name=srcData.pkgLink))
    
    objTTP  = genObject_TTP(data)
    objTTP.information_source = InformationSource(identity=Identity(name=srcData.pkgLink))

    objPkg = STIXPackage();
    objPkg.stix_header = objHdr
    objPkg.add_ttp(objTTP)
    
    for sKey in data['data']:
        obsList = []
        ### Build Observables
        obsURI = genObject_URI(data['data'][sKey]['src'])
        try:    
            obsURI.id_ = data['data'][sKey]['meta']['uri']
        except: 
            data['data'][sKey]['meta'].update({'uri':obsURI.id_})

        ### Srt: Stupid test to make sure URL be output via STIX.to_xml()
        try: 
            testPkg = STIXPackage();
            testPkg.add_observable(obsURI)
            testPkg.to_xml()
        except:
            sNAMEFUNC = 'adptrTransform_Dict2Obj'
            sndMSG('Error Parsing URL for this key: ['  + sKey + ']','INFO',sNAMEFUNC)
            testPkg = None 
            continue
        ### End: Stupid test

        objPkg.add_observable(obsURI)
        obsList.append(genRefObs(obsURI))

        ### Build Indicators
        objInd = genObject_Indicator(data['data'][sKey]['src'])
        try:    
            obsURI.id_ = data['data'][sKey]['meta']['ind']
        except: 
            data['data'][sKey]['meta'].update({'ind':objInd.id_})

        objInd.producer    = InformationSource(identity=Identity(name=srcData.pkgLink))
        objInd.observables = obsList
        objInd.indicator_types = ["URL Watchlist"]
        objInd.observable_composition_operator = "OR"
        objInd.set_received_time(data['data'][sKey]['meta']['dateDL'])
        try: 
            objInd.set_produced_time(data['data'][sKey]['src']['verification_time'])
        except: 
            pass;

        if not data['data'][sKey]['src']['target'] == 'Other':
            from stix.ttp                   import TTP
            objVictimTargeting = genData_VictimTargeting(data['data'][sKey]['src'])
            if obsURI:
                objVictimTargeting.targeted_technical_details = genRefObs(obsURI)
            objTTP_vic = TTP()
            objTTP_vic.title = "Targeting: " + data['data'][sKey]['src']['target']
            objTTP_vic.victim_targeting = objVictimTargeting
            objInd.add_indicated_ttp(objTTP_vic)
         
        objInd.add_indicated_ttp(TTP(idref=objTTP.id_))
        objPkg.add_indicator(objInd);
   
    #updateDB_local(data,srcData);
    return(objPkg);

def adptrLoad_asXML(srcData, data, isChunk=False):
    from lib.conns.curlTAXII        import sndTAXII
    bFlag = False
    import pprint
    tmpObj  = adptrTransform_Dict2Obj(srcData, data)

    if not tmpObj: return(None)
    #locSTIXFile = 'STIX_' + srcData.fileName.split('.')[0] + '.xml'
    locSTIXFile = 'STIX.xml'
    with open(locSTIXFile, "w") as outfile:
         outfile.write(tmpObj.to_xml());
         outfile.close();

    sNAMEFUNC = 'adptrLoad_asXML()'
    sndMSG('Called...','INFO',sNAMEFUNC)
    taxiiMsg = sndTAXII(srcData.dstCreds,tmpObj.to_xml(),True)

    if str(taxiiMsg[:1000]).find('SUCCESS')!=-1:
        sndMSG('Pkg Sent Successfully...','INFO',sNAMEFUNC)
        bFlag = True
    else:
        sndMSG('Pkg was not Sent...','ERROR',sNAMEFUNC)
        sndMSG(taxiiMsg)
        bFlag = False

    return(bFlag)

#####################################
### ---[ Supporting Functions ]---  

def genData_AttackPattern(data):
    from stix.utils                 import create_id as StixID
    from stix.ttp.attack_pattern    import AttackPattern

    objAttackPattern = AttackPattern()
    objAttackPattern.capec_id          = None
    objAttackPattern.title             = data['source']['stix.ttp.attack_pattern.AttackPattern.title']
    objAttackPattern.description       = None
    objAttackPattern.short_description = None

    return(objAttackPattern)

def genData_Behavior(data):
    from stix.ttp.behavior          import Behavior
    
    ### Behavior describes the attack patterns, malware, or exploits that the attacker leverages to execute this TTP
    ### http://stix.mitre.org/language/version1.0.1/xsddocs/extensions/attack_pattern/capec_2.6.1/1.0.1/ttp_xsd.html#TTPType_Behavior
    objBehavior = Behavior()
    objBehavior.attack_patterns     = [genData_AttackPattern(data)]
    # objBehavior.malware_instances = genObject_Malware(data)
    # objBehavior.exploits          = [genObject_Exploit(data)]

    return(objBehavior)

def genData_STIXHeader(data):
    from stix.core    import STIXHeader
    #from stix.common.vocabs import PackageIntent
    objHdr = STIXHeader()
    objHdr.title           = data['source']['stix.core.stix_header.STIXHeader.title']
    objHdr.description     = data['source']['stix.core.stix_header.STIXHeader.description']
    objHdr.package_intents = data['source']['stix.core.stix_header.STIXHeader.package_intents']
    objHdr.profiles        = data['source']['stix.core.stix_header.STIXHeader.profiles']

    ### Define/Used outside this function 
    # objHdr.handling = handling
    # objHdr.information_source = information_source

    return(objHdr)

def genData_VictimTargeting(data):
    from stix.common.vocabs         import InformationType, SystemType
    from stix.common.identity       import Identity 
    
    from stix.ttp.victim_targeting  import VictimTargeting
    objVictimTargeting = VictimTargeting()
    objVictimTargeting.identity = Identity(name=data['target'])

    objVictimTargeting.targeted_systems     = [SystemType.TERM_USERS]
    objVictimTargeting.targeted_information = InformationType.TERM_INFORMATION_ASSETS_USER_CREDENTIALS
    

    return(objVictimTargeting)

def genObject_TTP(data):
    from stix.utils                 import create_id as StixID 
    from stix.ttp                   import TTP
    from stix.common.vocabs         import IntendedEffect

    objTTP = TTP()
    objTTP.idref = None
    objTTP.title             = "Email Emmbedded URL"
    objTTP.description       = "Target Users via Email by adding a malicious URL"
    objTTP.short_description = "Target Users via Email by adding a malicious URL"
    objTTP.behavior          = genData_Behavior(data)
    objTTP.related_ttps      = None
    ### _ALLOWED_VALUES = ('Advantage', 'Advantage - Economic', 'Advantage - Military', 'Advantage - Political', 'Theft', 'Theft - Intellectual Property', 'Theft - Credential Theft', 'Theft - Identity Theft', 'Theft - Theft of Proprietary Information', 'Account Takeover', 'Brand Damage', 'Competitive Advantage', 'Degradation of Service', 'Denial and Deception', 'Destruction', 'Disruption', 'Embarrassment', 'Exposure', 'Extortion', 'Fraud', 'Harassment', 'ICS Control', 'Traffic Diversion', 'Unauthorized Access')
    objTTP.intended_effects  = data['source']['stix.ttp.TTP.intended_effects']


    # objTTP.resources          = None
    # objTTP.victim_targeting   = None
    # objTTP.information_source = None
    # objTTP.exploit_targets    = None
    # objTTP.handling           = None

    return(objTTP)

def genObject_MarkingSpecification(data=None):

    from stix.extensions.marking.terms_of_use_marking import TermsOfUseMarkingStructure
    objTOU = TermsOfUseMarkingStructure()
    try:
        objTOU.terms_of_use = open('tou.txt').read()
    except:
        objTOU.terms_of_use = None;    

    from stix.extensions.marking.simple_marking import SimpleMarkingStructure
    objSimpleMarkingStructure = SimpleMarkingStructure()
    objSimpleMarkingStructure.statement = data['source']["stix.extensions.marking.simple_marking.SimpleMarkingStructure.statement"]


    from stix.extensions.marking.tlp            import TLPMarkingStructure
    objTLP = TLPMarkingStructure()
    objTLP.color = data['source']['stix.extensions.marking.tlp.TLPMarkingStructure.color']

    from stix.data_marking                import MarkingSpecification
    objMarkingSpecification = MarkingSpecification()
    objMarkingSpecification.idref = None
    objMarkingSpecification.version = None
    objMarkingSpecification.marking_structures = []

    objMarkingSpecification.marking_structures.append(objSimpleMarkingStructure)
    objMarkingSpecification.marking_structures.append(objTLP)
    objMarkingSpecification.marking_structures.append(objTOU)

    ### Externally Modified
    # objMarkingSpecification.controlled_structure = None

    return(objMarkingSpecification)

def genObject_Indicator(data):
    from stix.indicator   import Indicator

    try: 

        sTitle  = "phishTank.com id:" + data['phish_id'] + " with malicious URL:" + data['url']
        sTitle = sTitle[:70] + "..."
    except:
        sTitle  = "phishTank.com id:" + data['phish_id'] + " with malicious URL:--[URL Not Displayed - Due to encoding issue]--"  

    # try: 
    #     sDscrpt = "This URL:[" + escape(unicode(srcDict[item]['url'])) + "] was identified by phishtank.com as part of a phishing email"
    # except:
    #     sDscrpt = "This URL:--[URL Not Displayed - Due to encoding issue]--  was identified by phishtank.com as part of a phishing email"
    sDscrpt = "This URL:[" + escape(data['url']) + "] was identified by phishtank.com as part of a phishing email"

    if data['target'] and not data['target'] == 'Other':
        sDscrpt += " which appears to be targeting " + data['target']
    else:
        sDscrpt += "."
    if data['online'] == 'yes':
        sDscrpt += " This URL appears to still be online as of " + data['verification_time']
    elif data['online'] == 'no':
        sDscrpt += " This URL appears to offline as of " + data['verification_time'] 
    sDscrpt += ". More detailed infomation can be found at " + data['phish_detail_url']
    
    objIndicator = Indicator();
    objIndicator.idref = None           
    
    objIndicator.title = sTitle
    objIndicator.description = "<![CDATA[" + sDscrpt + "]]>"
    objIndicator.short_description = "<![CDATA[" + sTitle + "]]>"
    if data['verified'] == 'yes':
        objIndicator.confidence = 'High'
    else:
        objIndicator.confidence = 'Low' 

    objIndicator.test_mechanisms = None
    objIndicator.alternative_id = None
    objIndicator.composite_indicator_expression = None
    objIndicator.valid_time_positions = None
    objIndicator.related_indicators = None

    # objIndicator.suggested_coas = SuggestedCOAs()
    # objIndicator.kill_chain_phases = KillChainPhasesReference()
    # objIndicator.likely_impact = None

    ### Used/Defined Outside this funtion 
    # objIndicator.indicator_types = ["URL Watchlist"]
    # objIndicator.observable_composition_operator = "OR"
    # objIndicator.producer = None
    # objIndicator.observables = obsList
    # objIndicator.handling = objMarking
    # objIndicator.sightings = None
    # objIndicator.set_received_time

    return(objIndicator)

def genObject_URI(data):
    from cybox.core.observable      import Observables, Observable
    from cybox.utils                import create_id as CyboxID
    from cybox.objects.uri_object   import URI

    objURI = URI()
    objURI.idref = None
    objURI.properties = None
    objURI.related_objects = []
    objURI.domain_specific_object_properties = None
    objURI.value =  escape(unicode(data['url']))
    objURI.value.condition = 'Equals'
    objURI.type_ = "URL"

    obsURI = Observable(objURI)
    obsURI.idref = None
    obsURI.object = None
    objURI = None
    obsURI.title = "URL: " + escape(unicode(data['url']))[:70] + "..."
    # sDscrpt = "URL: " + data['url'] + "| isOnline:" + data['online'] + "| dateVerified:" + data['verification_time']
    # obsURI.description = "<![CDATA[" + sDscrpt + "]]>"
    # try: 
    #     obsURI.description = "URL: " + escape(unicode(data['url'])) + "| isOnline:" + data['online'] + "| dateVerified:" + data['verification_time']
    # except:
    #     obsURI.description = "URL: " + " --[URL Not Displayed - Due to encoding issue]-- " + "| isOnline:" + data['online'] + "| dateVerified:" + data['verification_time']
    obsURI.description = "URL: " + escape(data['url']) + "| isOnline:" + data['online'] + "| dateVerified:" + data['verification_time']

    obsURI.event = None
    obsURI.observable_composition = None
    obsURI.sighting_count = 1
    obsURI.observable_source = []

    return(obsURI) 

#####################################
### ---[ Untility Functions]---
def getRmt_data(srcData):
    from lib.utils.mngRmtObjs  import getRmt_File
    getRmt_File(srcData.srcCreds,  srcData.filePath + srcData.fileName)
    return();

def genHash_md5(data):
    import hashlib
    objHash = hashlib.md5()
    objHash.update(str(data))
    return(objHash.hexdigest())

def isMatch_md5(extHash,newData):
    newHash = genHash_md5(newData)
    if extHash == newHash:
        return(True)
    return(False)

def genRefObs(data):
    from cybox.core.observable      import Observable
    refObs = Observable()
    refObs.id_ = None
    refObs.idref=data.id_
    return(refObs)

def cnvt_csv2dict(srcData):
    ### Specific to this Adapter
    from lib.utils.cnvtFiles    import cnvt_CSV2Dict
    from lib.utils.mngFiles     import clsCSVDialect

    ### Convert CSV File to a Dictionary Object
    oDialect = clsCSVDialect()
    oDialect.from_dict(srcData.parsearg) # Pull Dialect configuration from clsDataSource() object
    tmpDict = cnvt_CSV2Dict(srcData.filePath + srcData.fileName,dialect=oDialect)

    return(tmpDict)

def getDB_local(srcData):
    from lib.utils.mngFiles     import getFile_JSON2Dict
    localDB = 'db_' + srcData.fileName.split('.')[0] + '.json'

    tmpDict = getFile_JSON2Dict(srcData.filePath + localDB);
    if tmpDict:
        return(tmpDict)
    else:    
        tmpDict = getFile_JSON2Dict(srcData.filePath + 'db_pattern.json')
        return(tmpDict)

def setDB_local(dictData,srcData):
    from lib.utils.mngFiles     import sndFile_Dict2JSON
    localDB = 'db_' + srcData.fileName.split('.')[0] + '.json'
    sndFile_Dict2JSON(dictData,localDB);        
    return();

def updateDB_local(data,srcData):
    from lib.utils.mngFiles     import sndFile_Dict2JSON
    db = getDB_local(srcData)
    
    db = dict(data.items() + db.items())

    localDB = 'db_' + srcData.fileName.split('.')[0] + '.json'
    sndFile_Dict2JSON(db,localDB);
    return();    

if __name__ == "__main__":
    main()    
    
#EOF 