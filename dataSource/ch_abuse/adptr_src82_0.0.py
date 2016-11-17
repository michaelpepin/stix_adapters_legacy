#!/usr/bin/env python

import os
import sys
from datetime import datetime

sys.path.insert(0, '../../')
### Generally required for all Adapters
from lib.utils.mngMSG import sndMSG
from lib.utils.mngSources import clsDataSource
from lib.utils.mngFiles import getFile_JSON2Dict
from lib.utils.mngRmtObjs import getRmt_File
from lib.utils.mngFiles import sndFile_Dict2JSON, sndFile
from lib.utils.mngDateTime import getUTCTime
from lib.conns.curlTAXII import sndTAXII

from stix.utils import set_id_namespace as stix_set_id_namespace
from stix.indicator import Indicator
from stix.core import STIXPackage, STIXHeader
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.extensions.marking.simple_marking import SimpleMarkingStructure
from stix.extensions.marking.terms_of_use_marking import TermsOfUseMarkingStructure

from cybox.utils import set_id_namespace as obs_set_id_namespace
from cybox.utils import Namespace

### Specifically requried for this Adpater
from lib.utils.mngFiles import trimFile_btwn
from lib.utils.cnvtFiles import cnvt_XML2Dict
from lib.utils.mngMisc import isIPv4, isIPv6, isFQDN, isTLD

from stix.ttp import TTP, Behavior
from stix.ttp.behavior import MalwareInstance

from cybox.core.observable import Observable
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName



def main():
    sourceid = 'src_82'

    ### Setup for running as Main and template for use of adptr function
    tmp_json = getFile_JSON2Dict('../../data/openSourceList.json')
    tmp_dict = None

    for sKey in tmp_json:
        if tmp_json[sKey]['srcIndex'] == sourceid:
            tmp_dict = tmp_json[sKey]


    ### Without a valide Source Meta data this function will exit
    if tmp_dict is None:
        return False

    ### This infomation is only require if you wish upload this data
    ###     to a TAXII Server

    dst_creds = {
        "URI": "http://172.16.167.147/taxii-discovery-service",
        "usrName": "admin",
        "usrPass": "avalanche",
        "crtName": "",
        "crtPass": ""
    }


    ### The adpter function requires clsDataSource object populated
    ###     with a minimum of data 
    src_data = clsDataSource(isDebugOn=True)
    src_data.from_dict(tmp_dict)
    src_data.chnkSize = 500  # This version does not make use of the chucking capability
    src_data.dstCreds = dst_creds
    src_data.filePath = os.path.dirname(os.path.abspath(__file__)) + '/'

    ### Extract(src2Dict) Transform(dict2STIX) Load(sndTAXII)
    dict_obj = adptr_src2Dict(src_data, True)
    if not dict_obj == False:
        stix_obj = adptr_dict2STIX(src_data, dict_obj)
        if not stix_obj == False:
            pass

    return 0


def adptr_src2Dict(src_data, isUpdateNewDataOnly):
    namefunc = 'adptr_src2Dict()'
    stxt = "Called... "
    sndMSG(stxt, 'INFO', namefunc)

    ### Input Check    
    if src_data is None:
        # TODO: Needs error msg: Missing srcData Object
        return False

    locDataFile = 'db_' + src_data.fileName.split('.')[0] + '.json'

    ### fetch from Source location for newest version
    # srcData.getSrcData();   #TODO: This function in the clsDataSource is not completed
    # so this getRmt_File is used until class is completed

    # print "------< NOT UPDATING >------"
    if not getRmt_File(src_data.srcCreds,
                       src_data.filePath +
                               src_data.fileName) == True:
        # if no source data is found, this script will exit
        return False

    dstData = getFile_JSON2Dict(locDataFile)
    if not dstData:
        dstData = {}

    ### Here the code become specific (unique) this data source
    ###     in time I hope to refactor out as much unique as possible


    trimFile_btwn(src_data.filePath + src_data.fileName,
                  '<?xml version="1.0" encoding="ISO-8859-1" ?>',
                  '</rss>')

    srcDict = cnvt_XML2Dict(src_data.filePath + src_data.fileName)

    ### DEBUG CODE ####


    ###################



    src_data.pkgTitle = srcDict['rss']['channel']['title']
    src_data.pkgDscrpt = srcDict['rss']['channel']['description']
    src_data.pkgLink = srcDict['rss']['channel']['link']

    newData = {}
    for col in srcDict['rss']['channel']['item']:
        sKey = col['guid']

        sCol = col['title']
        sDateVF = sCol.split('(')[1]
        sDateVF = sDateVF[0:-1]
        try:
            dSrt = datetime.strptime(sDateVF, "%Y-%m-%d %H:%M:%S")
            sDateVF = dSrt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except:
            sDateVF = None

        sDomain = None
        sIPAddr = cleanString(sCol.split('(')[0])
        if not isIPv4(sIPAddr):
            sDomain = sIPAddr
            sIPAddr = None

        sCol = col['description']
        lstAttrib = sCol.split(',')

        dictAttrib = {
            "dateVF": sDateVF,
            "title": cleanString(col['title']),
            "link": cleanString(col['link']),
            "dscrpt": cleanString(col['description']),
            "ipAddr": sIPAddr,
            "domain": sDomain,
        }

        if sKey in dstData:
            dstData[sKey]['cnt'] += 1
            dstData[sKey]['dateDL'] = getUTCTime()

            # TODO:Check If Exist Element's inactive status changed

        else:
            ### Add new Data to local Database
            dstData[sKey] = {'cnt': 1, 'dateDL': getUTCTime()}
            dstData[sKey]['attrib'] = dictAttrib

            ### Generate list of new data only for STIX output
            newData[sKey] = dstData[sKey]

    sndFile_Dict2JSON(dstData, locDataFile)

    if not isUpdateNewDataOnly:
        newData = dstData

    if len(newData) > 0:
        stxt = "Found " + str(len(newData)) + " new data elements"
        sndMSG(stxt, 'INFO', namefunc)

    else:
        stxt = "Found no new data"
        sndMSG(stxt, 'INFO', namefunc)
        newData = False

    return newData


def adptr_dict2STIX(srcObj, data):
    sTxt = "Called... "
    sndMSG(sTxt, 'INFO', 'adptr_dict2STIX()')

    ### Input Check
    if srcObj is None or data is None:
        # TODO: Needs error msg: Missing srcData Object
        return False

    ### Generate NameSpace id tags
    STIX_NAMESPACE = {"http://hailataxii.com": "opensource"}
    OBS_NAMESPACE = Namespace("http://hailataxii.com", "opensource")
    stix_set_id_namespace(STIX_NAMESPACE)
    obs_set_id_namespace(OBS_NAMESPACE)

    ### Building STIX Wrapper
    stix_package = STIXPackage()

    ### Bulid Object Data
    for sKey in data:
        objIndicator = Indicator()
        listOBS = []

        ### Parsing IP Address
        sAddr = data[sKey]['attrib']['ipAddr']
        if sAddr:
            objAddr = Address()
            objAddr.is_source = True
            objAddr.address_value = sAddr
            objAddr.address_value.condition = 'Equals'
            if isIPv4(sAddr):
                objAddr.category = 'ipv4-addr'
            elif isIPv6(sAddr):
                objAddr.category = 'ipv6-addr'
            else:
                continue

            obsAddr = Observable(objAddr)
            obsAddr.sighting_count = 1
            obsAddr.title = 'IP: ' + sAddr
            sDscrpt = 'IPv4' + ': ' + sAddr + " | "
            sDscrpt += "isSource: True | "
            obsAddr.description = "<![CDATA[" + sDscrpt + "]]>"
            listOBS.append(obsAddr)
            objIndicator.add_indicator_type("IP Watchlist")

            ### Parsing Domain
        sDomain = data[sKey]['attrib']['domain']
        if sDomain:
            objDomain = DomainName()
            objDomain.value = sDomain
            objDomain.value.condition = 'Equals'
            if isFQDN(sDomain):
                objDomain.type = 'FQDN'
            elif isTLD(sDomain):
                objDomain.type = 'TLD'
            else:
                continue

            obsDomain = Observable(objDomain)
            obsDomain.sighting_count = 1
            obsDomain.title = 'Domain: ' + sDomain
            sDscrpt = 'Domain: ' + sDomain + " | "
            sDscrpt += "isFQDN: True | "
            obsDomain.description = "<![CDATA[" + sDscrpt + "]]>"
            listOBS.append(obsDomain)
            objIndicator.add_indicator_type("Domain Watchlist")


        # Parser File Hash
        # sHash = data[sKey]['attrib']['hash'];
        # if len(sHash) > 0:  
        # objFile = File()
        # sFileName = data[sKey]['attrib']['fileName']
        # if len(sFileName) > 0:
        # objFile.file_name   = sFileName
        # objFile.file_format = sFileName.split('.')[1]

        # objFile.add_hash(Hash(sHash, exact=True))
        # obsFile = Observable(objFile)
        # objFile = None;
        # obsFile.sighting_count = 1
        # obsFile.title = 'File: ' + sFileName
        #     sDscrpt = 'FileName: ' + sFileName + " | "
        #     sDscrpt += "FileHash: " + sHash + " | "
        #     obsFile.description = "<![CDATA[" + sDscrpt + "]]>" 
        #     listOBS.append(obsFile)
        #     obsFile = None;
        #     objIndicator.add_indicator_type("File Hash Watchlist")


        ### Add Generated observable to Indicator
        objIndicator.observables = listOBS
        objIndicator.observable_composition_operator = 'OR'

        #Parsing Producer
        sProducer = srcObj.Domain
        if len(srcObj.Domain) > 0:
            objIndicator.set_producer_identity(srcObj.Domain)

        if data[sKey]['attrib']['dateVF']:
            objIndicator.set_produced_time(data[sKey]['attrib']['dateVF'])
        objIndicator.set_received_time(data[sKey]['dateDL'])

        ### Old Title / Description Generator
        #objIndicator.title = data[sKey]['attrib']['title'];
        #objIndicator.description = "<![CDATA[" + data[sKey]['attrib']['dscrpt'] + "]]>";

        ### Generate Indicator Title based on availbe data
        sTitle = 'Feodo Tracker: '
        if sAddr:
            sAddLine = "This IP address has been identified as malicious"
        if sDomain:
            sAddLine = "This domain has been identified as malicious"
        if len(sAddLine) > 0:
            sTitle += " | " + sAddLine
        if len(srcObj.Domain) > 0:
            sTitle += " by " + srcObj.Domain
        else:
            sTitle += "."
        if len(sTitle) > 0:
            objIndicator.title = sTitle

        #Generate Indicator Description based on availbe data
        sDscrpt = ""
        if sAddr:
            sAddLine = "This IP address " + sAddr
        if sDomain:
            sAddLine = "This domain " + sDomain
        if sAddr and sDomain:
            sAddLine = "This domain " + sDomain + " (" + sAddr + ")"
        if len(sAddLine) > 0:
            sDscrpt += sAddLine

        sDscrpt += " has been identified as malicious"
        if len(srcObj.Domain) > 0:
            sDscrpt += " by " + srcObj.Domain
        else:
            sDscrpt += "."
        sDscrpt = sDscrpt + ". For more detailed infomation about this indicator go to [CAUTION!!Read-URL-Before-Click] [" + \
                  data[sKey]['attrib']['link'] + "]."

        if len(sDscrpt) > 0:
            objIndicator.description = "<![CDATA[" + sDscrpt + "]]>"

        #Parse TTP
        objMalware = MalwareInstance()
        objMalware.add_name("Cridex")
        objMalware.add_name("Bugat")
        objMalware.add_name("Dridex")
        objMalware.add_type("Remote Access Trojan")
        objMalware.short_description = "Feodo (also known as Cridex or Bugat) is a Trojan used to commit ebanking fraud and steal sensitive information from the victims computer, such as credit card details or credentials"

        sDscrpt = "Feodo (also known as Cridex or Bugat) is a Trojan used to commit ebanking fraud and steal sensitive information from the victims computer, such as credit card details or credentials. At the moment, Feodo Tracker is tracking four versions of Feodo, and they are labeled by Feodo Tracker as version A, version B, version C and version D:\n"
        sDscrpt += "\n"
        sDscrpt += "  Version A: Hosted on compromised webservers running an nginx proxy on port 8080 TCP forwarding all botnet traffic to a tier 2 proxy node. Botnet traffic usually directly hits these hosts on port 8080 TCP without using a domain name.\n"
        sDscrpt += "  Version B: Hosted on servers rented and operated by cybercriminals for the exclusive purpose of hosting a Feodo botnet controller. Usually taking advantage of a domain name within ccTLD .ru. Botnet traffic usually hits these domain names using port 80 TCP.\n"
        sDscrpt += "  Version C: Successor of Feodo, completely different code. Hosted on the same botnet infrastructure as Version A (compromised webservers, nginx on port 8080 TCP or port 7779 TCP, no domain names) but using a different URL structure. This Version is also known as Geodo.\n"
        sDscrpt += "  Version D: Successor of Cridex. This version is also known as Dridex\n"
        objMalware.description = "<![CDATA[" + sDscrpt + "]]>"

        objTTP = TTP(title="Feodo")
        objTTP.behavior = Behavior()
        objTTP.behavior.add_malware_instance(objMalware)
        objIndicator.add_indicated_ttp(objTTP)
        #objIndicator.add_indicated_ttp(TTP(idref=objTTP.id_))   
        #stix_package.add_ttp(objTTP)    

        stix_package.add_indicator(objIndicator)

        ### STIX Package Meta Data
    stix_header = STIXHeader()
    stix_header.title = srcObj.pkgTitle
    stix_header.description = "<![CDATA[" + srcObj.pkgDscrpt + "]]>"

    ### Understanding markings http://stixproject.github.io/idioms/features/data-markings/
    marking_specification = MarkingSpecification()

    classLevel = SimpleMarkingStructure()
    classLevel.statement = "Unclassified (Public)"
    marking_specification.marking_structures.append(classLevel)

    objTOU = TermsOfUseMarkingStructure()
    sTOU = open('tou.txt').read()
    objTOU.terms_of_use = srcObj.Domain + " | " + sTOU
    marking_specification.marking_structures.append(objTOU)

    tlp = TLPMarkingStructure()
    tlp.color = "WHITE"
    marking_specification.marking_structures.append(tlp)
    marking_specification.controlled_structure = "//node()"

    handling = Marking()
    handling.add_marking(marking_specification)
    stix_header.handling = handling

    stix_package.stix_header = stix_header

    ### Generate STIX XML File
    locSTIXFile = 'STIX_' + srcObj.fileName.split('.')[0] + '.xml'
    sndFile(stix_package.to_xml(), locSTIXFile)

    return stix_package


def cleanString(sData):
    sData = str(sData)
    sData = sData.strip(' \t\n\r')
    return sData


if __name__ == "__main__":
    main()

# EOF
