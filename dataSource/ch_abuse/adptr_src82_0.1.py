__author__ = 'mrp'

'''
    The is a source adapter.
    to convert Non-STIX source data into STIX complaint xml
'''

import os
import sys

sys.path.insert(0, '../../')
from lib.utils.mngMSG import sndMSG
from stix.utils import set_id_namespace as stix_set_id_namespace
from cybox.utils import set_id_namespace as cybox_set_id_namespace
from cybox.utils import Namespace


def main():
    from lib.utils.mngFiles import getFile_Source2Dict
    from lib.utils.mngRmtObjs import getRmt_data
    from lib.utils.mngSources_r01 import clsDataSource

    dst_creds = {
        "URI": "http://172.16.167.147/taxii-discovery-service",
        "usrName": "admin",
        "usrPass": "avalanche",
        "crtName": "",
        "crtPass": ""
    }

    src_data = clsDataSource(iID=82)
    src_data.chnkSize = 250
    src_data.dstCreds = dst_creds
    src_data.filePath = os.path.dirname(os.path.abspath(__file__)) + '/'
    src_data.from_dict(getFile_Source2Dict('../../data/db_sourceList.json', src_data.ID))

    sndMSG('---[ Start: Src_' + str(src_data.ID) + ' ]---', 'INFO', 'main()')
    # // Get Source data from Producer's Site
    # sndMSG('---< NOT UPDATING >--- ','INFO')
    # getRmt_data(src_data)

    # ---[ Extract / Transform / Load ]---
    dictObj = extract_asDict(src_data, process_NewDataOnly=True)

    return 0


#####################################
# ---[ ETL Functions ]---

def extract_asDict(src_data, process_NewDataOnly=True):
    sndMSG('Called...', 'INFO', 'extract_as_dict()')
    assert isinstance(src_data, object)

    # // Get Local Data - Used to Remove duplicates
    lcl_data = getDB_local(src_data)

    from lib.utils import feedparser
    items = feedparser.parse(src_data.srcCreds['URI'])
    print len(items['entries'])

    #print items['entries'][0]
    import pprint

    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(items['entries'][0])
    sys.exit(0)

#####################################
# ---[ Utility Functions]---

def getRmt_data(src_data):
    from lib.utils.mngRmtObjs import getRmt_File
    getRmt_File(src_data.srcCreds,  src_data.filePath + src_data.fileName)
    return 0


def getDB_local(src_data):
    from lib.utils.mngFiles import getFile_JSON2Dict
    localdb = 'db_' + src_data.fileName.split('.')[0] + '.json'

    tmp = getFile_JSON2Dict(src_data.filePath + localdb)
    if tmp:
        return tmp
    else:
        tmp = getFile_JSON2Dict(src_data.filePath + 'db_pattern.json')
        return tmp

if __name__ == "__main__":
    main()

    # EOF