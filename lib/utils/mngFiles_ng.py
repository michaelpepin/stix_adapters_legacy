 
"""
#
#   ### -----< File Managment Public Functions >-----
#   sndfile_dict2json,  return Boolean Object

#   ### -----< File Managment Classes >-----
#   clsCSVDialect,  return None         #Create Dailect Object in support of getFile_CSV()
#   
### 

### -----< Public - File Managment Functions >-----
"""

import os
import sys
import json

from adapters.lib.utils.mngMSG_ng import log



def getfile_json2dict(path):
    """

    :param path:
    :return:
    """

    try:
        with open(path, "r") as infile:
            data = json.load(infile)
        return data

    except IOError as e:
        msg = str("\--> I/O error({0}): {1}".format(e.errno, e.strerror))
        log(msg, 'INFO', sys._getframe())

    except:
        msg = "\--> Unexpected error: " + str(sys.exc_info()[0])
        log(msg, 'INFO', sys._getframe())

    return None

def sndfile_dict2json(data, path, pretty=False):
    """
        sndfile_dict2json -
    :param data: <dictionary>
    :param path: <string>
    :param pretty: <boolean>
    :return: <boolean>
    """

    try:
        with open(path, "w") as outfile:
            if pretty:
                json.dump(data, outfile)
            else:
                json.dump(data, outfile, indent=4)
            return True

    except IOError as e:
        msg = str("I/O error({0}): {1}".format(e.errno, e.strerror))
        log(msg, 'ERROR', sys._getframe())

    except:
        msg = "Unexpected error: " + str(sys.exc_info()[0])
        log(msg, 'ERROR', sys._getframe())

    return False

def chk_file(path, create=False, line=None):
    """

    :param path:
    :param create:
    :param line:
    :return:
    """
    bFlag = os.path.isfile(path)

    if bFlag:
        return True

    if bFlag is False and create is True:
        with open(path, 'a') as f:
            os.utime(path, None)
            if line:
                f.write(line)

        if os.path.isfile(path):
            return True
