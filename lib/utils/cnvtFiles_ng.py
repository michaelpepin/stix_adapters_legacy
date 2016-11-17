#!/usr/bin/env python

###
#
#   ### -----< Convert Files Public Functions >-----
#   cnvt_XML2Dict,      return Dictionary Object OR Boolean on file creation
#   cnvt_HTML2Dict,     return Dictionary Object OR Boolean on file creation
#
#   ### -----< Convert Files Classes >-----
#   
### 

import os
import sys
import csv, codecs, cStringIO
from mngFiles_ng import sndfile_dict2json

from adapters.lib.utils.mngMSG_ng import log


def cnvt_xml2dict(src, dstFile=None):
    """
    :param src: <string> source to process
                    this src can a remote source "https://opensource.rss"
                    or local source "file://opensource.xml"
    :param dstFile: Optional <string>
    :return: <dict> return a dictionary of the src's XML data
    """

    import urllib2
    import xmltodict

    if src:
        if not '://' in src:
            src = 'file://%s' % src
    else:
        return None

    try:
        data = urllib2.urlopen(src).read()
        log("opened: %s" % src, 'INFO', sys._getframe())

    except IOError as e:
        msg = str("\--> I/O error({0}): {1}".format(e.errno, e.strerror))
        log(msg, 'ERROR', sys._getframe())
        return None

    except:
        msg = "\--> Unexpected error: " + str(sys.exc_info()[0])
        log(msg, 'ERROR', sys._getframe())
        return None

    try:
        data = xmltodict.parse(data)

    except IOError as e:
        msg = str("\--> I/O error({0}): {1}".format(e.errno, e.strerror))
        log(msg, 'ERROR', sys._getframe())
        return None
    except:
        msg = "\--> Unexpected error: " + str(sys.exc_info()[0])
        log(msg, 'ERROR', sys._getframe())
        return None

    if dstFile:
        sndfile_dict2json(data, dstFile)

    return data




