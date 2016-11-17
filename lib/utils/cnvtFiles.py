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
from mngFiles import sndFile_Dict2JSON

from mngMSG   import sndMSG
from adapters.lib.utils.mngMSG_ng import log


def cnvt_xmlL2dict(src,dstFile=None):
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
        return sndFile_Dict2JSON(data, dstFile)

    return data


def cnvt_XML2Dict(srcXML,dstFile=None):

    '''
    {Description}
    
    Keyword arguments: 
   
    Returns:
    '''

    import urllib2
    import xmltodict
    
    ### Setup function
    sFuncName = 'cnvt_XML2Dict'
    if not srcXML:
        sTxt = 'XML Source Required'
        return(None)
        
    if not "http" in srcXML:
        srcXML = "file://" + srcXML         
    
    #rssData = urllib2.urlopen(srcXML).read()

    try:    
        rssData = urllib2.urlopen(srcXML).read()
    except IOError as e:
        sTxt = str("\--> I/O error({0}): {1}".format(e.errno, e.strerror))
        sndMSG(sTxt,'ERROR',sFuncName)
        return(None)
    except:
        sTxt = "\--> Unexpected error: " + str(sys.exc_info()[0])
        sndMSG(sTxt,'ERROR',sFuncName)
        return(None)
    
    #dataDict = xmltodict.parse(rssData)
    try:          
        dataDict = xmltodict.parse(rssData)
        pass
    except IOError as e:
        sTxt = str("\--> I/O error({0}): {1}".format(e.errno, e.strerror))
        sndMSG(sTxt,'ERROR',sFuncName)
        return(None)
    except:
        sTxt = "\--> Unexpected error: " + str(sys.exc_info()[0])
        sndMSG(sTxt,'ERROR',sFuncName)
        return(None)
        
    if dstFile:
        return(sndFile_Dict2JSON(dataDict,dstFile))
    else:
        return(dataDict)     
        
    return(None)
    
    
def cnvt_HTML2Dict(srcHTML,sArg,dstFile=None):
    '''
    {Description}
    
    Keyword arguments: 
   
    Returns:
    '''
    from lxml import html
    import urllib2
    
    if not srcHTML or not sArg:
        sTxt = 'Both HTML source and Parsing Arguments required'
        return(None)
        
    dataPage = urllib2.urlopen(srcHTML).read()
    dataTree = html.fromstring(dataPage)
    dataDict = dataTree.xpath(sArg)
    
    if dstFile:
        return(sndFile_Dict2JSON(dataDict,dstFile))
    else:
        return(dataDict)
        
    return(None)
    
def cnvt_CSV2Dict(srcCSV,dialect=None,sCommentFlag=None, strEncoding=None):
    _sFuncName = 'cnvtFiles.cnvt_CSV2Dict'
    sTxt = "Called... "
    sndMSG(sTxt,'INFO',_sFuncName)

    bDebug = False

    if srcCSV == None or dialect == None:
        return(None)
    
    if sCommentFlag == None:
        sCommentFlag = '#'
    
    if strEncoding == None:
        strEncoding = 'utf-8'
    
    if dialect.header == True:
        #TODO: Change Col header from number to Header Names
        
        pass
    
    if bDebug:
        sTxt = "\--[ CSV File Location ]--> " + str(srcCSV)
        sndMSG(sTxt,'INFO',_sFuncName)

    with open(srcCSV, 'rb') as dataSrc:

        if dataSrc == None:
            return(None)
        

        if bDebug:
            sTxt = "\--[ input File charCnt ]--> " + str(len(dataSrc.read()))
            sndMSG(sTxt,'INFO',_sFuncName)

        dataSrc.seek(0)
        data = csv.reader(dataSrc, dialect=dialect)
        if bDebug:
            sTxt = "\--[ output CSV RowCnt ]--> " + str(data)
            sndMSG(sTxt,'INFO',_sFuncName)

        csvDict = {}
        listHeaders = []
        iRow = 0
        iCol = 0
        
        for row in data:

            if len(row) < 1:
                continue

            if sCommentFlag in str(row[0]):
                continue
                
            if dialect.header == True and len(listHeaders) < 1:
                listHeaders = row
                continue
                
            csvDict.update({iRow:{}})
            for col in row:
                try:
                    col = unicode(col, strEncoding)
                except:
                    col = " (NOTE: This data was modified from origin, due to non " + strEncoding + " compatiable chars) " + unicode(col, "utf-8", errors='ignore' )

                if len(listHeaders) > 1:
                    csvDict[iRow].update({listHeaders[iCol]:col})
                else:    
                    csvDict[iRow].update({iCol:col})
                 
                iCol += 1
            
            iCol = 0    
            iRow +=1 
            
    if bDebug:
        sTxt = "\--[ output Dict RowCnt ]--> " + str(len(csvDict))
        sndMSG(sTxt,'INFO',_sFuncName)

    dataSrc.close 
    return(csvDict)       
