 
"""
#
#   ### -----< File Managment Public Functions >-----
#   getFile_asOBJ,      retrun File Object
#   getFile_CSV2List,   return List Object 
#   getFile_JSON2Dict,  return Dictionary Object
#   sndFile_Dict2JSON,  return Boolean Object
#   getFile_Source2Dict,return Dictionary Object
#
#   ### -----< File Managment Classes >-----
#   clsCSVDialect,  return None         #Create Dailect Object in support of getFile_CSV()
#   
### 

### -----< Public - File Managment Functions >-----
"""

import os
import sys
from mngMSG import sndMSG


def getFile_lineByNumber(sFile,iLine):
    
    if not sFile or not iLine: return(None)

    #objFile = _getFile_OBJ(sFile)

    with open(sFile) as data:
        lines   = data.readlines()
        rtnLine   = lines[iLine]
        lines   = None    
        data.close()

    return(rtnLine)    
    
def getFile_lineByValue(sFile,sLine):
    
    if not sFile or not sLine: return(None)

    #objFile = _getFile_OBJ(sFile)
    lstLines = []
    with open(sFile) as data:
        lines   = data.readlines()
        
        for line in lines:
            if sLine in line:
               lstLines.append(line)
        
        lines   = None    
        data.close()

    return(lstLines)    

def getFile_asOBJ(sFile):
    """
    Public Interface for the mngFiles._getFile_OBJ function
    """
    sFuncName = 'mngFiles.getFile_asOBJ'
    objFile = _getFile_OBJ(sFile)
    if objFile == None:
            return(None)
    return(objFile)

def getFile_Source2Dict(sFile,iID):
    tmpDict = None
    tmpDict = getFile_JSON2Dict(sFile)

    if tmpDict:
        for sKey in tmpDict:
            for link in tmpDict[sKey]['attrib']['srcLinks']:
                if iID == link['iID']:
                    dictData = link
                    break
    else:
        return(None)        

    return(dictData)
    
                                                 
def getFile_CSV2List(sFile,dialect=None,sCommentFlag=None):
    """
    Opens received File and parses it based on the received dialect
    
    Keyword arguments: 
    sFile -- File Path and File name to be parsed
        exmple: ./test/test.csv
    dialect -- Is an instantiates of mngLoc_File.clsCSVDialect 
        containing the CSV parsing parameters
    sCommentChar -- Is char that begins a line to be ingnored
    
    Returns:
        List object containing a List for each line 
        example:
        [['date','ip1','domain1'],
         ['date','ip2','domain2']
        ]
    """

    import csv
    sFuncName = 'mngFiles.getFile_CSV2List'
    sTxt = "Attemping to parse file as CSV: " + sFile
    sndMSG(sTxt,'INFO',sFuncName)
    
    if dialect == None:
        sTxt = "\--> NOTE: No csv dialect was passed, default parsing is by comma "
        sndMSG(sTxt,'INFO',sFuncName)
         
    if sCommentFlag == None: 
        sCommentFlag = '#'
        sTxt = "\--> NOTE: No comment flag was passed, default is '#' "
        sndMSG(sTxt,'INFO',sFuncName)
    
    try:     
        #objFile = _getFile_OBJ(sFile)
        objFile = open(sFile)
        if objFile == None:
            return(None)
        data = csv.reader(objFile, dialect)
        sList = []
        for line in data:
            if sCommentFlag in str(line):
                # TODO: Needs better comment handling, 
                # As is it will remove line in line comments 
                # this need to be fixed to just remove commented section 
                # and still keep the data before it
                continue 
            sList.append(line)
        #sList.sort()
        objFile.close 
        return(sList)
    except IOError as e:
        sTxt = str("\--> I/O error({0}): {1}".format(e.errno, e.strerror))
        sndMSG(sTxt,'ERROR',sFuncName)
        return(None)
    except:
        sTxt = "\--> Unexpected error: " + str(sys.exc_info()[0])
        sndMSG(sTxt,'ERROR',sFuncName)
        return(None)


def getfile_json2dict(sFile):
    return getFile_JSON2Dict(sFile)


def getFile_JSON2Dict(sFile):
    '''
    {Description}
    Keyword arguments: 
    Returns:
    '''
    import json
    sFuncName = 'mngFiles.getFile_JSON2Dict'
    sTxt = "Attemping to parse file as JSON: " + sFile
    sndMSG(sTxt,'INFO',sFuncName)
        
    
    try:
        
        #json_data = _getFile_OBJ(sFile)
        json_data = open(sFile)
        if json_data == None:
            return(None)   
        data = json.load(json_data)
        json_data.close()
        return(data)
    except IOError as e:
        sTxt = str("\--> I/O error({0}): {1}".format(e.errno, e.strerror))
        sndMSG(sTxt,'ERROR',sFuncName)
        return(None) 
    except:
        sTxt = "\--> Unexpected error: " + str(sys.exc_info()[0])
        sndMSG(sTxt,'ERROR',sFuncName)
        return(None)                                                 


def sndFile_Dict2JSON(sData,sFile,isCompact=False):
    '''
    {Description}
    
    Keyword arguments: 
   
    Returns:
    '''
    import json
    sFuncName = 'mngFiles.sndFile_Dict2JSON'
    sTxt = "Trying to write to this file : " + sFile
    sndMSG(sTxt,'INFO',sFuncName)
    
    chkFile(sFile,True)
    
    try:
        with open(sFile, "w") as outfile:
            
            try:
                if isCompact == 'True':
                    json.dump(sData,outfile)
                else:
                    json.dump(sData,outfile, indent=4)
            except:
                sTxt = "Unexpected error: " + str(sys.exc_info()[0])
                sndMSG(sTxt,'ERROR',sFuncName)
                return(False)
        outfile.close()
        return(True)
    except IOError as e:
        sTxt = str("I/O error({0}): {1}".format(e.errno, e.strerror))
        sndMSG(sTxt,'ERROR',sFuncName)
        return(None) 
    except:
        sTxt = "Unexpected error: " + str(sys.exc_info()[0])
        sndMSG(sTxt,'ERROR',sFuncName)
        return(None) 


def sndFile(sData,sFile):
    import sys
    sFuncName = 'mngFiles.sndFile'
    sTxt = "Trying to write to this file : " + sFile
    sndMSG(sTxt,'INFO',sFuncName)
    
    with open(sFile, "w") as outfile:
        for line in sData:
            outfile.write(line)
    outfile.close()
    return(0)


def chk_file(path, create, line):
    """
        chk_file - Check to see if file exists and if not creates the file
    :param path: <string>
    :param create: <boolean>
    :return: <boolean>
    """
    return chkFile(path, create, line)


def chkFile(path, create, line=None):
    
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

    
def decompressor(srcFile,dstFile,cmpFormat):
    _strFuncName = 'mngFiles.decompressor'
    _strFuncVer  = '0.0.0'
    
    if srcFile == None or dstFile == None or cmpFormat == None:
        return(None)
        
    if srcFile:
        sTxt = 'decompressing ' + srcFile
        sndMSG(sTxt,'INFO',_strFuncName)
        return(True)

    return(None)
    
class clsDecompressor():

    def __init__(self):
        self._strClassName = 'clsSourceFile'
        self._strClassVer  = '0.0.0'
        
        self.CompressionTypes = ('gz','zip','bz','tar')    
        
    def decompress(self,srcFile,dstFile,cmpType):
        
        if not cmpType in self.CompressionTypes:
            sTxt = 'Unknown decompress type: ' + cmpType
            sndMSG(sTxt,'ERROR',self._strClassName)
            return(None)
        
        if cmpType == 'gz':
            sTxt = 'Attempting to decompress ' + cmpType + ' file '
            sndMSG(sTxt,'INFO',self._strClassName)
            return(True)

        if cmpType == 'zip':
            sTxt = 'Attempting to decompress ' + cmpType + ' file '
            sndMSG(sTxt,'INFO',self._strClassName)
            return(True)
        
        if cmpType == 'bz':
            sTxt = 'Attempting to decompress ' + cmpType + ' file '
            sndMSG(sTxt,'INFO',self._strClassName) 
            return(True)
            
        if cmpType == 'tar':
            sTxt = 'Attempting to decompress ' + cmpType + ' file '
            sndMSG(sTxt,'INFO',self._strClassName) 
            return(True)  
            
        return(False)    
                 
    pass # End clsDecompressor      
    
def trimFile_btwn(sFile,string_srt,string_end):
    sNAMEFUNC = 'trimFile_btwn'
    sTxt = "Called... " 
    sndMSG(sTxt,'INFO',sNAMEFUNC)

    iCnt = 0
    iSrt = 0
    iEnd = 0
    with open(sFile,'r+') as data:
        lines = data.readlines()

        data.seek(0)
        for line in lines:
            if string_srt in line:
                iSrt = iCnt
            if string_end in line:
                iEnd = iCnt
            iCnt += 1
  
        data.truncate()
        for i in range(iSrt,iEnd+1):
            data.write(lines[i])

        lines = None    
        data.close()

    return(False)
    


### -----< Unitlity Classes >-----
import csv                                                     
class clsCSVDialect(csv.Dialect):
    _version = "0.1"
    '''
    - Extends csv.Dialect class to explicitly set csv parsing parameters
    
    Keyword arguments: 
    
    Returns:
    '''
    def __init__(self):
        self.delimiter = ','
        self.skipinitialspace = True
        self.quotechar = '"'
        self.doublequote = True
        self.quoting = csv.QUOTE_MINIMAL
        self.lineterminator = '\r\n'
        self.header = False
    
    def from_dict(self, dictData):
        
        if dictData == None:
            return(None)
        
        if "delimiter" in dictData:
            self.delimiter = str(dictData["delimiter"])
        if "skipinitialspace" in dictData:
            self.skipinitialspace = dictData["skipinitialspace"]
        if "quotechar" in dictData:
            self.quotechar = dictData["quotechar"]
        if "doublequote" in dictData:
            self.doublequote = dictData["doublequote"]
        if "quoting" in dictData:
            self.quoting = dictData["quoting"] 
        if "lineterminator" in dictData:
            self.lineterminator = dictData["lineterminator"]
        if "header" in dictData:
            self.header = dictData["header"]

    def toDict(self):
        return({
            "delimiter":self.delimiter,
            "skipinitialspace":self.skipinitialspace,
            "quotechar":self.quotechar,
            "doublequote":self.doublequote,
            "quoting":self.quoting,
            "lineterminator":self.lineterminator,
            "header":self.header
            })

        
    pass

    

### -----< Private - File Managment Functions >-----

def _getFile_OBJ(sFile,MAXFILESIZE=None,FILEENCODING=None,sPassFuncName=None):
    """
        Code Broken, do not use
    """
    
    #if sPAssFuncName == None:
    #    sFuncName = 'mngFiles._getFile_OBJ'
    #else:
    #    sFuncName = sPAssFuncName + "(" + sFuncName + ")"
        
    sFuncName = 'mngFiles._getFile_OBJ'
    
    sTxt = "Attemping to open this file: " + sFile
    sndMSG(sTxt,'INFO',sFuncName)
     
    if MAXFILESIZE == None:
        MAXFILESIZE = 1000000000 # => 1GB
    else:
        sTxt = "\--> MAXFILESIZE was changed to: " + MAXFILESIZE
        sndMSG(sTxt,'INFO',sFuncName)
    
    if FILEENCODING == None:  
        FILEENCODING = 'utf-8'
    else:
        sTxt = "\--> FILEENCODING was changed to: " + FILEENCODING
        sndMSG(sTxt,'INFO',sFuncName)
    
    #check Existance of file
    bFlag = os.path.exists(sFile)
    if bFlag == False:
        sTxt = "\--> This file or file path does not exist: " + sFile
        sndMSG(sTxt,'ERROR',sFuncName)
        return(None)

    #check File size 
    #iSize = os.path.getsize(sFile)
    #if iSize > MAXFILESIZE:
        #sTxt = "\--> This file is larger than MAXFILESIZE: " + sFile
        #sndMSG(sTxt,'ERROR',sFuncName)
        #return(None)
    
    try:
        with open(sFile) as data:
            oFile = data.read() 

        data.close()
    except IOError as e:
        sTxt = str("\--> I/O error({0}): {1}".format(e.errno, e.strerror))
        sndMSG(sTxt,'ERROR',sFuncName)
        return(None)
    except:
        sTxt = "\--> Unexpected error: " + str(sys.exc_info()[0])
        sndMSG(sTxt,'ERROR',sFuncName)
        return(None)
    
    sTxt = "\--> File was successfully Opened"
    sndMSG(sTxt,'INFO',sFuncName)
    return(oFile)
    
### -----< Test Cases >----- 


if __name__ == "__main__":
    main()
    
#EOF                                                
