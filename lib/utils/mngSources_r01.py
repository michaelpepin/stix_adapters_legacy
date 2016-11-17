
from mngMSG import sndMSG

class Source(object):
    """

    """
    SRC_TYPES = ['file', 'html']
    FILE_FORMATS = ['cvs', 'xml', 'rss']

    def __init__(self, id_=None, isDebugOn=False):
        self._id = id_
        self._type = None
        self._uri = None
        self._src_creds = {}    # Credention nessary to connect to remote source
        self._src_type = None   # Remote source type
        self._file_formats = [] # listed in order of decomp exmple, [zip, xml]

    def from_dict(self, data):
        if isinstance(data, dict):
            if data.get('creds'):
                self._src_creds = data.get('creds')
            if data.get('attrib'):
                self._type = data.get('attrib', {}).get('srcType')
                self._uri  = data.get('attrib', {}).get('uri')
            if data.get('data'):
                if isinstance(data.get('data', {}).get('format'), list):
                    # TODO: Handle existing data in list
                    self._file_types = data.get('data', {}).get('format')
                else:
                    # TODO: Handle if empty
                    self._file_types = [data.get('data', {}).get('format')]


class clsDataSource(object):
    
    _version = "0.1"
    
    def __init__(self, iID=None, isDebugOn=False):
        self._className    = 'clsDataSource'
        self._ID           = iID
        self._isDebugOn    = isDebugOn
        self._dateRunLast  = None
        self._dateRunNext  = None
        self._dateInterval = 300 #time in seconds
        self._chnkSize     = 500
        self._maxThreadCnt = 2
        
        #Credentials
        self._dicPrxCreds = tmpCred()
        self._dicSrcCreds = tmpCred()
        self._dicDstCreds = tmpCred()
        
        #Source Arribute Data
        self._dicParseArg = {}                
        self._Type      = None
        self._URI       = None
        self._Domain    = None
        self._Origin    = None
        self._TLD       = None
        self._useAdpter = None
        self._Quaity    = 0
        self._isValid   = False
        
        #Source Meta Data
        self._srcPkgTitle  = None
        self._srcPkgDscrpt = None
        self._srcPkgLink   = None
    
        #Local storage of Source Data
        self._typeFileFormats = ('txt','csv','xml','rss','htm','html')
        self._typeFileComp    = ('gz','zip','bz','tar')
        self._localFileExt    = None
        self._localFilePath   = './'
        self._localFileName   = self._ID
        
        
        
    @property
    def isDebugOn(self):
        return(self._isDebugOn) 
    
    @isDebugOn.setter
    def isDebugOn(self, value):
        self._isDebugOn = value
        
    @property
    def chnkSize(self):
        return(self._chnkSize) 
    
    @chnkSize.setter
    def chnkSize(self, value):
        self._chnkSize = value    

    @property
    def maxThreadCnt(self):
        return(self._maxThreadCnt) 
    
    @maxThreadCnt.setter
    def maxThreadCnt(self, value):
        self._maxThreadCnt = value  
                                                  
    @property
    def ID(self):
        return(self._ID)  

    @property
    def Type(self):
        return(self._Type)
        
    @property
    def URI(self):
        return(self._URI)

    @property
    def Domain(self):
        return(self._Domain)

    @property
    def Origin(self):        
        return(self._Origin)

    @property
    def TLD(self):
        return(self._TLD)
    
    @property
    def Adpter(self):    
        return(self._useAdpter)

    @property
    def Quality(self):        
        return(self._Quaity)
        
    @Quality.setter
    def Quality(self,value):        
        self._Quaity = value
        
    @property
    def isValid(self):        
        return(self._isValid)
    
    @isValid.setter
    def isValid(self, value):
        self._isValid = value
   
    @property
    def srcCreds(self):        
        return(self._dicSrcCreds)
           
    @srcCreds.setter
    def srcCreds(self, dicObj):
        if dicObj:
            self._dicSrcCreds = dicObj
        return(0)
        
    @property
    def dstCreds(self):        
        return(self._dicDstCreds)
           
    @dstCreds.setter
    def dstCreds(self, dicObj):
        if dicObj:
            self._dicDstCreds = dicObj
        return(0) 
        
    @property
    def prxCreds(self):        
        return(self._dicPrxCreds)
           
    @prxCreds.setter
    def prxCreds(self, dicObj):
        if dicObj:
            self._dicPrxCreds = dicObj
        return(0)   
    
    @property
    def fileName(self):  
        self._localFileExt = self._dicParseArg["format"][0]
        self._localFileName = "src_" + str(self._ID) + "." + self._localFileExt      
        return(self._localFileName)
    
    @fileName.setter
    def fileName(self, value):
        self._localFileName = value    

    @property
    def filePath(self):        
        return(self._localFilePath)
    
    @filePath.setter
    def filePath(self, value):
        self._localFilePath = value  
        
    @property
    def pkgTitle(self):        
        return(self._srcPkgTitle)
     
    @pkgTitle.setter
    def pkgTitle(self, value):
        self._srcPkgTitle = value           

    @property
    def pkgDscrpt(self):        
        return(self._srcPkgDscrpt)
     
    @pkgDscrpt.setter
    def pkgDscrpt(self, value):
        self._srcPkgDscrpt = value 
        
    @property
    def pkgLink(self):        
        return(self._srcPkgLink)
     
    @pkgLink.setter
    def pkgLink(self, value):
        self._srcPkgLink = value

    @property
    def parsearg(self):
        return(self._dicParseArg)  
        
    def to_string(self):
        return(0)
        
    def from_dict(self, dictData):
        try: self._ID = dictData['iID']
        except: pass
        try: self._Type = dictData["srcType"]
        except: pass
        try: self._dicSrcCreds['URI'] = dictData["uri"]
        except: pass
        try: self._URI  = dictData["uri"]
        except: pass
        try: self._Quaity = dictData["srcQuality"]
        except: pass
        try: 
            self._dicParseArg = dictData["srcParseArg"]
            if self._dicParseArg["format"][0]:
                self._localFileExt = self._dicParseArg["format"][0]
                self._localFileName = self._ID + "." + self._localFileExt

        except: pass
        return(0)
        
    def getSrcData(self):
        #print self._isDebugOn
        
        if self._isDebugOn == True:
            print "--- Debug Mode On "
            print "---" + str(self._ID) + " -> GetData was called "
            
    
        else:
            print "---" + str(self._ID) + " -> GetData was called "
    
        return(False)    
                
    def cnvrt_Src2Dict(self):
                 
        ### Convert file to a Directory object
        oSrcFile = _clsSourceFile()
        oSrcFile.filePath = self._localFilePath
        oSrcFile.fileName = self._ID
        oSrcFile.parsingArgs_fromDict(self._dicParseArg)
        oSrcFile.cnvt_SrcFile2Dict()
          
        return(oSrcFile.cnvt_SrcFile2Dict())
        

    
    pass
    
    
def tmpCred():
    dictObj = {
        "URI"    :"",
        "usrName":"",
        "usrPass":"",
        "crtName":"",
        "crtPass":""        
        }
    return(dictObj)
    
class _clsSourceFile():


    def __init__(self):
        self._strClassName = 'clsSourceFile'
        self._strClassVer  = '0.0.0'
        
        self._strFilePath         = './'
        self._chrCommentFlag      = '#'
        self._strFileNameSuffix   = 'src_'
        self._strUnicodeEncoding  = 'utf-8'
        self._lstFileEncapFormats = []
        
        self._dicParsingArgs      = {}
        self._lstCompressionTypes = ('gz','zip','bz','tar')
        self._lstFileFormatTypes  = ('txt','csv','xml','rss','htm','html')
        
    @property
    def filePath(self):        
        return(self._strFilePath)
     
    @filePath.setter
    def filePath(self, value):
        if not value[:-1] == '/':
            value = value + '/'
        else:       
            self._strFilePath = value
    
    @property
    def fileName(self):   
        return(self._strFileNameSuffix)
     
    @fileName.setter
    def fileName(self, value):
        if '.' in value:
            value = value.split('.')[0]    
        else:
            self._strFileNameSuffix = value
                             
    def parsingArgs_fromDict(self, dictData):
        if dictData == None:
            return(None)
        
        self._dicParsingArgs = dictData
        if "format" in dictData:
            if dictData["format"]:
                self.lstFileEncapFormats = dictData["format"]
        if "strEncode" in dictData:
            if dictData["strEncode"]:
                self._strUnicodeEncoding = dictData["strEncode"]
        if "ignore" in dictData:
            if dictData["ignore"]:
                self._chrCommentFlag = dictData["ignore"]          
                
    def cnvt_SrcFile2Dict(self):

        if self._dicParsingArgs['format'][0] in self._lstCompressionTypes:
            self.unpck_file2file()      
            
        if self._dicParsingArgs['format'][0] in self._lstFileFormatTypes:
            sFrmt = self._dicParsingArgs['format'][0]
            sFileSuffix = self._strFilePath + self._strFileNameSuffix 
            
               
            if sFrmt == 'txt' or sFrmt == 'csv':
                from cnvtFiles import cnvt_CSV2Dict
                from mngFiles  import clsCSVDialect_01
                oDialect = clsCSVDialect_01()
                oDialect.from_dict(self._dicParsingArgs)
                sFile = self.fileName + "." + sFrmt
                
                return(cnvt_CSV2Dict(sFile,oDialect,strEncoding=self._strUnicodeEncoding))
            
            elif sFrmt == 'xml' or sFrmt == 'rss':
                from mngFiles import cnvt_XML2Dict
                return(cnvt_XML2Dict(sFileSuffix + sFrmt))
                
            elif sFrmt == 'htm' or sFrmt == 'html':
                from mngFiles import cnvt_HTML2Dict
                sArg = self._dicParseArg["format"]["htmFltr"]
                return(cnvt_HTML2Dict(sFileSuffix + sFrmt,sArg))
                    
            else:
                sTxt = "Format not recognized: " + sFrmt
                sndMSG(sTxt,'ERROR',self._strClassName)                
        
        else:
            sTxt = 'Unrecognized file compression format: ' + self._dicParsingArgs['format'][0]
            sndMSG(sTxt,'ERROR',self._strClassName)
            return(None)
        
    def unpck_file2file(self):
            
         if self._dicParsingArgs['format'][0] in self._lstCompressionTypes:
            sTxt = 'Attempting to decompression format: ' + self._dicParsingArgs['format'][0]
            sndMSG(sTxt,'INFO',self._strClassName)
         
            ### Run decompressor
            from mngFiles import decompressor
            from mngFiles import Decompressor
            
            sFile = self._strFilePath + self.fileName + "." 
            
            srcFile = sFile + self._dicParsingArgs['format'][0]
            dstFile = sFile + self._dicParsingArgs['format'][1]
            cmpFrmt = self._dicParsingArgs['format'][0]
            oDcmp = Decompressor()
            bStatus = oDcmp.decompress(srcFile,dstFile,cmpFrmt)
            
            if bStatus == True:
                self._dicParsingArgs['format'].pop(0)

            elif bStatus == False:
                sTxt = 'Failed to unpack ' + self._lstFileEncapFormats(0) + ' file '
                sndMSG(sTxt,'ERROR',self._strClassName)
            
            else:
                sTxt = 'Unpacker returned unexpected result'
                sndMSG(sTxt,'ERROR',self._strClassName)
         
            ### This causes a loop to interater through self._lstFileEncapFormats
            self.cnvt_SrcFile2Dict()
         else:
            sTxt = 'Unrecognized file compression format: ' + self._lstFileEncapFormats(0)
            sndMSG(sTxt,'ERROR',self._strClassName)
            return(None)
            
    pass # End clsSourceFile
    
        
    
#EOF    
