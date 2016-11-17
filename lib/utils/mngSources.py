

def main():

    testDict = {
            "dateADD": "2014-06-19 08:53:08.562601", 
            "attrib": {
                "crtPass": "", 
                "crtName": "",  
                "srcDomain": "www.malwaredomainlist.com", 
                "srcOrigin": "OringinalOpenSourceList_20140231", 
                "srcTLD": "com", 
                "URI": "http://www.malwaredomainlist.com/hostslist/hosts.txt", 
                "srcValid": True, 
                "srcType":"file",
                "parseArg":{"format":["txt"],
                            "token":"\n",
                            "ignore":"#",
                            "hasHdrRow":False},
                "parser":"./mdl/adptr_mdl_01.py",             
                "usrPass": "", 
                "usrName": "", 
                "srcQuality": 1, 
                "isSSL": False
            }, 
            "cnt": 1, 
            "srcIndex": "src_22"
        }

    src_47 = clsDataSource(sID = 'src_47')
    
    src_47.creds['usrName'] = 'test2'
    print str(src_47.creds)

    lstSrcs = []
    
    lstSrcs.append(clsDataSource(sID = 'src_01'))
    lstSrcs.append(clsDataSource(sID = 'src_02'))
    lstSrcs.append(clsDataSource(sID = 'src_03'))
    
    print lstSrcs[0].ID
    
    lstSrcs[1].from_dict(testDict)
    print lstSrcs[1].URI
    print lstSrcs[1].URI
    
    return(0)


class clsDataSource(object):
    _version = "0.1"
    
    def __init__(self, sID=None, isDebugOn=False):
        self._ID           = sID
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
        self._Quality   = 0
        self._isValid   = False
        
        #Source Meta Data
        self._srcPkgTitle  = None
        self._srcPkgDscrpt = None
        self._srcPkgLink   = None
        self._srcProducer  = None
        self._srcTOU       = None
    
        #Local storage of Source Data
        self._localFileExt = None
        self._localFilePath = '.'
        self._localFileName = self._ID
        
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
    def creds(self):
        return(self._dicDstCreds)

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
        return(self._Quality)
        
    @Quality.setter
    def Quality(self,value):        
        self._Quality = value
        
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
    def srcTOU(self):        
        return(self._srcTOU)
     
    @srcTOU.setter
    def srcTOU(self, value):
        self._srcTOU = value
    
    @property
    def parsearg(self):
        return(self._dicParseArg)
        
    @property
    def producer(self):
        if self._srcProducer == None:
            self._srcProducer = self._Domain     
        
        return(self._srcProducer)
        
    @producer.setter
    def producer(self, value):        
        self._srcProducer = value
        
    @property
    def fileExt(self):
        if self._localFileExt == None:
            self._localFileExt = '.txt'     
        
        return(self._localFileExt)
        
    @fileExt.setter
    def fileExt(self, value):        
        self._localFileExt = value
        
    def to_string(self):
        return(0)
        
    def from_dict(self, dictData):

        self._dateSrcADDtoDB = dictData['dateADD']
        self._ID = dictData['srcIndex']
       
        if 'parseArg' in dictData['attrib']:
            self._dicParseArg = dictData['attrib']["parseArg"]
        
        #Generate local file Name
        if self._dicParseArg["format"][0]:
            self._localFileExt = self._dicParseArg["format"][0]
            self._localFileName = self._ID + "." + self._localFileExt


        if 'srcType' in dictData['attrib']:
            self._Type = dictData['attrib']["srcType"]
        
        if 'URI' in dictData['attrib']:    
            self._URI  = dictData['attrib']["URI"]
            
        if 'srcDomain' in dictData['attrib']:    
            self._Domain = dictData['attrib']["srcDomain"]
        
        if 'srcOrigin' in dictData['attrib']:    
            self._Origin = dictData['attrib']["srcOrigin"]
        
        if 'srcTLD' in dictData['attrib']:     
            self._TLD    = dictData['attrib']["srcTLD"]
        
        if 'srcQuality' in dictData['attrib']:     
            self._Quaity = dictData['attrib']["srcQuality"]
        
        if 'touDetail' in dictData['attrib']:
            self._srcTOU = dictData['attrib']["touDetail"]
        
        if 'srcValid' in dictData['attrib']:
            self._isValid   = dictData['attrib']["srcValid"]

        if len(self._URI) > 0:
            self._dicSrcCreds["URI"] = self._URI

        return(0)
        
    def getSrcData(self):
        #print self._isDebugOn
        
        if self._isDebugOn == True:
            print "--- Debug Mode On "
            print "---" + str(self._ID) + " -> GetData was called "
            
    
        else:
            print "---" + str(self._ID) + " -> GetData was called "
    
        return(False)    
        
    def unpakFile(self):
        knownFormats = ['gz','zip','bz','tar']
        
        
        return(0)    
            
    def cnvrt2JSON(self):
            
        if len(self._dicParseArg["format"]) > 1:
            lstExt = self._dicParseArg["format"]
            
        
        if x == 'file':
            sExt = self._dicParseArg["format"][0]
            if sExt == 'txt' or sExt == 'csv':
                dialect = clsCSVDialect()
                dialect.delimiter = ','
                dialect.header = False
                lstFileData = getFile_CSV2List(locDir + sFileName,dialect,'#')
                dialect = None

            
        return(0)
        

    
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
        
if __name__ == "__main__":
    main()    
    
#EOF    
