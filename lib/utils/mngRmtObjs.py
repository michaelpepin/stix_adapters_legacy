
###
#
#   ### -----< Remote Object Managment Functions >-----
#   getRmt_File(),   return Boolean 
#
###

import sys
from mngMSG import sndMSG

### -----< Remote Object Managment Functions >-----

def getRmt_data(srcData):
    getRmt_File(srcData.srcCreds,  srcData.filePath + srcData.fileName)
    return 0

def getRmt_File(dicCreds,sFile):
    '''
    - Simple URL Retrieval function based on python's urllib
    
    Keyword arguments: 
   
    Returns:
    '''
    import urllib
    sFuncName = 'getRmt_File'
    rmtSrcFile = dicCreds['URI']
    
    sTxt = "Connecting to " + rmtSrcFile
    sndMSG(sTxt,'INFO',sFuncName)
    
    try:
        urllib.urlretrieve(rmtSrcFile,sFile)
        return(True)
    except:
        sTxt = "Unexpected error: " + str(sys.exc_info()[0])
        sndMSG(sTxt,'ERROR',sFuncName)
        return(False)
    return False

def getRmt_File2(dicCreds,sFile):
    '''
    - Simple URL Retreval funtion based on python's urllib2
    - With chunking and download update 
    
    Keyword arguments: 
   
    Returns:
    '''
    import urllib2
    sFuncName = 'getRmtFile2'
    rmtFile = dicCreds['URI']
    
    #"Mozilla/5.0 (X11 U Linux i686) Gecko/20071127 Firefox/2.0.0.11"
    try:
        ### Add Proxy
        # SOURCE: https://docs.python.org/2.4/lib/urllib2-examples.html
        # proxy_handler = urllib2.ProxyHandler({'http': 'http://www.example.com:3128/'})
        # proxy_auth_handler = urllib2.HTTPBasicAuthHandler()
        # proxy_auth_handler.add_password('realm', 'host', 'username', 'password')
        #
        # opener = build_opener(proxy_handler, proxy_auth_handler)
        # This time, rather than install the OpenerDirector, we use it directly:
        # opener.open('http://www.example.com/login.html'
        #
        # ## Mixed HTTPS HTTP enviroment
        # urllib2.ProxyHandler({'https': 'http://user:pass@proxy:3128' }))
        ###
        
        ### Basic HTTP Authentication
        # SOURCE: https://docs.python.org/2.4/lib/urllib2-examples.html
        # ##Create an OpenerDirector with support for Basic HTTP Authentication...
        #   auth_handler = urllib2.HTTPBasicAuthHandler()
        #   auth_handler.add_password('realm', 'host', 'username', 'password')
        #   opener = urllib2.build_opener(auth_handler)
        # ##...and install it globally so it can be used with urlopen.
        #   urllib2.install_opener(opener)
        #   urllib2.urlopen('http://www.example.com/login.html')
        ###
        
        ### Cookie Handler
        # jar = cookielib.FileCookieJar("cookies")
        # opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(jar))
        ### 

        ### Modifiy User Agent
        # opener = urllib2.build_opener()
        # opener.addheaders = [('User-agent', 'Mozilla/5.0')]
        # opener.open('http://www.example.com/')
        ###
        
        objURL = urllib2.urlopen(rmtFile)
    except:
        sTxt = "Unexpected error: " + str(sys.exc_info()[0])
        sndMSG(sTxt,'ERROR',sFuncName)
        return(False)
    
    objFile = open(sFile, 'wb')
    meta = objURL.info()
    file_size = int(meta.getheaders("Content-Length")[0])
    sTxt = "Downloading: %s Bytes: %s" % (sFile, file_size)
    sndMSG(sTxt,'INFO',sFuncName)

    file_size_dl = 0
    block_sz = 8192
    while True:
        buffer = objURL.read(block_sz)
        if not buffer:
            break

        file_size_dl += len(buffer)
        objFile.write(buffer)
        status = r"%10d  [%3.2f%%]" % (file_size_dl, file_size_dl * 100. / file_size)
        status = status + chr(8)*(len(status)+1)
        sndMSG(status,'INFO',sFuncName)

    objFile.close()
    return(True)


#EOF
