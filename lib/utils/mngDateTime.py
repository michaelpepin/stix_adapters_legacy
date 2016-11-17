
###
#
#   ### -----< Date & Time Managment Functions >-----
#   cnvtDate2STD(), return String
#   getUTCTime(),   retrun String    
#
###

import sys
import datetime

from mngMSG import sndMSG

### -----< Date & Time Managment Functions >-----

def cnvtDate2STD(sDate):
    #TODO: This is broken
    '''
    - Used to standardizes datetime formats  
    
    Keyword arguments: 
   
    Returns:
    '''
    
    sFuncName = 'cnvtDate2STD()'
    sDateTime = sDate.strftime("%Y-%m-%dT%H:%M:%SZ")
    #try:
    #    sDateTime = sDate.strftime("%Y-%m-%dT%H:%M:%SZ")
    #    return(sDateTime)
    #except:
    #    sTxt = "Unexpected error: " + str(sys.exc_info()[0])
    #    sndMSG(sTxt,'ERROR',sFuncName)
    #    return(None)
    
def getUTCTime():
    '''
    - Used to get UTC in a standardized format
    
    Keyword arguments: 
   
    Returns:
    '''
    from datetime import datetime
    sFuncName = 'getUTCTime()'
    try:
        sDateTime = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        return(sDateTime)
    except:
        sTxt = "Unexpected error: " + str(sys.exc_info()[0])
        sndMSG(sTxt,'ERROR',sFuncName)
        return(None)
    
#EOF
