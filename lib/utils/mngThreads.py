
###
#
#   ### -----< File Managment Functions >-----
#   genThread_Conn,         retrun List of Threads
#   genThread_Conn_wQue,    retrun List of Threads
#   
### 

from mngFiles import getFile_asOBJ

def genThread_Conn_wQue(thrdList,conn_cred,thrdName,sFile,bTAXIIWrp):
    
    import threading
    import Queue
    que= Queue.Queue()
    tList = thrdList
    
    oFile = getFile_asOBJ(sFile)
    tList.append(
        threading.Thread(
            name=thrdName,
            target=Connector_Que, 
            args=(que, conn_cred,oFile,bTAXIIWrp,sFile)
            )
        )
        
    i = len(tList) -1
    #thrdList[iIdx].setDaemon(True)
    tList[i].start()
    tList[i].join
    return(tList)
    
def genThread_Conn(thrdList,conn_cred,thrdName,sFile,bTAXIIWrp):
    
    import threading
    tList = thrdList
    
    oFile = getFile_asOBJ(sFile)
    tList.append(
        threading.Thread(
            name=thrdName,
            target=Connector, 
            args=(conn_cred,oFile,bTAXIIWrp,sFile)
            )
        )
        
    i = len(tList) -1
    #thrdList[iIdx].setDaemon(True)
    tList[i].start()
    tList[i].join
    return(tList)
    

