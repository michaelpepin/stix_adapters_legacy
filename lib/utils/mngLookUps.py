




def lookUp_CntryCode(sCntryCode):
    
    if len(sCntryCode) == 2:
        from data import dictCC2CN
        if sCntryCode.upper() in dictCC2CN:
            return(dictCC2CN[sCntryCode])

    elif len(sCntryCode) == 3:
        from data import dictCC3CN
        if sCntryCode.upper() in dictCC3CN:
            return(dictCC3CN[sCntryCode])
        
    return()
    
