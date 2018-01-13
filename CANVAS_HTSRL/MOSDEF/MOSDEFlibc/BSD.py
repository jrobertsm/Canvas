#! /usr/bin/env python

from UNIX import UNIX

class BSD(UNIX):
    #S_IREAD =  S_IRUSR
    #S_IWRITE = S_IWUSR
    #S_IEXEC =  S_IXUSR
    
    def __init__(self):
        UNIX.__init__(self)


class BSD41(BSD): # HPUX+IRIX+SunOS+oldMacOS
    
    # <sys/ioctl.h>
    
    SIOCGIFADDR =    0xc020690dL # _IOWR('i',13, struct ifreq)
    SIOCGIFCONF =    0xc0086914L # _IOWR('i',20, struct ifconf)
    
    def __init__(self):
        BSD.__init__(self)


class BSD42(BSD41):
    
    # <netinet/in.h>
    
    INADDR_ANY       = 0x00000000
    INADDR_BROADCAST = 0xffffffff
    INADDR_NONE      = 0xffffffff
    INADDR_LOOPBACK  = 0x7f000001
    
    IN_LOOPBACKNET = 127
    
    def __init__(self):
        BSD41.__init__(self)


class BSD43(BSD42):
    
    # <sys/ioctl.h>
    
    SIOCGIFNETMASK = 0xc0206919L # _IOWR('i',21, struct ifreq)
    
    def __init__(self):
        BSD42.__init__(self)


class BSD44(BSD43):
    
    def __init__(self):
        BSD43.__init__(self)


class BSD44lite1(BSD44):
    
    def __init__(self):
        BSD44.__init__(self)


class BSD44lite2(BSD44lite1):
    
    def __init__(self):
        BSD44lite1.__init__(self)


# XXX: place holder untill we have time to fully port it over
# XXX: TODO: port defines, port syscall table, port syscall gen.
# XXX: TODO: deal with stat asm.i386 structs for BSD
# XXX: TODO: match functionality with Linux_intel class

class BSD_intel(BSD44lite2):

    def __init__(self, version = None):
        BSD44lite2.__init__(self)
