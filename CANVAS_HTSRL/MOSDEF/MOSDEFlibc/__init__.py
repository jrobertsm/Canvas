#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

import sys
if "." not in sys.path: sys.path.append(".")

from internal import devlog
__all__ = [
    'asm',
]

__MOSDEFlibc_cache = {}

__procfamily_table = {
    'intel': ["i386", "i486", "i568", "i686", "i86pc"],
    'sparc': ["sparc64"],
}

__procname_table = {
    'ppc':    "powerpc",
    'mipsel': "mips",
    'armel':  "arm",
}


def GetMOSDEFlibc(os, proc=None, version=None):
    import sys
    global __MOSDEFlibc_cache
    if proc:
        proc = proc.lower()
    if proc not in __procfamily_table.keys():
        for procfamily in __procfamily_table.keys():
            if proc in __procfamily_table[procfamily]:
                proc = procfamily
                break
    if proc in __procname_table.keys():
        proc = __procname_table[proc]
    sysnamekey = "%s_%s_%s" % (os, proc, version)
    if __MOSDEFlibc_cache.has_key(sysnamekey):
        #print "returning %s from cache" % sysnamekey, __MOSDEFlibc_cache[sysnamekey]
        return __MOSDEFlibc_cache[sysnamekey]
    old_path = sys.path
    # TODO: fix sys.path here
    sys.path = ['MOSDEFlibc', 'MOSDEF/MOSDEFlibc'] + old_path
    sysname = os
    if proc:
        sysname += '_' + proc
    else:
        proc = "Generic"

    devlog("MOSDEFLibC","Importing %s.%s"%(os,sysname))
    
    libc = getattr(__import__(os), sysname)(version)
    
    setattr(libc, "_names", {'os':os, 'proc':proc, 'version':version})
    sys.path = old_path
    libc.postinit()
    libc.initStaticFunctions()
    __MOSDEFlibc_cache[sysnamekey] = libc
    return libc

if __name__ == "__main__":
    import sys
    sys.path.append('../..')
    sys.path.append('..')
    
    def testlibc(os, proc, vers=None):
        print "-"*10 + "  %s - %s  " % (os, proc) + "-"*10
        libc = GetMOSDEFlibc(os, proc, vers)
        print libc
        #print dir(libc)
        #print "   " + "-"*20
        print libc.getdefines()
        #print libc.localfunctions
        print libc.endianorder
        print "0x12345678 -> 0x%08x" % libc.endianorder('\x12\x34\x56\x78')
        return libc
    
    print "testing module..."
    testlibc("Win32", None)
    testlibc('Linux', 'sparc')
    testlibc('Linux', 'i386')
    testlibc('Linux', 'ppc')
    testlibc('Solaris', 'sparc')
    testlibc('AIX', 'rs6000', '5.1')
    testlibc('IRIX', 'mips')
    testlibc('AIX', 'powerpc', '5.2')
    testlibc('Solaris', 'i86pc')
    testlibc('OSX', 'PowerPC')
    testlibc('OSX', 'i386')
    
    print "tests done."
