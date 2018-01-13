#! /usr/bin/env python
"""
makeexe.py

Copywrite: Dave Aitel, 2003

"""


NOTES="""
See this article for information on create a minimal ELF file on Linux
http://www.muppetlabs.com/~breadbox/software/tiny/teensy.html
  BITS 32
  
                org     0x08048000
  
  ehdr:                                                 ; Elf32_Ehdr
                db      0x7F, "ELF", 1, 1, 1            ;   e_ident
        times 9 db      0
                dw      2                               ;   e_type
                dw      3                               ;   e_machine
                dd      1                               ;   e_version
                dd      _start                          ;   e_entry
                dd      phdr - $$                       ;   e_phoff
                dd      0                               ;   e_shoff
                dd      0                               ;   e_flags
                dw      ehdrsize                        ;   e_ehsize
                dw      phdrsize                        ;   e_phentsize
                dw      1                               ;   e_phnum
                dw      0                               ;   e_shentsize
                dw      0                               ;   e_shnum
                dw      0                               ;   e_shstrndx
  
  ehdrsize      equ     $ - ehdr
  
  phdr:                                                 ; Elf32_Phdr
                dd      1                               ;   p_type
                dd      0                               ;   p_offset
                dd      $$                              ;   p_vaddr
                dd      $$                              ;   p_paddr
                dd      filesize                        ;   p_filesz
                dd      filesize                        ;   p_memsz
                dd      5                               ;   p_flags
                dd      0x1000                          ;   p_align
  
  phdrsize      equ     $ - phdr
  
  _start:
  
  ; your program here
  
  filesize      equ     $ - $$

"""

import sys
from mosdefutils import *
from binfmt import elf
from binfmt.elf_const import *


#returns a binary version of the string
def binstring(instring):
    result=""
    #erase all whitespace
    tmp=instring.replace(" ","")
    tmp=tmp.replace("\n","")
    tmp=tmp.replace("\t","")
    tmp=tmp.replace("\r","")
    tmp=tmp.replace(",","")
    
    
    if len(tmp) % 2 != 0:
        print "tried to binstring something of illegal length: %d: *%s*"%(len(tmp),prettyprint(tmp))
        return ""

    while tmp!="":
        two=tmp[:2]
        #account for 0x and \x stuff
        if two!="0x" and two!="\\x":
            result+=chr(int(two,16))
        tmp=tmp[2:]

    return result

__ELF_proc_data = {
    #proc    machine   entry      class data  align    flags
    'X86':   ["386",   0x08048000, 32, "LSB", 0x1000,  0],
    'SPARC': ["SPARC", 0x10000,    32, "MSB", 0x10000, 0],
    'PPC':   ["PPC",   0x10000000, 32, "MSB", 0x10000, 0],
    'ARM':   ["ARM",   0x00008000, 32, "LSB", 0x8000,  EF_ARM_HASENTRY],
    'ARMEL': ["ARM",   0x00008000, 32, "LSB", 0x8000,  EF_ARM_HASENTRY],
    'MIPS':  ["MIPS",  0x0e000000, 32, "MSB", 0x4000,  EF_MIPS_ABI2|EF_MIPS_ARCH_3],
    'MIPSEL':["MIPS",  0x00400000, 32, "LSB", 0x1000,  EF_MIPS_NOREORDER|EF_MIPS_PIC|EF_MIPS_CPIC| \
                                                       EF_MIPS_ARCH_2|EF_MIPS_ARCH_5],
}

__ELF_endian = {'LSB': 0, 'MSB': 1}

def get_proc_data(proc):
    assert __ELF_proc_data.has_key(proc)
    p = {}
    p['machine'] = getattr(elf, "EM_" + __ELF_proc_data[proc][0])
    p['entry'] = __ELF_proc_data[proc][1]
    p['class'] = getattr(elf, "ELFCLASS%d" % __ELF_proc_data[proc][2])
    p['data'] = getattr(elf, "ELFDATA2" + __ELF_proc_data[proc][3])
    p['align'] = __ELF_proc_data[proc][4]
    p['flags'] = __ELF_proc_data[proc][5]
    p['abi'] = elf.ELFOSABI_SYSV
    try:
        p['abi'] = getattr(elf, "ELFOSABI_" + __ELF_proc_data[proc][0])
    except AttributeError:
        pass
    return p

def elf_ident(pdata):
    e_ident  = elf.ELF_MAGIC + chr(pdata['class']) + chr(pdata['data'])
    e_ident += chr(elf.EV_CURRENT) + chr(pdata['abi']) # ABIVERSION
    e_ident += "\x00" * (int(elf.EI_NIDENT) - (len(e_ident))) # PADDING
    return e_ident

def makeELF(data, filename = "", proc = "X86"):
        """
        Makes a ELF executable from the data bytes (shellcode) in "data"
        Should be close to optimally small
        e_entry is where our shellcode will start, if you want to debug it with gdb
        """

        pdata = get_proc_data(proc)
        e=elf.Elf32_Ehdr(config = (pdata['class'], pdata['data']))
        #                           
        e.e_ident    = elf_ident(pdata)
        e.e_type     = elf.ET_EXEC
        e.e_machine  = pdata['machine']
        e.e_version  = elf.EV_CURRENT
        e.e_entry    = pdata['entry'] + 0x54
        e.e_phoff    = 0x34
        e.e_shoff    = 0x0
        e.e_flags    = pdata['flags']
        e.e_ehsize   = elf.Elf32_Ehdr.size
        e.e_phentsize= elf.Elf32_Phdr.size
        e.e_phnum    = 0x1
        e.e_shentsize= 0x0
        e.e_shnum    = 0x0
        e.e_shstrndx = 0x0
        e.offset     = 0
        e.ei_class   = pdata['class']
        e.ei_data    = pdata['data']
        
        p=elf.Elf32_Phdr(config = e.getconf())
        
        p.offset     = e.e_phoff
        p.p_type     = elf.PT_LOAD
        p.p_offset   = 0x0
        p.p_vaddr    = pdata['entry']
        p.p_paddr    = pdata['entry']
        p.p_filesz   = elf.Elf32_Ehdr.size + elf.Elf32_Phdr.size + len(data)
        # XXX imo p_memsz should be p_filesz rounded up to p_align
        p.p_memsz   = p.p_filesz
        #p.p_memsz    = (p.p_filesz & ~(pdata['align'] - 1)) + pdata['align']
        p.p_flags    = elf.PF_X | elf.PF_W | elf.PF_R # read, write and execute!
        p.p_align    = pdata['align']
        
        if filename!="":
            try:
                f=open(filename, "w")
                p.fd=e.fd=f
                e.write()
                p.write()
                f.write(data)
                import os
                os.chmod(filename, 0775)
                f.close()
            except: 
                print "Couldn't open, write or chmod outfile"
        return e.raw() + p.raw() + data
    
def makelinuxexe(data, filename = "", proc = "X86"):
    return makeELF(data, filename = filename, proc = proc)

def makelinuxexeSPARC(data, filename=""):
    return makelinuxexe(data, filename = filename, proc = "SPARC")

def makesolarisexe(data, filename = "", proc = "SPARC"):
    return makeELF(data, filename = filename, proc = proc)

def makeirixexe(data, filename = "", proc = "MIPS"):
    return makeELF(data, filename = filename, proc = proc)

def makenetbsdexe(data,filename=""):
        """
        Makes a netbsd executable from the data bytes (shellcode) in "data"
        Should be close to optimally small
        0x???????? is where our shellcode will start, if you want to debug it with gdb
        """
        tmp=""
        tmp+=binstring("7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00")
        tmp+=binstring("02 00 03 00 01 00 00 00")
        tmp+=binstring("54 80 04 08")
        tmp+=binstring("34 00 00 00")
        tmp+=binstring("00"*8)
        tmp+=binstring("34 00 20 00 01 00")
        tmp+=binstring("00 00")
        tmp+=binstring("00 00 00 00 01 00 00 00 00 00 00 00 00 80 04 08")
        tmp+=binstring("00 80 04 08")
        tmp+=intel_order(0x54+len(data))*2
        tmp+=binstring("07 00 00 00 00 10 00 00")
        tmp+=data 
        if filename!="":                                                                                                             
            try:                                                                                                                     
                fd=open(filename,"w")                                                                                                
                fd.write(tmp)                                                                                                        
                fd.close()                                                                                                           
                import os                                                                                                            
                os.chmod(filename, 0775)                                                                                             
            except:                                                                                                                  
                print "Couldn't open, write or chmod outfile3"  
        return tmp                                                 

def makeopenbsdexe(data,filename=""):
        """
        Makes a openbsd executable from the data bytes (shellcode) in "data"
        Should be close to optimally small
        0x???????? is where our shellcode will start, if you want to debug it with gdb 
        """
        tmp=""
        pass

def makefreebsdexe(data,filename=""):
        """                                                                                                             
        Makes a openbsd executable from the data bytes (shellcode) in "data"                                            
        Should be close to optimally small                                                                              
        0x???????? is where our shellcode will start, if you want to debug it with gdb                                  
        """                                                                                                             
        tmp=""                                                                                                          
        tmp+=binstring("7f 45 4c 46 01 01 01 09 00 00 00 00 00 00 00 00")
        tmp+=binstring("02 00 03 00 01 00 00 00")
        tmp+=binstring("54 80 04 08")
        tmp+=binstring("34 00 00 00")
        tmp+=binstring("00"*8)
        tmp+=binstring("34 00 20 00 01 00 00 00")
        tmp+=binstring("00 00 00 00 01 00 00 00 00 00 00 00 00 80 04 08")
        tmp+=binstring("00 80 04 08")
        tmp+=intel_order(57+len(data))*2
        tmp+=binstring("07 00 00 00 00 10 00 00")
        tmp+=data
        if filename!="":                                                                                                                                   
            try:                                                                                                                                           
                fd=open(filename,"w")                                                                                                                      
                fd.write(tmp)                                                                                                                              
                fd.close()                                                                                                                                 
                import os                                                                                                                                  
                os.chmod(filename, 0775)                                                                                                                   
            except:                                                                                                                                        
                print "Couldn't open, write or chmod outfile3"                                                                                             
        return tmp                                  
    

#def halfword2bstr(halfword):
#    data=""
#    a=halfword & 0xff
#    b=halfword/256 & 0xff
#    data+=chr(b)+chr(a)
#    return data

def makewin32exe(data,filename="",imports=[],exports=[]):
    """
    Make a windows executable from the data bytes
    """
    out="MZ"
    out+="\x00"*(0x3c-2)
    out+=intel_order(0x3c+4)
    #now the start of the pe header
    out+="PE\x00\x00"
    machine = {}
    machine["x86"]="\x01\x4c"
    #machine
    out+=machine["x86"]
    #number of sections
    sections=3
    out+=halfword2bstr(sections)
    #Time Date Stamp
    out+="\x00"*4
    #Pointer To Symbol Table
    out+="\x00"*4 #0 for none is present
    #Number of Symbols
    out+="\x00"*4 #0 for none is present    
    #Size of Optional Header
    optionalheader=""
    out+=halfword2bstr(len(optionalheader)) # XXX wtf is optionalheader?
    #Charactaristics
    STRIPPED=0x0001
    EXECUTABLE=0x0002
    charactaristics=0
    charactaristics|=STRIPPED
    charactaristics|=EXECUTABLE
    out+=halfword2bstr(charactaristics)
    
    return out

makewindowsexe=makewin32exe

def makeexe(OS, data, filename = "", proc = None):
    if hasattr(sys.modules[__name__], "make%sexe" % OS.lower()):
        return getattr(sys.modules[__name__], "make%sexe" % OS.lower())(data, filename, proc)
    print "Cannot make %s an exe"%OS.lower()
    return None

def usage():
        print "%s inputfile outputfile"%sys.argv[0]
        sys.exit(1)
        
def usage():
        print "%s -s [Solaris|NetBSD|OpenBSD|FreeBSD|Linux] -f [opcodesfile] -o [outputfile]" % sys.argv[0]
        print "If you want to test a default shellcode /bin/sh just leave out the -f options"
        print "Tested on:"
        print "FreeBSD-5.1 Elf Header"
        print "OpenBSD-3.4 Elf Header"
        print "NetBSD-1.6 Elf Header"
        print "Linux 2.4 Elf Header"
        print "-f [opcodesfile] File with opcodes"
        print "-o [outputfile] Output binary file"
        sys.exit(1)


if __name__=="__main__":
        try:
                import getopt, re
                opts, args = getopt.getopt(sys.argv[1:], 's:f:o:e')
        except getopt.GetoptError:
                usage()
        
        opcodesfile=""
        elftype=0
        outputfile=""

        for opt, value in opts:
            if opt == ('-s'):
               netbsd  = re.compile('netbsd',re.IGNORECASE)
               openbsd = re.compile('openbsd',re.IGNORECASE)
               freebsd = re.compile('freebsd',re.IGNORECASE)
               linux   = re.compile('linux',re.IGNORECASE)
               solaris   = re.compile('solaris',re.IGNORECASE)
               if netbsd.match(value): 
                   elftype = 1
               elif openbsd.match(value):
                   elftype = 2
               elif freebsd.match(value):
                   elftype = 3
               elif linux.match(value):
                   elftype = 4
               elif solaris.match(value):
                   elftype = 5
               else:
                  usage()
                  
            if opt ==  ('-f'): 
               opcodesfile = value

            if opt == ('-o'):
               outputfile = value
        
        try:
            if opcodesfile == "":
               if elftype == 1:
               #netbsd /bin/sh NetBSD 1.6ZC NetBSD 1.6ZC (foofuck)
                   data="\xe9\x0d\x00\x00\x00\x5f\x31\xc0\x50\x89\xe2\x52"
                   data+="\x57\x54\xb0\x3b\xcd\x80\xe8\xee\xff\xff\xff\x2f\x62\x69\x6e\x2f"
                   data+="\x73\x68"
               elif elftype == 2:
                   pass
               elif elftype == 3:
               #freebsd /bin/sh FreeBSD 5.1-RELEASE FreeBSD 5.1-RELEASE
                   data="\xe9\x0d\x00\x00\x00\x5f\x31\xc0\x50\x89\xe2\x52"
                   data+="\x57\x54\xb0\x3b\xcd\x80\xe8\xee\xff\xff\xff\x2f\x62\x69\x6e\x2f"
                   data+="\x73\x68"
               elif elftype == 4:
               #linux /bin/sh Linux 2.4.22-grsec-1.9.12 i686 Pentium III (Katmai) GenuineIntel GNU/Linux
                   data="\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x99\x52\x53\x89\xe1\xb0\x0b\xcd\x80"
               elif elftype == 5:
                   #ba self, nop
                   data= "\x10\x80\x00\x00\x01\x00\x00\x00"
               else:
                   print "ERROR: Problem with setting data string"
                   sys.exit(1)
            else:
                 try:
                     data=open(opcodesfile).read()
                 except:
                     print "ERROR: Can't open opcodesfile."
                     usage()

        except:
            usage()
        try:
            import socket
        except:
            pass
        print "Using %d bytes of data"%len(data)
        try:
            if elftype == 1:
                filedata=makenetbsdexe(data)
            elif elftype == 2:
                filedata=makeopenbsdexe(data)
            elif elftype == 3:
                filedata=makefreebsdexe(data)
            elif elftype == 4:
                filedata=makelinuxexe(data)
            elif elftype == 5:
                data= "\x10\x80\x00\x00\x01\x00\x00\x00"+data
                #print "Making file with %d bytes"%(len(data))
                filedata= makelinuxexeSPARC(data)
            else:
                 print "ERROR: Can't choose an elf header type"
                 sys.exit(1)

        except socket.error:
           print "ERROR: Can't choose an elf header type"
           sys.exit(1)

        try:
            if outputfile == "":
                print "ERROR: No outputfile"
                sys.exit(1)
            else:
                fd=open(outputfile,"w")
                fd.write(filedata)
                fd.close()
                import os
                os.chmod(outputfile,0775)

        except:
            print "ERROR: Couldn't open, write or chmod %s" % outputfile
        
        
        
