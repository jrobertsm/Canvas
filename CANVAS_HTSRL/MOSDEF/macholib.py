#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2003
#http://www.immunityinc.com/CANVAS/ for more information
                                                                                                         
                                                                                                         
#Part of CANVAS For licensing information, please refer to your
#Immunity CANVAS licensing documentation

# Documentation on Mach-O:
#   http://developer.apple.com/documentation/DeveloperTools/Conceptual/MachORuntime/Reference/reference.html#//apple_ref/c/tag/segment_command

import struct
from struct_endian import struct_endian

class MACHOException(Exception):
    
    def __init__(self, args=None):
        self.args = args
    
    def __str__(self):
        return `self.args`


class _struct_fmt(struct_endian):
    _fmt = ""
    
    def __init__(self, endian = None):
        struct_endian.__init__(self, endian)
    
    def Size(self):
        return self.calcsize(self._fmt)


FAT_MAGIC = 0xcafebabeL 
FAT_CIGAM = 0xbebafecaL
class FatHdr(_struct_fmt):
    _fmt = "LL"
    _magicfmt = "L"
    
    def __init__(self):
        _struct_fmt.__init__(self, 'big')
        
        self.magic     = 0
        self.nfat_arch = 0
    
    def Set(self, data):
        self.magic = self.unpack(self._magicfmt, data[ : self.calcsize(self._magicfmt) ])[0]
        
        if self.magic not in (FAT_MAGIC, FAT_CIGAM):
            raise MACHOException, "Bad Magic number: 0x%08x" % self.magic
        
        if self.magic == FAT_CIGAM:
            self.switch_endian()
        
        (self.magic, self.nfat_arch) = self.unpack(self._fmt, data[ : self.calcsize(self._fmt) ])
    
    def Raw(self):
        return self.unpack(self._fmt, self.magic, self.nfat_arch)


class FatArch(_struct_fmt):
    _fmt = "LLLLL"
    
    def __init__(self, endian):
        _struct_fmt.__init__(self, endian)
        
        self.cputype    = 0        # CPU family
        self.cpusubtype =  0      #  specific member of the CPU family
        self.offset     =   0    #   Offset to the begging of the data
        self.size       =    0  #    Size
        self.align      =     0#     Aligment
    
    def Set(self, data):
        (self.cputype, self.cpusubtype, self.offset, self.size, self.align) = \
            self.unpack(self._fmt, data[: self.Size()])
    
    def Raw(self):
        return self.pack(self._fmt, self.cputype, self.cpusubtype, self.offset, \
            self.size, self.align)
 

class Fat:
    def __init__(self):
        #XXX self.endian = ">"
        self.Binaries = []
    
    def Set(self, data):
        self.FatHdr = FatHdr()
        
        self.FatHdr.Set(data)
        #XXX self.endian = self.FatHdr.endian
        
        idx = self.FatHdr.Size()
        
        for a in range(0, self.FatHdr.nfat_arch):
            fat = FatArch()
            fat.Set(data[ idx: idx+ fat.Size() ])
            
            idx += fat.Size()
            self.Binaries.append(fat)


MH_MAGIC        = 0xfeedfaceL      #/* the mach magic number */
MH_CIGAM        = 0xcefaedfeL      #/* NXSwapInt(MH_MAGIC) */
class MachHdr(_struct_fmt):
    _fmt ="LLLLLLL"
    _magicfmt = "L"
    
    def __init__(self):
        _struct_fmt.__init__(self)
        self.magic      = 0
        self.cputype    =  0
        self.cpusubtype = 0
        self.filetype   =  0
        self.ncmds      = 0
        self.sizeofcmds =  0
        self.flags      = 0
    
    def Raw(self):
        return self.pack(self._fmt, self.magic, self.cputype, self.cpusubtype, \
            self.filetype, self.ncmds, self.sizeofcmds, self.flags)
        
    def Set(self, data):
        magic = self.unpack(self._magicfmt, data[ : self.calcsize(self._magicfmt) ])[0]
        
        if magic not in (MH_MAGIC, MH_CIGAM):
            raise MACHOException, "Bad Magic number: 0x%08x" % self.magic
        if magic == MH_CIGAM:
            self.switch_endian()
        
        # We get Magic again
        (self.magic, self.cputype, self.cpusubtype, self.filetype, self.ncmds, \
            self.sizeofcmds, self.flags) = self.unpack(self._fmt, data[:self.Size()])
    
    def Print(self):
        return "Magic: 0x%08x  Cputype: 0x%08x Cpusubtype: 0x%08x Filetype: 0x%08x\n" \
                "Ncmds: 0x%08x   Sizeofcmds: 0x%08x   Flags:0x%08x\n" % \
                (self.magic, self.cputype, self.cpusubtype, \
                self.filetype, self.ncmds, self.sizeofcmds, self.flags)


class LoadCommand(struct_endian):
    _hdrfmt = "LL"
    _fmt = ""
    
    def __init__(self, endian):
        struct_endian.__init__(self, endian)
        self.cmd = 0
        self.cmdsize = 0
    
    def Raw(self):
        return self.pack(self._fmt, self.cmd, self.cmdsize) + self.doraw()
    
    def Set(self, data):
        hdrsize = self.calcsize(self._hdrfmt) 
        
        (self.cmd, self.cmdsize) = self.unpack(self._hdrfmt, data[:hdrsize])
        
        # doraw from behind cmdsize to buf[:cmdsize] 
        self.doset( data[ hdrsize : self.cmdsize ] )
    
    def doraw(self):
        return ""
    
    def doset(self, data):
        pass
    
    def Size(self):
        return self.cmdsize
    
    def dosize(self):
        return self.calcsize(self._fmt)
    
    def Print(self):
        return "Cmd: %02x CmdSize: %d" % (self.cmd, self.cmdsize)
    
    def HdrSize(self):
        return self.calcsize(self._fmt) + self.calcsize(self._hdrfmt)


LC_SEGMENT = 1
class CmdSegment(LoadCommand):
    _fmt = "16sLLLLLLLL" 

    def __init__(self, endian = 'little'):
        LoadCommand.__init__(self, endian)
        
        self.segname = ""
        self.vmaddr = self.vmsize = self.fileoff = self.filesize = self.maxprot = \
            self.initprot = self.nsects = self.flags = 0
    
    def doraw(self):
        return self.pack(self._fmt, self.segname, \
            self.vmaddr, self.vmsize, self.fileoff, self.filesize, \
            self.maxprot, self.initprot, self.nsects, self.flags)
    
    def doset(self, data):
        (self.segname, self.vmaddr, self.vmsize, self.fileoff, self.filesize, \
            self.maxprot, self.initprot, self.nsects, self.flags) = \
            self.unpack(self._fmt, data[:self.dosize()] )
        self.segname = self.segname.strip('\x00')


LC_SYMTAB = 2
class CmdSymTab(LoadCommand):
    _fmt = "LLLL"
    
    def __init__(self, endian = 'little'):
        LoadCommand.__init__(self, endian)
        self.symoff  = 0
        self.nsyms   =  0
        self.stroff  =  0
        self.strsize = 0
        
    def doraw(self):
        return self.pack(self._fmt, self.symoff, self.nsyms, self.stroff, self.strsize)
    
    def doset(self, data):
        (self.symoff, self.nsyms, self.stroff, self.strsize) = \
            self.unpack(self._fmt, data[:self.dosize()] )


class Section(_struct_fmt):
    _fmt = "16s16sLLLLLLLLL"
    
    def __init__(self, endian):
        _struct_fmt.__init__(self, endian)
        
        self.segname  = ""
        self.addr      = 0
        self.size      =  0
        self.offset    =   0
        self.align     =    0
        self.reloff    =     0
        self.nreloc    =    0
        self.flags     =   0
        self.reserved1 =  0
        self.reserved2 = 0
    
    def Raw(self):
        return self.pack(self._fmt, self.sectname, self.segname, self.addr, \
            self.size, self.offset, self.align, self.reloff, \
            self.nreloc, self.flags, self.reserved1, self.reserved2)
    
    def Set(self, data):
        (self.sectname, self.segname, self.addr, \
            self.size, self.offset, self.align, self.reloff, \
            self.nreloc, self.flags, self.reserved1, self.reserved2) = \
            self.unpack(self._fmt, data[: self.Size()])
        self.sectname = self.sectname.strip('\x00')
        self.segname = self.segname.strip('\x00')


class NList(_struct_fmt):
    _fmt = "LBBHL"
    
    def __init__(self, endian):
        _struct_fmt.__init__(self, endian)
        
        self.n_strx  = 0
        self.n_type  =  0
        self.n_sect  =  0
        self.n_desc  =  0
        self.n_value = 0
    
    def Raw(self):
        return self.pack(self._fmt, self.n_strx, self.n_type, self.n_sect, \
            self.n_desc, self.n_value)
    
    def Set(self, data, strtbl):
        (self.n_strx, self.n_type, self.n_sect, \
            self.n_desc, self.n_value) = self.unpack( self._fmt, data[:self.Size()] )
        ndx = strtbl[ self.n_strx:].find("\0")
        
        self.name = strtbl[self.n_strx : self.n_strx + ndx ] 
    
    def Print(self):
        return "%-50s 0x%08x" % (self.name, self.n_value)


class MachO(struct_endian):
    def __init__(self):
        struct_endian.__init__(self)
        self._commandsegment = { LC_SEGMENT: CmdSegment, LC_SYMTAB: CmdSymTab }
        self._getfunctions = {LC_SYMTAB: self.getSymbols, LC_SEGMENT: self.getSections}
        self.Symbols = []
        self.Commands = []
        self.Sections = []
    
    def OpenFile(self, filename):
        f = open(filename, "r")
        buf = f.read()
        self.OpenRaw(buf)
        self.getCommands()
        f.close()
    
    def OpenRaw(self, data):
        self.data = data
        self.idx = 0
        
        self.MachHdr = MachHdr()
        self.MachHdr.Set(data)
        self.set_endian(self.MachHdr.get_endian())
        self.idx = self.MachHdr.Size()
    
    def getCommands(self):
        for a in range(0, self.MachHdr.ncmds):
            ncmd = self.unpack("L", self.data[self.idx : self.idx+4])[0]
            try:
                clase = self._commandsegment[ncmd](self.get_endian())
            except KeyError:
                clase = LoadCommand(self.get_endian())
            clase.Set( self.data[self.idx:] )
            
            self.Commands.append(clase)
            try:
                function = self._getfunctions[ clase.cmd ]
                function(clase)
            except KeyError:
                # not available now
                pass
                
            #if clase.cmd == LC_SYMTAB:
            #    self.getSymbols(clase)
            
            self.idx += clase.Size()
    
    def getSymbols(self, clase):
        self.symbolstrtable = self.data[ clase.stroff: clase.stroff + clase.strsize]
        idx = clase.symoff
        for a in range(0, clase.nsyms):
            nlist = NList(self.get_endian())
            
            nlist.Set( self.data[idx:], self.symbolstrtable)
            self.Symbols.append(nlist)
            
            idx+= nlist.Size()
    
    def getSections(self, clase):
        idx = self.idx + clase.HdrSize() # size of the hdr
        
        for a in range(0, clase.nsects):
            section = Section(self.get_endian())
            
            section.Set( self.data[ idx: idx+section.Size()] )
            self.Sections.append( section )
            print "segment:", section.segname
            print "sectname:", section.sectname
            
            idx += section.Size()


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print "Usage: %s <file>" % sys.argv[0]
        raise SystemExit

    m = MachO()
    m.OpenFile(sys.argv[1])
    print "Commands:"
    for a in m.Commands:
        print a.Print()
    if m.Symbols == []:
        print "No symbols."
    else:
        print "Symbols: "
        for a in m.Symbols:
            print a.Print()

