#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

import struct
from exploitutils import *

from MSSsystem import MSSsystem
from MSSnetwork import MSSnetwork

BigEndian_Processors = ["Sparc", "PPC", "POWER", "PowerPC", "MIPS"]

class MSSgeneric(MSSnetwork, MSSsystem):
    
    Endianness = 'little' # XXX STATIC
    _endian_fmt = {'little': "<", 'big': ">"}
    
    def __init__(self, arch = None):
        
        self.doDes = False # start with plaintext mosdef
        
        if arch == None:
            assert hasattr(self, 'arch'), "instance missing a \"arch\" member"
            arch = self.arch
        for proc in BigEndian_Processors:
            if arch.upper() == proc.upper():
                self.Endianness = 'big'
                break
    
    def _struct_fmt(self, fmt):
        return self._endian_fmt[self.Endianness] + fmt
    
    def str2int32(self, buf):
        return struct.unpack(self._struct_fmt("L"), buf[:4])[0]
    
    def int2str32(self, integer):
        return struct.pack(self._struct_fmt("L"), integer)
    
    def runCode(self, code, vars):
        """ 
        usage:      node.shell.runCode("int main() ...", {"DEFINE" : 0 ...})
        """
        self.clearfunctioncache()
        message = self.compile(code, vars)
        self.sendrequest(message)
        ret = self.readint()
        self.leave()
        return ret

