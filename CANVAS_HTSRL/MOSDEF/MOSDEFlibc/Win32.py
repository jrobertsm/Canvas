#! /usr/bin/env python

from crippleC import crippleC
from ANSI import ANSI

class Win32(ANSI, crippleC):
    
    def __init__(self):
        ANSI.__init__(self)
        crippleC.__init__(self)

# XXX hook
class Win32_intel(Win32):
    
    Endianness = 'little'
    
    def __init__(self, version = None):
        self.version = version
        Win32.__init__(self)

Win32_x86=Win32_intel
