
#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
smbshell.py
"""

import os
from shellserver import shellserver

from exploitutils import binstring
import time
from libs import mysqllib
from msrpc import smb_nt_64bit_time
    
class smbshell(shellserver):
    def __init__(self, mysmbobj ,node, logfunction=None):
        shellserver.__init__(self,None,type="Active",logfunction=logfunction)
        self.node = node
        node.shell = self
        self.smbobj = mysmbobj
        self.connection = self.smbobj.s #set this up for self.interact()
        return
    
    def startup(self):
        #we got data, and we need to read it...
        return ""
    
    def pwd(self):
        """Get current working directory"""
        return self.smbobj.getcwd()

    def getcwd(self):
        return self.pwd()
    
    def sendraw(self,data):
        return 1
        
    def dospawn(self,command):
        return ""
    
    def dounlink(self,filename):
        """Delete a file"""
        return self.smbobj.unlink(filename)
    
    def cd(self,directory):
        """Change working directory"""
        return self.smbobj.chdir(directory)

    def chdir(self,directory):
        """Change working directory"""
        return self.cd(directory)
    
    def dodir(self,directory="."):
        """Get a directory listing.
        Currently time is incorrect (:<)
        """
        success,results = self.smbobj.dir()
        ret=""
        if success:
            import time
            for f in results:
                ret+="%26s %8s %10s %20s\n"%(f["Filename"],f["Attributes"],
                                             f["End Of File"], #filesize
                                             smb_nt_64bit_time(f["Last Change"] ))
        return ret

    def mkdir(self,directory):
        """ Make directory """
        ret = self.smbobj.mkdir(directory)
        return ret
    
    def upload(self,source,dest=".",destfilename=""):
        return self.smbobj.put(source,dest,destfilename)
    
    def download(self, source, destdir = '.'):
        data = self.smbobj.get(source)
        
        if os.path.sep in destdir:
            # already path joined ..
            outname = destdir
        else:
            outname = os.path.join(destdir, source)

        if type(data) != type(0): # check for int

            try:
                f = file(outname, "wb+")
            except:
                return "[!] XXX: could not create destination file: %s" % outname

            f.write(data)
            f.close()

            return "[+] Wrote %d bytes to %s" % (len(data), outname)

        else:
            return "[!] XXX: SMB Object GET returned an int instead of data!"
