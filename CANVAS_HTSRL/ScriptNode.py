#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
ScriptNode.py - used for remote connections from eval() in a scripting environment
"""

from CANVASNode import CrossPlatformNode
from exploitutils import *
from canvaserror import *
from MOSDEFNode import MOSDEFNode
from MOSDEFSock import MOSDEFSock

class ScriptNode(CrossPlatformNode, MOSDEFNode):
    def __init__(self):
        CrossPlatformNode.__init__(self)
        MOSDEFNode.__init__(self)
        self.nodetype="ScriptNode"
        self.pix="ScriptNode"
        self.capabilities +=  ["upload","download","sock"]
        self.activate_text()
        return 
    
    def recv(self, sock, length):
        return MOSDEFNode.recv(self,sock,length)
    
    def send(self,sock,message):
        return MOSDEFNode.send(self,sock,message)
        
    def getInfo(self):
        
        phpver = self.shell.getPHPVersion()
        self.hostsknowledge.get_localhost().add_knowledge("PHP Version", phpver, 100)
        
        ini = {}
        for i in ["safe_mode", "register_globals", "allow_url_fopen", "allow_url_include"]:
            ini[i] = self.shell.getPHPIniVal(i)
        self.hostsknowledge.get_localhost().add_knowledge("PHP Config", ini, 100)
        
        info = {}
        for i in ["SERVER_SOFTWARE", "SERVER_NAME", "SERVER_ADDR", "SERVER_PORT", "REMOTE_ADDR", "DOCUMENT_ROOT"]:
            info[i] = self.shell.getPHPVar("_SERVER['%s']" % i)
            
        for i in ["PATH", "LANG"]:
            info[i] = self.shell.getPHPVar("_ENV['%s']" % i)
        
        self.hostsknowledge.get_localhost().add_knowledge("PHP Info", info, 100)
        
        os = self.shell.getPlatformInfo()
        if os != None:
            self.hostsknowledge.get_localhost().add_knowledge("OS", os, 100)
        
        try:
            uid,euid,gid,egid = self.shell.ids()
        except NodeCommandError, i:
            pass
        
        #now try to get the pid
        try:
            pid=self.shell.getpid()
            self.log("PID: %d"%pid)
        except NodeCommandError, i:
            pass 
        
        if self.isOnAUnix():
            self.capabilities.append("Unix Shell")
            if hasattr(self.shell, "dospawn"):
                self.capabilities.append("spawn") #we emulate dospawn with the & shell character. This is important for converttomosdef module.
                self.spawn=self.unix_spawn
        return os

    def unix_spawn(self,filename):
        devlog("node", "unix_spawn called with filename: %s"%filename)
        ret = self.shell.dospawn(filename)
        devlog("node", "unix_spawn returning %s"%ret)
        return ret
    
    def createListener(self,addr,port):
        """Create a listener for a connectback"""
        fd=self.shell.getListenSock(addr,port)
        if fd==0:
            return 0
        devlog("phplistener","Created a listener socket: %d"%fd)
        s=MOSDEFSock(fd,self.shell) #a mosdef object for that fd (wraps send, recv, etc) and implements timeouts
        s.set_blocking(0) #set non-blocking
        s.reuse()
        return s
    
if __name__=="__main__":
    node=ScriptNode()

