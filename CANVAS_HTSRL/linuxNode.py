#! /usr/bin/env python
"""
linuxNode.py

CANVAS License

A linux MOSDEF node.

"""

from MOSDEFNode import MOSDEFNode
from exploitutils import *
import linuxMosdefShellServer
from MOSDEFSock import MOSDEFSock
from MOSDEF import GetMOSDEFlibc

class linuxNode(MOSDEFNode):
    def __init__(self, proctype='i386'):
        MOSDEFNode.__init__(self)
        self.nodetype = "linuxNode"
        self.pix = "linuxMOSDEFNode"
        self.activate_text()
        self.shell = None
        self.hasrawsocks=None #initialized first time hasRawSocks is called
        self.capabilities = ["linux","Unix Shell", "posix", "VFS"]
        return
    
    def findInterfaces(self):
        """
        Most nodes need to be able to find all the active interfaces
        on their host. (UnixShellNode cannot, for example. SQL nodes cannot...)
        
        The Linux Node uses ioctl to do this - it can't be blocked by 
        chroot, etc.
        """
        self.log("Calling findInterfaces")
        vars = self.shell.libc.getdefines()
        code="""
        #include <sys/socket.h>
        #include <sys/ioctl.h>
        #include <net/if.h>
        #include <unistd.h>

        #import "local", "sendint" as "sendint"
        #import "local", "sendstring" as "sendstring"
 
        void main() {
          int s;
          int i;
          int j;
          struct ifreq *ifr;
          char addr[1005];
          char * c;
          struct ifconf ifc;

          ifc.ifc_len=1000;
          ifc.addr=addr;
          
          s=socket(AF_INET,SOCK_STREAM,0);
          ioctl(s,SIOCGIFCONF,&ifc);
          j=ifc.ifc_len; //there are j records in the return value
          sendint(j); //send the number of records
          c=ifc.addr;
          i=0;
          while (i<j) {
             ifr=c;
             // debug();
             sendstring(ifr->ifr_name); //send the string of the interface name

             c=c+32;
             i=i+32;
          }

          close(s);
        }
        """
        self.shell.clearfunctioncache()
        message=self.shell.compile(code,vars)
        self.shell.sendrequest(message)
        j=self.shell.readint()/32
        interfaces=[]
        self.log("Reading %d interfaces from remote side"%j)
        for i in range(0,j):
            interfaces.append(self.shell.readstring())
        self.shell.leave()
        #print "Interfaces: %s"%interfaces
        #now that we have all the interfaces, we need to get the ip and network
        #for each of them
        for i in interfaces:
            #print "Getting ip for %s"%i
            ip=self.ipFromInterface(i)
            #print "ip=%s:%s"%(i,ip)
            netmask=self.netmaskFromInterface(i)
            #print "netmask %s:%s" % (i, uint32fmt(netmask))
            self.interfaces.add_ip((i,ip,netmask))
            
        return interfaces

    def hasRawSocks(self):
        """
        Overrides CANVASNode::hasRawSocks() because in the case where we are
        running as root on this remote node, then we need to be able to tell the user
        it's ok to do raw sockets. Our MOSDEFSock library can do raw sockets, which 
        means we can test it that way.
        """
        #we set this the first time, to avoid constantly creating sockets
        if self.hasrawsocks!=None:
            return self.hasrawsocks 
        sock=self.shell.bindraw()
        if sock!=-1:
            self.hasrawsocks=True
            self.shell.close(sock) #close it now to avoid fd leak
        else:
            self.hasrawsocks=False
        return self.hasrawsocks
        
    def ipFromInterface(self,interface):
        """
        gets the ip from an interface name using ioctl
        """
        
        vars = self.shell.libc.getdefines()
        vars["ifname"]=interface
        code="""
        #import "string","ifname" as "ifname"
        #import "local","close" as "close"
        #import "int", "AF_INET" as "AF_INET"
        #import "int", "SOCK_STREAM" as "SOCK_STREAM"
        #import "int", "SIOCGIFADDR" as "SIOCGIFADDR"
        #import "local","ioctl" as "ioctl"
        #import "local","socket" as "socket"
        #import "local","strcpy" as "strcpy"
        #import "local","sendint" as "sendint"
        
        #include "socket.h"

        struct ifreq {
          char ifr_name[16];
          struct sockaddr_in addr; // I hope this is right. :> Hey, it is! :>
        };
        
        struct ifconf {
          int ifc_len;
          char * addr;
        };
        
        void main() {
          int s;
          int i;
          int j;
          struct ifreq ifr;
          char addr[1005];
          char * c;
          struct ifconf ifc;
          struct sockaddr_in *sa;
          
          sa=&ifr.addr;
          s=socket(AF_INET,SOCK_STREAM,0);
          strcpy(ifr.ifr_name,ifname);
          ioctl(s,SIOCGIFADDR,&ifr);
          j=sa->addr;
          sendint(j); //send the ip
          close(s);
        }
        """
        self.shell.clearfunctioncache()
        message=self.shell.compile(code,vars)
        self.shell.sendrequest(message)
        r=self.shell.reliableread(4) #read it like a buffer, although it used sendint
        IP = socket.inet_ntoa(r)
        self.shell.leave()
        return IP
    
    def netmaskFromInterface(self,interface):
        """
        gets the netmask from an interface name using ioctl
        """
        
        vars = self.shell.libc.getdefines()
        vars["ifname"]=interface
        code="""
        #import "string","ifname" as "ifname"
        #import "local","close" as "close"
        #import "int", "AF_INET" as "AF_INET"
        #import "int", "SOCK_STREAM" as "SOCK_STREAM"
        #import "int", "SIOCGIFNETMASK" as "SIOCGIFNETMASK"
        #import "local","ioctl" as "ioctl"
        #import "local","socket" as "socket"
        #import "local","strcpy" as "strcpy"
        #import "local","sendint" as "sendint"
        
        #include "socket.h"

        struct ifreq {
          char ifr_name[16];
          struct sockaddr_in addr; // I hope this is right. :> Hey, it is! :>
        };
        
        struct ifconf {
          int ifc_len;
          char * addr;
        };
        
        void main() {
          int s;
          int i;
          int j;
          struct ifreq ifr;
          char addr[1005];
          char * c;
          struct ifconf ifc;
          struct sockaddr_in *sa;
          
          sa=&ifr.addr;
          s=socket(AF_INET,SOCK_STREAM,0);
          strcpy(ifr.ifr_name,ifname);
          ioctl(s,SIOCGIFNETMASK,&ifr);
          j=sa->addr;
          sendint(j); //send the ip
          close(s);
        }
        """
        self.shell.clearfunctioncache()
        message=self.shell.compile(code,vars)
        self.shell.sendrequest(message)
        r=self.shell.reliableread(4) #read it like a buffer, although it used sendint
        netmask = str2bigendian(r)
        self.shell.leave()
        return netmask
    
    def createListener(self,addr,port):
        """
        Creates a listening mosdefsock on a port/interface
        """
        fd=self.shell.getListenSock(addr,port)
        devlog("linuxNode","FD returned from getListenSock=%s"%fd)
        if fd<0:
            return 0
        s=MOSDEFSock(fd,self.shell) #a mosdef object for that fd (wraps send, recv, etc) and implements timeouts
        s.set_blocking(0) #set non-blocking
        s.reuse()
        return s

    def fexec(self,command,args,env):
        return self.shell.fexec(command,args,env)
    
    def dir(self,directory):
        #we could filter out shell escape characters here...
        #return self.shell.runcommand("ls -lart %s"%directory)
        
        #d_name = self.readstring()
        #statbuf=self.readstruct([("s","st_mode"),
        #                         ("s","st_uid"),
        #                         ("s","st_gid"),
        #                         ("l","st_size"),
        #                         ("l","st_mtime")])
        #self.files.append( (d_name, statbuf) )
        
        S_IFMT = 0x017000
        IFDIR  = 0x4000
        
        UREAD  = 0x100
        UWRITE = 0x80
        UEXEC  = 0x40
        
        GREAD  = 0x20
        GWRITE = 0x10
        GEXEC  = 0x8
        
        OREAD  =  0x4   
        OWRITE =  0x2  
        OEXEC  =  0x1
        
        
        ret = self.shell.dodir(directory)
        out = []
        FFLAGS = ["_", "d"]
        RFLAGS = ["_", "r"]
        WFLAGS = ["_", "w"]
        XFLAGS = ["_", "x"]
        
        for (filename, statbuf) in ret:
            flags = []
            flags.append( FFLAGS [bool( ( statbuf["st_mode"] & S_IFMT) == IFDIR )] )
            flags.append( RFLAGS [bool( ( statbuf["st_mode"] & UREAD)  )] )
            flags.append( WFLAGS [bool( ( statbuf["st_mode"] & UWRITE) )] )
            flags.append( XFLAGS [bool( ( statbuf["st_mode"] & UEXEC)  )] )
            flags.append( RFLAGS [bool( ( statbuf["st_mode"] & GREAD)  )] )
            flags.append( WFLAGS [bool( ( statbuf["st_mode"] & GWRITE) )] )
            flags.append( XFLAGS [bool( ( statbuf["st_mode"] & GEXEC)  )] )
            flags.append( RFLAGS [bool( ( statbuf["st_mode"] & OREAD)  )] )
            flags.append( WFLAGS [bool( ( statbuf["st_mode"] & OWRITE) )] )
            flags.append( XFLAGS [bool( ( statbuf["st_mode"] & OEXEC)  )] )
            out.append("%s   %6d %6d  %10d %s %s" % ("".join(flags), statbuf["st_uid"], statbuf["st_gid"],\
                                                      statbuf["st_size"], time.ctime(statbuf["st_mtime"]), filename) ) 
        return out
    
            
        
    # VFS Routines 
    def vfs_dir(self, path):
        # returns (afile, st_size, st_mtime, is_dir)
        S_IFMT = 00170000
        IFDIR  = 0040000
        ret = self.shell.dodir(path)
        out = []
        for (filename, statbuf) in ret:
            isdir = bool( ( statbuf["st_mode"] & S_IFMT) == IFDIR )
            isexe = bool(statbuf["st_mode"] & 0x49 ) # User, group and other EXE
            out.append( (filename, statbuf["st_size"], statbuf["st_mtime"], {"is_dir":isdir, "is_exe": isexe} ))
        #entries = self.shell.runcommand("ls %s" % path)
        #return entries.split('\n')
        return out

    def vfs_upload(self, path, dest):
        ret = self.shell.upload( path, dest )
        return ret
    
    def vfs_download(self, path, dest):
        ret = self.download( path, dest )
        return ret

    def vfs_stat(self, path):
        print "XXX: linuxNode stat %s" % path 
        ret,statbuf = self.shell.stat(path)
        
        if ret:
            # failed
            print "XXX: VFS linuxNode stat failed"
            retstat    = (0, 0, {"is_dir": True })
        else:
            # determine if it's a directory from the mode
            # I guess technically we should pull these
            # from the MOSDEFLibc
            S_IFMT      = 00170000
            S_IFSOCK    = 0140000
            S_IFLNK     = 0120000
            S_IFREG     = 0100000
            S_IFBLK     = 0060000
            S_IFDIR     = 0040000
            S_IFCHR     = 0020000
            S_IFIFO     = 0010000
            S_ISUID     = 0004000
            S_ISGID     = 0002000
            S_ISVTX     = 0001000
            m           = statbuf['st_mode']
            attr        = {}
            isexe = bool(statbuf["st_mode"] & 0x49 ) # User, group and other EXE
            attr["is_dir"] = bool( ((m & S_IFMT) == S_IFDIR) )            
            attr["is_exe"] = isexe
            retstat        = (statbuf['st_size'], statbuf['st_mtime'], attr)
        return retstat
    
if __name__=="__main__":
    node=linuxNode()

