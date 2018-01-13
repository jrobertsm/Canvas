#! /usr/bin/env python

"""
osxNode.py

CANVAS License

A OSX MOSDEF node.

"""

from MOSDEFNode import MOSDEFNode
from exploitutils import *
from MOSDEFSock import MOSDEFSock
import struct,socket

class osxNode(MOSDEFNode):
    def __init__(self):
        MOSDEFNode.__init__(self)
        self.nodetype = "osxNode"
        self.pix = "osxMOSDEFNode"
        self.activate_text()
        self.shell = None
        self.capabilities=["bsd", "posix", "Unix Shell", "VFS"]

        return       
            
    def findInterfaces(self):
        self.log("Calling findInterfaces")
        vars = self.shell.libc.getdefines()
        code="""
        #import "local","sendint" as "sendint"
        #import "local","sendstring" as "sendstring"
        #import "local","close" as "close"
        #import "local","ioctl" as "ioctl"
        #import "local","socket" as "socket"
        
        #include <sys/socket.h>

        struct ifreq {
          char ifr_name[16];
          char sa_len;
          char arg[15];
        };
        
        struct ifconf {
          int ifc_len;
          char * addr;
        };
        int max(int a, int b) {
           if( a > b) {
           return a;
           }
           else {
              return b;
           }
        }
        
        void main() 
        {
          int s;
          int i;
          int j;
          int size;
          struct ifreq *ifr;
          char addr[2005];
          char * c;
          struct ifconf ifc;

          ifc.ifc_len = 2000;
          ifc.addr = addr;

          s = socket(0x2, 0x2, 0);

          ioctl(s, 0xc0086924, &ifc); // SIOCGIFCONF
          
          j = ifc.ifc_len; //there are j records in the return value          
          c = ifc.addr;
          i = 0;
          
          while (i<j) 
          {
             ifr = c;
             sendstring(ifr->ifr_name); //send the string of the interface name

             // A little twist presented by MAC OSX 10.x :>
             size= max(32, 16 + ifr->sa_len);
             
             c = c+size;
             i = i+size;
          }
          sendstring("end");
          close(s);
        }
        """
        self.shell.clearfunctioncache()
        message = self.shell.compile(code,vars)
        self.shell.sendrequest(message)
        interfaces = {}
        while 1:
            face = self.shell.readstring()
            if face == "end":
                break
            interfaces[face] = None
        self.shell.leave()

        for i in interfaces.keys():
            print "Getting ip for %s"%i
            try:
                ip = self.ipFromInterface(i)
            except Exception:
                print "XXX: Exception in ipFromInterface"
                continue
            #print "ip=%s:%s"%(i,ip)
            netmask = self.netmaskFromInterface(i)
            #print "netmask %s:%x"%(i,netmask)
            self.interfaces.add_ip((i, ip, netmask))
        return interfaces

    def ipFromInterface(self,interface):
        """
        gets the ip from an interface name using ioctl
        """
        
        SIOCGIFADDR = 0xc020690dL
        vars = self.shell.libc.getdefines()
        vars["ifname"] = interface
        code="""
        #import "string","ifname" as "ifname"
        #import "local","close" as "close"
        #import "local","ioctl" as "ioctl"
        #import "local","socket" as "socket"
        #import "local","strcpy" as "strcpy"
        #import "local","sendint" as "sendint"
        
        #include <sys/socket.h>

        struct ifreq {
          char ifr_name[16];
          struct sockaddr_in addr; // I hope this is right. :> Hey, it is! :>
        };
        
        struct ifconf {
          int ifc_len;
          char * addr;
        };
        
        void main() 
        {
          int s;
          int i;
          int j;
          struct ifreq ifr;
          char addr[1005];
          char * c;
          struct ifconf ifc;
          struct sockaddr_in *sa;
          
          sa = &ifr.addr;
          s = socket(AF_INET,SOCK_STREAM,0);
          strcpy(ifr.ifr_name, ifname);

          // SIOCGIFADDR
          if(ioctl(s,0xc0206921,&ifr) != -1) 
          { 
             j = sa->sin_addr_s_addr;
             sendint(j); //send the ip
          } 
          else 
          {
             sendint(0);
          }
          
          close(s);
        }
        """

        self.shell.clearfunctioncache()
        message = self.shell.compile(code,vars)
        self.shell.sendrequest(message)
        r = self.shell.reliableread(4)

        self.shell.leave()        

        if r == 0:
            raise Exception, "No IP found"
        
        return socket.inet_ntoa(r)
    
    def netmaskFromInterface(self,interface):
        """
        gets the netmask from an interface name using ioctl
        """
        
        SIOCGIFNETMASK = 0xc0206919L
        vars = self.shell.libc.getdefines()
        vars["ifname"] = interface
        code="""
        #import "string","ifname" as "ifname"
        #import "local","close" as "close"
        #import "local","ioctl" as "ioctl"
        #import "local","socket" as "socket"
        #import "local","strcpy" as "strcpy"
        #import "local","sendint" as "sendint"
        
        #include <sys/socket.h>

        struct ifreq {
          char ifr_name[16];
          struct sockaddr_in addr;
        };
        
        struct ifconf {
          int ifc_len;
          char * addr;
        };
        
        void main() 
        {
          int s;
          int i;
          int j;
          struct ifreq ifr;
          char addr[1005];
          char * c;
          struct ifconf ifc;
          struct sockaddr_in *sa;
          
          sa = &ifr.addr;
          s = socket(AF_INET,SOCK_STREAM,0);
          strcpy(ifr.ifr_name,ifname);
          ioctl(s,0xc0206925,&ifr); // SIOCGIFNETMASK
          j = sa->sin_addr_s_addr;
          sendint(j); //send the ip
          close(s);
        }
        """
        self.shell.clearfunctioncache()
        message = self.shell.compile(code,vars)
        self.shell.sendrequest(message)
        r=self.shell.reliableread(4) #read it like a buffer, although it used sendint
        netmask = str2bigendian(r)
        self.shell.leave()
        return netmask

    def findHost(self):
        # XXX: skip for now until we figure out the new __sysctl
        if 1:
            return
        
        vars = self.shell.libc.getdefines()
        self.log("Calling findHost")

        code="""
        #import "local", "sysctl" as "sysctl"
        #import "local", "mmap" as "mmap"
        #import "local", "munmap" as "munmap"
        #import "local", "debug" as "debug"
        #import "local", "sendint" as "sendint"
        
        void main() 
        {
          int mib[6];
          unsigned long i;
          unsigned long msglen;
          long *buf;
          unsigned long a;
          long addr;
          unsigned long needed;
          
          mib[0] = 4;     // CTL_NET
          mib[1] = 17;    // AF_ROUTE
          mib[2] = 0;
          mib[3] = 2;     // AF_INET
          mib[4] = 2;     // NET_RT_FLAGS
          mib[5] = 0x400; // RTF_LLINFO

          
          i=sysctl(mib, 6, 0x0, &needed, 0);
          buf = mmap(0, needed, 7, 0x1002, -1, 0);

          i=sysctl(mib, 6, buf, &needed, 0);
          i=0;
          needed= needed/4;
          
          while(i < needed) 
          {
                 //debug();
                 msglen = buf[i]>>16;
                 
                 a=i + 24;

                 addr = buf[a];
                 sendint(addr);
                 
                 a= msglen/4;
                 i= i+ a;                 
                 
          }
          sendint(0);
          munmap(buf);
        }
          
        """
        self.shell.clearfunctioncache()
        message = self.shell.compile(code,vars)
        self.shell.sendrequest(message)
        ips = []
        while 1:
            ret = self.shell.readint()
            if ret == 0:
                break
            ips.append(socket.inet_ntoa(struct.pack("!L", uint32(ret)) ) )
        self.shell.leave()
        for a in ips:
            self.new_host(a)           
    
    def createListener(self,addr,port):
        fd = self.shell.getListenSock(addr,port)
        if fd < 0:
            if fd == -1:
                print "Remote getListenSock failed binding"
            return 0
        s = MOSDEFSock(fd, self.shell)
        s.set_blocking(0)
        s.reuse()
        return s

    def fexec(self,command, args, env):
        return self.shell.fexec(command, args, env)
    
    def dir(self,directory):
        # we could filter out shell escape characters here...
        return self.shell.runcommand("ls -lart %s" % directory)
    
    def vfs_dir(self, directory):
        lines = self.shell.runcommand("ls -lat %s" % directory)
        out = []
        for line in lines.split("\n"):
            if line:
                t = []
                for x in line.split(" "):
                    if x:
                        t.append(x)
                if len(t) < 7:
                    continue
                out.append( (t[-1], t[4] , " ".join(t[5:7]), {"is_dir": bool(t[0][0] == "d"), "is_exe": bool(t[0].find("x")>-1)} ))
        return out
    
    def vfs_stat(self, file):
        lines = string.strip( self.shell.runcommand("ls -lat %s" % file) )
        lines = lines.split("\n")
        line = None
        if len(lines) == 1: # Is a file:
            line = lines[0]
        else:
            for a in lines:
                if a.rstrip().rsplit(" ", 1) == ".":
                    line = a
                    break
        if not line:
            return (0, 0, {"is_dir": True })
        else:
            t = []
            for x in line.split(" "):
                if x:
                    t.append(x)
            if len(t) < 7:
                print "Error: Wrong line"
                return (0, 0, {"is_dir": True })
            return (t[4] , " ".join(t[5:7]), {"is_dir": bool(t[0][0] == "d"), "is_exe": bool(t[0].find("x")>-1)} )
                
    
    def vfs_download(self, path, dest):
        ret = self.shell.download( path, dest )
        return ret
    
    def vfs_upload(self, path, dest):
        ret = self.shell.upload( path, dest )
        return ret
    


