#! /usr/bin/env python

"""
the linux remote resolver. A kind of combination of libc and a few other things...
"""

from remoteresolver import remoteresolver


class linuxremoteresolver(remoteresolver):
    """
    Our remote resolver for linux
    
    Threading issue: Cannot call clearfunctioncache() and then
    call compile() as a two step process because another thread
    might call clearfunctioncache() in between, and that's very bad.
    
    So we call acquire() in clearfunctioncache() and then release()
    in compile() and we're good to go.
    """
    
    def __init__(self, proc, version = '2.6'):
        remoteresolver.__init__(self, 'Linux', proc, version)

    def initLocalFunctions(self):
        self.functioncache={}
 
        self.localfunctions["socket.h"]=("header","""
            struct sockaddr {
                unsigned short int family;
                char data[14];
            };
            
            struct sockaddr_in {
                unsigned short int family;
                unsigned short int port;
                unsigned int addr;
                char pad[6];
            };
            
            struct sockaddr_storage {
                //unsigned short int family;
                char padding[128];
            };
        """)
        
        # a bit like popen
        # XXX
        self.localfunctions["fexec"]=("c","""
        #import "local","syscall0" as "syscall0"
        int fexec(char *command) {
            
        }
        """)
        
        #fd_zero and fd_set stolen from BSD
        self.localfunctions["FD_ZERO"]=("c","""
        #import "local", "memset" as "memset"
        int 
        FD_ZERO(int *fd_set) {
            memset(fd_set,0,128);
            return 1;
        }
        """)
        
        self.localfunctions["FD_SET"]=("c","""
        #import "local", "memset" as "memset"
        void
        FD_SET(int fd, int *fd_set) {
            int index;
            int flag;
            int *p;
            int bucket;
            int oldvalue;
            int newvalue;
            
            flag=1;
            index=fd%32;
            //index=32-index;
            bucket=fd/32;
            while (index>0) {
                flag=flag<<1;
                index=index-1;
            }
            //now flag has our bit value set
            p=fd_set+bucket;
            oldvalue=*p;
            newvalue=oldvalue|flag;
            *p=newvalue;
        }
        """)
        
        #
        #end syscalls, begin libc functions
        #
        
        # XXX: all libc functions using self.fd go into crippleC.py !
        # XXX: self.fd is then re-set properly using initStaticFunctions ;)

class x86linuxremoteresolver(linuxremoteresolver):
    
    def __init__(self, proc="i386", version = '2.4'):
        linuxremoteresolver.__init__(self, 'i386', version)
    
    def initLocalFunctions(self):
        linuxremoteresolver.initLocalFunctions(self)
        
        # FIXME move in <MOSDEF/MOSDEFlibc/asm/i386.py> ? (int 80 is a linux-ism so prolly not)
        self.localfunctions["sendint"]=("asm","""
        sendint:
        //.byte 0xcc
        push %ebp
        movl %esp, %ebp
        push %ebx
        push %ecx
        movl 8(%ebp),%eax
        pushl %eax //push the argument we were passed
        xorl %eax,%eax
        pushl %eax //flags of zero
        movb $4,%al
        pushl %eax //length of 4
        leal 8(%ebp),%ecx
        pushl %ecx //message 
        pushl $FDVAL
        xorl %ecx,%ecx
        movl %esp,%ecx
        xorl %ebx,%ebx
        movb $9,%bl
        movb $102,%al // send(2)
        int $0x80 // send 1 word on fd
        addl $20,%esp //reset stack pointer
        popl %ecx
        popl %ebx
        movl %ebp,%esp
        popl %ebp
        ret  $4
        """.replace("FDVAL",str(self.fd)))
        

class ppclinuxremoteresolver(linuxremoteresolver):
    def __init__(self, proc="powerpc", version = '2.6'):
        linuxremoteresolver.__init__(self, 'powerpc', version)
    
    def initLocalFunctions(self):
        linuxremoteresolver.initLocalFunctions(self)

