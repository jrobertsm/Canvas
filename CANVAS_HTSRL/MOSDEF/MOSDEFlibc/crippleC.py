#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

from MLCutils import MLCutils
from C_headers import C_headers

class crippleC(MLCutils, C_headers):
    
    def __init__(self):
        # Warning: self.localfunctions could have be initialized before.
        # XXX where ? something weird here, since MLCutils is called after.
        if not hasattr(self, 'localfunctions'):
            self.localfunctions = {}

        MLCutils.__init__(self)
        C_headers.__init__(self)
        self._crippleC_initLocalFunctions()
    
    def init_shortcut_vars(self):
        if hasattr(self, 'O_NONBLOCK'):
            self.O_BLOCK = ~self.O_NONBLOCK
        if hasattr(self, 'S_IRWXU') and hasattr(self, 'S_IRWXG') and hasattr(self, 'S_IRWXO'):
            self.MODE_ALL = self.S_IRWXU|self.S_IRWXG|self.S_IRWXO
        # XXX <stdio.h>
        self.EOF = -1
    
    def _crippleC_initLocalFunctions(self):
        #print "crippleC_initLocalFunctions: %s"%(str(self.localfunctions.get("htons")))
        #############
        #
        #  string.h
        #
        #############
        
        self.localfunctions["memset"] = ("c", """
        int
        memset(char *outstr, int outbyte, int size)
        {
            int i;
            char *p;
            
            i = 0;
            p = outstr;
            while (i < size) {
                i = i + 1;
                *p = outbyte;
                p = p + 1;
            }
            
            return i;
        }
        """)
        
        self.localfunctions["memcpy"] = ("c", """
        char *
        memcpy(char *dst, char *src, int size)
        {
            char c;
            char *ret;
            
            ret = dst;
            while (size > 0) {
                c = *src;
                *dst = c;
                src = src + 1;
                dst = dst + 1;
                size = size - 1;
            }
            
            return ret;
        }
        """)
        
        self.localfunctions["strlen"] = ("c", """
        int strlen(char *instr)
        {
            int i;
            char *p;
            
            i = 0;
            p = instr;
            while (*p != 0) {
                p = p + 1;
                i = i + 1;
            }
            
            return i;
        }
        """)
        
        self.localfunctions["strcpy"] = ("c", """
        int strcpy(char *outstr, char *instr)
        {
            int i;
            char *p;
            char *y;
            char c;
            
            i = 0;
            p = instr;
            y = outstr;
            while (*p != 0) {
                c = *p;
                *y = c;
                y = y + 1;
                p = p + 1;
                i = i + 1;
            }
            *y = 0;
            
            // XXX should return outstr
            return i;
        }
        """)

        self.localfunctions["strcat"] = ("c", """
        int strcat(char *outstr, char *instr)
        {
            int i;
            char *y;
            char *p;
            char  c;
            i = 0;
            y = outstr;
            p = instr;
            
            while (*y != 0) {
                y = y + 1;
                i = i + 1;
            }
            
            while( *p != 0) {
                c = *p;
                *y = c;
                y = y + 1;
                p = p + 1;
                i = i + 1;
            }
            *y = 0;
            
            return i;
        }
        """)
        
        #############
        #
        #  string.h
        #
        #############
        
        self.localfunctions["bzero"] = ("c", """
        #include <string.h>
        
        void
        bzero(char *ptr, int size)
        {
            memset(ptr, 0, size);
        }
        """)
        
        self.localfunctions["bcopy"] = ("c", """
        #include <string.h>
        
        void
        bcopy(char *src, char *dst, int size)
        {
            memcpy(dst, src, size);
        }
        """)
        
        #############
        #
        #  ctype.h
        #
        #############
        
        self.localfunctions["isdigit"] = ("c", """
        int
        isdigit(int c)
        {
            if (c < '0') {
                return 0;
            }
            if (c > '9') {
                return 0;
            }
            return 1;
        }
        """)
        
        #############
        #
        #  stdlib.h
        #
        #############
        
        self.localfunctions["exit"] = ("c", """
        #include <unistd.h>
        
        void exit(int status)
        {
            _exit(status);
        }
        """)
        
        self.localfunctions["atoi"] = ("c", """
        #include <ctype.h>
        
        int
        atoi(char *p)
        {
            int n;
            int cond;
            long t;
            long r;
            
            n = 0;
            if (*p == '-') {
                n = -1;
                p = p + 1;
            }
            r = 0;
            cond = 1;
            while (cond) {
                if (*p == '\0') {
                    cond = 0;
                } else {
                    if (isdigit(*p) == 0) {
                        cond = 0;
                    }
                }
                if (cond) {
                    t = *p;
                    t = t - '0';
                    r = r * 10;
                    r = r + t;
                    p = p + 1;
                }
            }
            if (n) {
                r = r * n;
            }
            return r;
        }
        """)
        
        # XXX
        self.localfunctions["malloc"] = ("c", """
        #include <stdlib.h>
        #warn "broken malloc()"
        
        char *
        malloc(int size)
        {
            char buf[1024];
            return buf;
        }
        """)
        
        # XXX
        self.localfunctions["free"] = ("c", """
        #include <stdlib.h>
        #warn "broken free()"
        
        void
        free(char *ptr)
        {
            return;
        }
        """)
        
        #############
        #
        #  stdio.h
        #
        #############
        
        # XXX '\n' breaks MOSDEF here.
        self.localfunctions["puts"] = ("c", """
        #include <unistd.h>
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        
        int
        puts(char *s)
        {
            int len;
            int ret;
            char *p;
            
            len = strlen(s);
            p = malloc(len + 1);
            if (p == NULL) {
                return EOF;
            }
            memcpy(p, s, len);
            p[len] = 0x0a; // MOSDEF problem with 'back n'
            len = len + 1;
            ret = write(STDOUT_FILENO, p, len);
            free(p);
            if (ret != len) {
                return EOF;
            }
            return len;
        }
        """)
        
        ################
        #
        # network utils
        #
        ################
        
        self.localfunctions["writeblock"]=("c","""
        #import "local", "write" as "write"
        int writeblock(int fd, char *instr, int size) {
            int left;
            int i;
            char *p;
            
            left = size;
            p = instr;
            
            while (left > 0) {
                i = write(fd, p, left);
                if (i < 1) {
                    return 0;
                }
                left = left - i;
                p = p + i;
            }
            return 1;
        }
        """)
        
        self.localfunctions["sendblock"]=("c","""
        #import "local", "writeblock" as "writeblock"
        #import "local", "sendint" as "sendint"
        
        int sendblock(int fd, char *buf, int size)
        {
            int i;
            
            sendint(size);
            i = writeblock(fd, buf, size);
            
            return i;
        }
        """)
        
        # FIXME is that really useful?
        self.localfunctions["writestring"]=("c","""
        #import "local","sendblock" as "sendblock"
        #import "local","strlen" as "strlen"
        
        int writestring(int fd, char *string) {
            
            sendblock(fd, string, strlen(string));
            
        }
        """)
        
        # XXX yo wtf is that?
        # TODO: move it in CANVAS/MOSDEFShellServer or CANVAS/MOSDEF/MOSDEFlibc/libs/libhttp or something.
        # move below in initStaticFunctions() at least
        # XXX
        #reads an HTTP header from an FD
        #also takes in a timeout value
        #if the timeout value expires, returns 0
        #else returns 1 and then the header as a block of data
        #this function avoids having loops on the Python side
        if 0:
            self.localfunctions["readHTTPheader"]=("c","""
            #import "local", "sendblock" as "sendblock"
            #import "local", "sendint" as "sendint"
            #import "local", "readLineFromFD" as "readLineFromFD"
            #import "local", "malloc" as "malloc"
            #import "local,  "free" as "free"
            #import "local", "isactive" as "isactive"
            int readHTTPheader(int fd, int timeout)
            {
                int done;
                int i;
                char buf[3000]; //a three thousand byte buffer for our header.            
                int size;
                char * p;
                char * p2;
                int ret;
                
                p=buf;
                size=0;
                done=0;
                while (!done) {
                   //fd must have something on it otherwise we'll get stuck if we're not in async mode
                    if isactive(fd,timeout) {
                       ret=recv(fd,p,1,0); //recv our one byte
                       if (ret<0) {
                         done=-1; //we are done, but with an error.
                       }
                       size=size+1;
                       if (size==3000)
                       {
                          //we recved a massive header - and hence we're done with some error val.
                          done=-1;
                       }
                       if (size >=4 ) {
                           //check for \r\n\r\n
                           p2=p-4; //go four bytes back
                           if (!strcmp(p2,"\r\n\r\n"))
                           {
                             //we have found the end of our buffer!
                             done=1;
                           }
                       }
                    } else {
                       //we are done but with an error due to timeout
                       done=-1;
                    }
                    
                
                sendblock(STATIC_FD, buf, size);
                
                return i;
            }
            """.replace("STATIC_FD",str(self.fd)))
        
    def initStaticFunctions(self, kvars = {'fd': 666}):
        for key in kvars.keys():
            #if hasattr(self, key):
            #    print "overwritting self.%s = %d" % (key, getattr(self, key))
            #print "STATIC[%s] = %s" % (key, kvars[key])
            setattr(self, key, kvars[key])
        
        self.localfunctions["sendint"] = ("c", """
        #import "local", "write" as "write"
        
        int sendint(int val)
        {
            int r;
            int i;
            
            i = val;
            r = write(STATIC_FD, &i, 4);
            
            return r;
        }
        """.replace("STATIC_FD", str(self.fd)))
        
        self.localfunctions["sendstring"]=("c","""
        #import "local", "sendblock" as "sendblock"
        #import "local", "strlen" as "strlen"
        
        int sendstring(char *instr)
        {
            int i;
            int len;
            
            len = strlen(instr);
            i = sendblock(STATIC_FD, instr, len);
            
            return i;
        }
        """.replace("STATIC_FD", str(self.fd)))

        self.localfunctions["sendblock2self"]=("c","""
        #import "local","writeblock" as "writeblock"
        #import "local","strlen" as "strlen"
        #import "local","sendint" as "sendint"
        
        int sendblock2self(char * buf, int size) {
            sendint(size);
            writeblock(FD,buf,size);
        }
        """.replace("FD",str(self.fd)))

        self.localfunctions["writeblock2self"]=("c","""
        #import "local","writeblock" as "writeblock"
        #import "local","strlen" as "strlen"
        #import "local","sendint" as "sendint"

        int writeblock2self(char * buf, int size) {
            writeblock(FD,buf,size);
        }
        """.replace("FD",str(self.fd)))

        self.localfunctions["writestring"]=("c","""
        #import "local","sendblock" as "sendblock"
        #import "local","strlen" as "strlen"
        int writestring(int fd, char * outstr) {
            sendblock(fd,outstr,strlen(outstr));
        }
        """)

        #our reliable reading function
        self.localfunctions["readblock"]=("c","""
        #import "local","read" as "read"
        #import "local","strlen" as "strlen"
        int readblock(int fd, char * outstr,int size) {
            int left;
            int i;
            char * p;
            left=size;
            p=outstr;
            while (left > 0) {
            i=read(fd,p,left);
            if (i<0) {
                return 0;
            }
            left=left-i;
            p=p+i;
            }
            return 1;
        }
        """)

        self.localfunctions["sendshort"]=("c","""
        #import "local","writeblock" as "writeblock"
        void sendshort(short tosend)
        {
            short i;
            i=tosend;
            writeblock(SOCKETFD, &i,2);
        }
        """.replace("SOCKETFD",str(self.fd)))

