#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

TODO = """
    - add x86_64
    - check ia64
"""

from GNU import GNU
from asm.Linux.i386 import i386
from asm.Linux.ppc import ppc

import re

class Linux(GNU):
    
    # <bits/fcntl.h>
    
    O_RDONLY =         00
    O_WRONLY =         01
    O_RDWR =           02
    O_APPEND =      02000
    O_NONBLOCK =    04000
    O_NDELAY = O_NONBLOCK
    O_LARGEFILE = 0100000
    
    O_CREAT =  0100
    O_EXCL =   0200
    O_NOCTTY = 0400
    O_TRUNC =  01000
    
    F_DUPFD = 0
    F_GETFD = 1
    F_SETFD = 2
    F_GETFL = 3
    F_SETFL = 4
    
    # <bits/socket.h>
    
    PF_LOCAL  = 1
    PF_UNIX   = PF_LOCAL
    PF_INET   = 2
    PF_INET6  = 10
    PF_KEY    = 15
    PF_PACKET = 17
    
    AF_UNIX   = PF_UNIX
    AF_INET   = PF_INET
    AF_INET6  = PF_INET6
    AF_KEY    = PF_KEY
    AF_PACKET = PF_PACKET
    
    MSG_OOB =  0x1
    MSG_PEEK = 0x2
    
    # <sys/socket.h>
    
    SHUT_RD =   0
    SHUT_WR =   1
    SHUT_RDWR = 2
    
    # <bits/signum.h>
    
    SIGBUS = 2
    
    SIG_ERR = -1
    SIG_DFL = 0
    SIG_IGN = 1
    
    # <linux/sockios.h>
    
    SIOCGIFCONF = 0x8912
    SIOCGIFADDR = 0x8915
    SIOCGIFNETMASK = 0x891b
    SIOCGIFINDEX = 0x8933
    
    # <bits/errno.h>
    
    ECANCELED = 125
    
    # <linux/prctl.h>
    
    PR_SET_PDEATHSIG = 1
    PR_GET_PDEATHSIG = 2
    PR_GET_DUMPABLE = 3
    PR_SET_DUMPABLE = 4
    PR_GET_UNALIGN = 5
    PR_SET_UNALIGN = 6
    PR_GET_KEEPCAPS = 7
    PR_SET_KEEPCAPS = 8
    PR_GET_TIMING = 13
    PR_SET_TIMING = 14
    PR_SET_NAME = 15
    PR_GET_NAME = 16
    
    # <sys/mman.h>
    
    MAP_FAILED = -1
    
    # <netinet/in.h>
    
    IPPROTO_IP = 0
    IPPROTO_ICMP = 1
    IPPROTO_IGMP = 2
    IPPROTO_IPIP = 4
    IPPROTO_TCP = 6
    IPPROTO_EGP = 8
    IPPROTO_UDP = 17
    IPPROTO_IPV6 = 41
    IPPROTO_RSVP = 46
    IPPROTO_GRE = 47
    IPPROTO_ESP = 50
    IPPROTO_AH = 51
    IPPROTO_ICMPV6 = 58
    IPPROTO_RAW = 255
    
    INET_ADDRSTRLEN  = 16
    INET6_ADDRSTRLEN = 46

    ETH_P_IP = 0x0800
    
    # <linux/net.h>
    SYS_SOCKET      = 1
    SYS_BIND        = 2
    SYS_CONNECT     = 3
    SYS_LISTEN      = 4
    SYS_ACCEPT      = 5
    SYS_GETSOCKNAME = 6
    SYS_GETPEERNAME = 7
    SYS_SOCKETPAIR  = 8
    SYS_SEND        = 9
    SYS_RECV        = 10
    SYS_SENDTO      = 11
    SYS_RECVFROM    = 12
    SYS_SHUTDOWN    = 13
    SYS_SETSOCKOPT  = 14
    SYS_GETSOCKOPT  = 15
    SYS_SENDMSG     = 16
    SYS_RECVMSG     = 17
    
    _socketcall_functions = [
        "socket",
        "bind",
        "connect",
        "listen",
        "accept",
        "getsockname",
        "getpeername",
        "socketpair",
        "send",
        "recv",
        "sendto",
        "recvfrom",
        "shutdown",
        "setsockopt",
        "getsockopt",
        "sendmsg",
        "recvmsg",
    ]
    
    def __init__(self, version):
        if version == None: # XXX
            version = "2.6" # XXX
        self.version = version
        GNU.__init__(self)
        #self.add_generic_syscall('prctl', 'int', 'int option', 'unsigned long arg2', \
        #    'unsigned long arg3' 'unsigned long arg4', 'unsigned long arg5')
        self.add_generic_syscall('prctl', 'int', 'int option', 'int arg2', 'int arg3', 'int arg4', 'int arg5')
        
        self.init_socketcall_functions()
        
        self.localfunctions["seteuid"] = ("c", """
        #import "local", "syscall3" as "syscall3"
        // #import "int", "SYS_setresuid" as "SYS_setresuid"
        
        int seteuid(int euid)
        {
            int i;
            
            i = syscall3(SYS_setresuid, -1, euid, -1);
            
            return i;
        }
        """)
        
        self.localfunctions["setegid"] = ("c", """
        #import "local", "syscall3" as "syscall3"
        // #import "int", "SYS_setresgid" as "SYS_setresgid"
        
        int setegid(int egid)
        {
            int i;
            
            i = syscall3(SYS_setresgid, -1, egid, -1);
            
            return i;
        }
        """)
        
    def init_socketcall_functions(self):
        if not hasattr(self, '_socketcall_functions'):
            return
        for funcname in self._socketcall_functions:
            if self.localfunctions.has_key(funcname):
                self.Linux_patch_socketcall(funcname)
            else:
                print "[%s] MISSING" % funcname
    
    def Linux_patch_socketcall(self, funcname):
        if self.localfunctions[funcname][0].upper() != "C":
            return

        rx = "(.*)[ \r\t\n]+([\w]+[ \r\t\n]+[\w]+[(].*[)].*[{].*)(syscall)([0-6]?)[(]([\w]+)(,[ \r\n]*.*[)].*[}].*)$"
        m = re.match(rx, self.localfunctions[funcname][1], re.S)
        if not m:
            return
        g = m.groups()
        g4 = g[4].upper()
        syscalln = g[2] + str(int(g[3]) + 1)
        s  = '\t#import "local", "socketcall" as "socketcall"\n'
        #s  = '\t#import "local", "syscallN" as "syscallN"\n'
        #s += '\t#import "int", "SYS_socketcall" as "SYS_socketcall"\n'
        #s += '\t#import "int", "%s" as "%s"\n\n\t' % (g4, g4)
        code = s + g[1] + "socketcall(SYS_socketcall, " + g4 + g[5]
        #code = s + g[1] + "syscallN(SYS_socketcall, " + g4 + g[5]
        self.localfunctions[funcname] = ('c', code)


class Linux_intel(Linux, i386):
    
    Endianness = 'little'
    
    # <asm/socket.h>
    
    SOCK_STREAM    = 1
    SOCK_DGRAM     = 2
    SOCK_RAW       = 3
    SOCK_RDM       = 4
    SOCK_SEQPACKET = 5
    SOCK_PACKET    = 10
    
    SOL_SOCKET = 1
    
    SO_DEBUG        = 1
    SO_REUSEADDR    = 2
    SO_TYPE         = 3
    SO_ERROR        = 4
    SO_DONTROUTE    = 5
    SO_BROADCAST    = 6
    SO_SNDBUF       = 7
    SO_RCVBUF       = 8
    SO_KEEPALIVE    = 9
    SO_OOBINLINE    = 10
    SO_NO_CHECK     = 11
    SO_PRIORITY     = 12
    SO_LINGER       = 13
    SO_BSDCOMPAT    = 14
    SO_REUSEPORT    = 15
    SO_PASSCRED     = 16
    SO_PEERCRED     = 17
    SO_RCVLOWAT     = 18
    SO_SNDLOWAT     = 19
    SO_RCVTIMEO     = 20
    SO_SNDTIMEO     = 21
    SO_BINDTODEVICE = 25
    SO_PEERNAME     = 28
    SO_TIMESTAMP    = 29
    SO_ACCEPTCONN   = 30
    
    # <bits/mman.h>
    
    PROT_NONE  = 0x0
    PROT_READ  = 0x1
    PROT_WRITE = 0x2
    PROT_EXEC  = 0x4
    
    MAP_SHARED    = 0x01
    MAP_PRIVATE   = 0x02
    MAP_FIXED     = 0x10
    MAP_ANONYMOUS = 0x20
    
    MAP_GROWSDOWN  = 0x0100
    MAP_DENYWRITE  = 0x0800
    MAP_EXECUTABLE = 0x1000
    MAP_LOCKED     = 0x2000
    MAP_NORESERVE  = 0x4000
    
    MAP_ANON      = MAP_ANONYMOUS
    MAP_FILE      = 0
    
    # <bits/confname.h>
    
    _SC_PAGESIZE = 0x1000
    
    # <bits/resource.h>
    
    RLIMIT_CPU     = 0
    RLIMIT_FSIZE   = 1
    RLIMIT_DATA    = 2
    RLIMIT_STACK   = 3
    RLIMIT_CORE    = 4
    RLIMIT_RSS     = 5
    RLIMIT_NPROC   = 6
    RLIMIT_NOFILE  = 7
    RLIMIT_MEMLOCK = 8
    RLIMIT_AS      = 9
    RLIMIT_LOCKS   = 10
    
    # <bits/poll.h>
    
    POLLIN     = 0x0001 
    POLLPRI    = 0x0002
    POLLOUT    = 0x0004
    POLLERR    = 0x0008
    POLLHUP    = 0x0010
    POLLNVAL   = 0x0020
    POLLRDNORM = 0x0040
    POLLRDBAND = 0x0080
    POLLWRNORM = 0x0100
    POLLWRBAND = 0x0200
    POLLMSG    = 0x0400
    
    _syscall_table = {
        '2.4': {
            'exit': 1,
            'fork': 2,
            'read': 3,
            'write': 4,
            'open': 5,
            'close': 6,
            'waitpid': 7,
            'creat': 8,
            'link': 9,
            'unlink': 10,
            'execve': 11,
            'chdir': 12,
            'time': 13,
            'mknod': 14,
            'chmod': 15,
            'lchown': 16,
            'break': 17,
            'oldstat': 18,
            'lseek': 19,
            'getpid': 20,
            'mount': 21,
            'umount': 22,
            'setuid': 23,
            'getuid': 24,
            'stime': 25,
            'ptrace': 26,
            'alarm': 27,
            'oldfstat': 28,
            'pause': 29,
            'utime': 30,
            'stty': 31,
            'gtty': 32,
            'access': 33,
            'nice': 34,
            'ftime': 35,
            'sync': 36,
            'kill': 37,
            'rename': 38,
            'mkdir': 39,
            'rmdir': 40,
            'dup': 41,
            'pipe': 42,
            'times': 43,
            'prof': 44,
            'brk': 45,
            'setgid': 46,
            'getgid': 47,
            'signal': 48,
            'geteuid': 49,
            'getegid': 50,
            'acct': 51,
            'umount2': 52,
            'lock': 53,
            'ioctl': 54,
            'fcntl': 55,
            'mpx': 56,
            'setpgid': 57,
            'ulimit': 58,
            'oldolduname': 59,
            'umask': 60,
            'chroot': 61,
            'ustat': 62,
            'dup2': 63,
            'getppid': 64,
            'getpgrp': 65,
            'setsid': 66,
            'sigaction': 67,
            'sgetmask': 68,
            'ssetmask': 69,
            'setreuid': 70,
            'setregid': 71,
            'sigsuspend': 72,
            'sigpending': 73,
            'sethostname': 74,
            'setrlimit': 75,
            'getrlimit': 76,
            'getrusage': 77,
            'gettimeofday': 78,
            'settimeofday': 79,
            'getgroups': 80,
            'setgroups': 81,
            'select': 82,
            'symlink': 83,
            'oldlstat': 84,
            'readlink': 85,
            'uselib': 86,
            'swapon': 87,
            'reboot': 88,
            'readdir': 89,
            'mmap': 90,
            'munmap': 91,
            'truncate': 92,
            'ftruncate': 93,
            'fchmod': 94,
            'fchown': 95,
            'getpriority': 96,
            'setpriority': 97,
            'profil': 98,
            'statfs': 99,
            'fstatfs': 100,
            'ioperm': 101,
            'socketcall': 102,
            'syslog': 103,
            'setitimer': 104,
            'getitimer': 105,
            'stat': 106,
            'lstat': 107,
            'fstat': 108,
            'olduname': 109,
            'iopl': 110,
            'vhangup': 111,
            'idle': 112,
            'vm86old': 113,
            'wait4': 114,
            'swapoff': 115,
            'sysinfo': 116,
            'ipc': 117,
            'fsync': 118,
            'sigreturn': 119,
            'clone': 120,
            'setdomainname': 121,
            'uname': 122,
            'modify_ldt': 123,
            'adjtimex': 124,
            'mprotect': 125,
            'sigprocmask': 126,
            'create_module': 127,
            'init_module': 128,
            'delete_module': 129,
            'get_kernel_syms': 130,
            'quotactl': 131,
            'getpgid': 132,
            'fchdir': 133,
            'bdflush': 134,
            'sysfs': 135,
            'personality': 136,
            'afs_syscall': 137,
            'setfsuid': 138,
            'setfsgid': 139,
            '_llseek': 140,
            'getdents': 141,
            '_newselect': 142,
            'flock': 143,
            'msync': 144,
            'readv': 145,
            'writev': 146,
            'getsid': 147,
            'fdatasync': 148,
            '_sysctl': 149,
            'mlock': 150,
            'munlock': 151,
            'mlockall': 152,
            'munlockall': 153,
            'sched_setparam': 154,
            'sched_getparam': 155,
            'sched_setscheduler': 156,
            'sched_getscheduler': 157,
            'sched_yield': 158,
            'sched_get_priority_max': 159,
            'sched_get_priority_min': 160,
            'sched_rr_get_interval': 161,
            'nanosleep': 162,
            'mremap': 163,
            'setresuid': 164,
            'getresuid': 165,
            'vm86': 166,
            'query_module': 167,
            'poll': 168,
            'nfsservctl': 169,
            'setresgid': 170,
            'getresgid': 171,
            'prctl': 172,
            'rt_sigreturn': 173,
            'rt_sigaction': 174,
            'rt_sigprocmask': 175,
            'rt_sigpending': 176,
            'rt_sigtimedwait': 177,
            'rt_sigqueueinfo': 178,
            'rt_sigsuspend': 179,
            'pread': 180,
            'pwrite': 181,
            'chown': 182,
            'getcwd': 183,
            'capget': 184,
            'capset': 185,
            'sigaltstack': 186,
            'sendfile': 187,
            'getpmsg': 188,
            'putpmsg': 189,
            'vfork': 190,
            'ugetrlimit': 191,
            'mmap2': 192,
            'truncate64': 193,
            'ftruncate64': 194,
            'stat64': 195,
            'lstat64': 196,
            'fstat64': 197,
            'lchown32': 198,
            'getuid32': 199,
            'getgid32': 200,
            'geteuid32': 201,
            'getegid32': 202,
            'setreuid32': 203,
            'setregid32': 204,
            'getgroups32': 205,
            'setgroups32': 206,
            'fchown32': 207,
            'setresuid32': 208,
            'getresuid32': 209,
            'setresgid32': 210,
            'getresgid32': 211,
            'chown32': 212,
            'setuid32': 213,
            'setgid32': 214,
            'setfsuid32': 215,
            'setfsgid32': 216,
            'pivot_root': 217,
            'mincore': 218,
            'madvise': 219,
            'madvise1': 219,
            'getdents64': 220,
            'fcntl64': 221,
            'security': 223,
            'gettid': 224,
            'readahead': 225,
            'setxattr': 226,
            'lsetxattr': 227,
            'fsetxattr': 228,
            'getxattr': 229,
            'lgetxattr': 230,
            'fgetxattr': 231,
            'listxattr': 232,
            'llistxattr': 233,
            'flistxattr': 234,
            'removexattr': 235,
            'lremovexattr': 236,
            'fremovexattr': 237,
            'tkill': 238,
            'sendfile64': 239,
            'futex': 240,
            'sched_setaffinity': 241,
            'sched_getaffinity': 242,
            'set_thread_area': 243,
            'get_thread_area': 244,
            'io_setup': 245,
            'io_destroy': 246,
            'io_getevents': 247,
            'io_submit': 248,
            'io_cancel': 249,
            'alloc_hugepages': 250,
            'free_hugepages': 251,
            'exit_group': 252,
        }, 
    }

    # XXX KLUDGE
    _syscall_table['2.2'] = _syscall_table['2.4']
    _syscall_table['2.6'] = _syscall_table['2.4']
    
    _aliases_table = [
        # WARNING: this could lead to problems on very old kernels...
        ('SYS__exit', 'SYS_exit'),
        ('SYS_mmap', 'SYS_mmap2'),           # we dont want to use old_mmap
        ('SYS_getrlimit', 'SYS_ugetrlimit'), # we dont want to use old_getrlimit
        ('SYS_setuid', 'SYS_setuid32'),
        ('SYS_setgid', 'SYS_setgid32'),
        ('SYS_chown', 'SYS_chown32'),
        ('SYS_select', 'SYS__newselect'),
    ]
    
    def __init__(self, version = None):
        Linux.__init__(self, version)
        i386.__init__(self)
        self._Linux_i386_initLocalFunctions()
    
    def _Linux_i386_initLocalFunctions(self):
        
        self.createSyscall()
        
    def createSyscall(self):
        #
        # http://asm.sourceforge.net/articles/linasm.html#Syscall5
        #
        # on linux a syscall with 4 arguments puts the first
        # in ebx and the second in ecx and the third in edx and 4 in esi
        # we take in the arguments on the stack and convert them to that
        # and so on...
        #
        # note: first pop after int 0x80 is skipped by gdb due to gdb hooks
        NOTE = """
        <bas> 6 args == syscall in eax, pointer to args in ebx
        <bas> if i recall correctly
        <bas> cuz you run out of regs on 6 :)
        <bas> so it goes to a stack based arg handling
        <bas> that's 2.4 semantic?
        <bas> ebp can be used as the 6th arg?
        <bas> <- learned syscalls on old kernel
        <bas> it will work on 2.4
        <bas> but it's 2.4 specific i believe
        """
        sysreg = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"]
        for n in range(0, 7):
            code = """
            syscall%d:
            push %%ebp
            movl %%esp, %%ebp
            //.byte 0xcc\n""" % n
            for i in range(1, n + 1):
                code += "            push %%%s          // save %s\n" % (sysreg[i], sysreg[i])
            for i in range(0, n + 1):
                off = 4 * (2 + i)
                code += "            mov %d(%%ebp), %%%s%s // arg%d\n" % (off, sysreg[i], ' ' * (2 - len(str(off))), i)
            code += "            int $0x80\n"
            for i in range(n, 0, -1):
                code += "            pop %%%s           // restore %s\n" % (sysreg[i], sysreg[i])
            code += """            movl %%ebp,%%esp
            popl %%ebp
            ret $%d
            """ % (4 * (n + 1))
            self.localfunctions["syscall%d" % n]=("asm", code)
        
        # http://asm.sourceforge.net/articles/linasm.html#Syscall6
        # XXX what about syscall6? TODO: verify syscall7
        self.localfunctions["syscall7"]=("asm", """
            syscall7:
            push %ebp
            movl %esp, %ebp
            push %ebx
            //int3
            mov 8(%ebp), %eax
            lea 12(%ebp), %ebx
            int $0x80
            pop %ebx
            movl %ebp, %esp
            popl %ebp
            ret $8
        """)
        
        # http://asm.sourceforge.net/articles/linasm.html#Sockets
        self.localfunctions["socketcall"]=("asm", """
            socketcall:
            pushl %ebp
            movl %esp, %ebp
            push %ebx
            push %ecx
            // here i dont know what's the best since it's arch-specific.
            // using that way, i give syscall(SYS_socketcall, args...)
            // but maybe it's unuseful.
            //movl $102, %eax      // SYS_socketcall
            //mov 8(%ebp), %ebx    // socketcall
            //lea 12(%ebp), %ecx   // args
            mov 8(%ebp), %eax      // SYS_socketcall
            mov 12(%ebp), %ebx     // socketcall
            lea 16(%ebp), %ecx     // args
            int $0x80
            pop %ecx
            pop %ebx
            movl %ebp, %esp
            popl %ebp
            ret $12 // ?
        """)

# just in case we ever run into the cc_main problems again
# we just have a callthrough class that handles Linux_x86

class Linux_x86(Linux_intel):
    
    def __init__(self, version = None):
        Linux_intel.__init__(self, version)

class Linux_ia64(Linux_intel): # XXX need to be tested.
    
    def __init__(self, version = None):
        Linux_intel.__init__(self, version)

class Linux_sparc(Linux):
    
    Endianness = 'big'
    
    # <asm/socket.h>
    
    SOCK_STREAM    = 1
    SOCK_DGRAM     = 2
    SOCK_RAW       = 3
    SOCK_RDM       = 4
    SOCK_SEQPACKET = 5
    SOCK_PACKET    = 10
    
    SOL_SOCKET = 0xffff
    
    SO_DEBUG        = 0x0001
    SO_PASSCRED     = 0x0002
    SO_REUSEADDR    = 0x0004
    SO_KEEPALIVE    = 0x0008
    SO_DONTROUTE    = 0x0010
    SO_BROADCAST    = 0x0020
    SO_PEERCRED     = 0x0040
    SO_LINGER       = 0x0080
    SO_OOBINLINE    = 0x0100
    SO_TYPE         = 0x1008
    SO_BSDCOMPAT    = 0x0400
    SO_RCVLOWAT     = 0x0800
    SO_SNDLOWAT     = 0x1000
    SO_RCVTIMEO     = 0x2000
    SO_SNDTIMEO     = 0x4000
    SO_ACCEPTCONN   = 0x8000
    SO_DONTLINGER   = ~SO_LINGER
    SO_SNDBUF       = 0x1001
    SO_RCVBUF       = 0x1002
    SO_ERROR        = 0x1007
    SO_TYPE         = 0x1008
    SO_NO_CHECK     = 0x000b
    SO_PRIORITY     = 0x000c
    SO_BINDTODEVICE = 0x000d
    SO_PEERNAME     = 0x001c
    SO_TIMESTAMP    = 0x001d
    
    # <bits/mman.h>
    
    PROT_NONE  = 0x0
    PROT_READ  = 0x1
    PROT_WRITE = 0x2
    PROT_EXEC  = 0x4
    
    MAP_SHARED    = 0x01
    MAP_PRIVATE   = 0x02
    MAP_TYPE      = 0x0f
    MAP_FIXED     = 0x10
    MAP_ANONYMOUS = 0x20
    MAP_RENAME    = MAP_ANONYMOUS
    MAP_NORESERVE = 0x40
    MAP_INHERIT   = 0x80
    MAP_LOCKED    = 0x100
    _MAP_NEW      = 0x80000000 # !#@$!#@%!
    
    MAP_GROWSDOWN  = 0x0100
    MAP_DENYWRITE  = 0x0800
    MAP_EXECUTABLE = 0x1000
    
    MAP_ANON      = MAP_ANONYMOUS
    MAP_FILE      = 0
    
    # <bits/poll.h>
    
    POLLIN     = 1 
    POLLPRI    = 2
    POLLOUT    = 4
    POLLERR    = 8
    POLLHUP    = 16
    POLLNVAL   = 32
    POLLRDNORM = 64
    POLLRDBAND = POLLOUT
    POLLWRNORM = 128
    POLLWRBAND = 256
    POLLMSG    = 512
    
    # <bits/resource.h>
    
    RLIMIT_CPU     = 0
    RLIMIT_FSIZE   = 1
    RLIMIT_DATA    = 2
    RLIMIT_STACK   = 3
    RLIMIT_CORE    = 4
    RLIMIT_RSS     = 5
    RLIMIT_NOFILE  = 6
    RLIMIT_NPROC   = 7
    RLIMIT_MEMLOCK = 8
    RLIMIT_AS      = 9
    RLIMIT_LOCKS   = 10
    
    _syscall_table = {
        '2.4': {
            'exit': 1,
            'fork': 2,
            'read': 3,
            'write': 4,
            'open': 5,
            'close': 6,
            'wait4': 7,
            'creat': 8,
            'link': 9,
            'unlink': 10,
            'execv': 11,
            'chdir': 12,
            'chown': 13,
            'mknod': 14,
            'chmod': 15,
            'lchown': 16,
            'brk': 17,
            'perfctr': 18,
            'lseek': 19,
            'getpid': 20,
            'capget': 21,
            'capset': 22,
            'setuid': 23,
            'getuid': 24,
            'ptrace': 26,
            'alarm': 27,
            'sigaltstack': 28,
            'pause': 29,
            'utime': 30,
            'lchown32': 31,
            'fchown32': 32,
            'access': 33,
            'nice': 34,
            'chown32': 35,
            'sync': 36,
            'kill': 37,
            'stat': 38,
            'sendfile': 39,
            'lstat': 40,
            'dup': 41,
            'pipe': 42,
            'times': 43,
            'getuid32': 44,
            'umount2': 45,
            'setgid': 46,
            'getgid': 47,
            'signal': 48,
            'geteuid': 49,
            'getegid': 50,
            'acct': 51,
            'getgid32': 53,
            'ioctl': 54,
            'reboot': 55,
            'mmap2': 56,
            'symlink': 57,
            'readlink': 58,
            'execve': 59,
            'umask': 60,
            'chroot': 61,
            'fstat': 62,
            'fstat64': 63,
            'getpagesize': 64,
            'msync': 65,
            'vfork': 66,
            'pread': 67,
            'pwrite': 68,
            'geteuid32': 69,
            'getegid32': 70,
            'mmap': 71,
            'setreuid32': 72,
            'munmap': 73,
            'mprotect': 74,
            'madvise': 75,
            'vhangup': 76,
            'truncate64': 77,
            'mincore': 78,
            'getgroups': 79,
            'setgroups': 80,
            'getpgrp': 81,
            'setgroups32': 82,
            'setitimer': 83,
            'ftruncate64': 84,
            'swapon': 85,
            'getitimer': 86,
            'setuid32': 87,
            'sethostname': 88,
            'setgid32': 89,
            'dup2': 90,
            'setfsuid32': 91,
            'fcntl': 92,
            'select': 93,
            'setfsgid32': 94,
            'fsync': 95,
            'setpriority': 96,
            'socket': 97,
            'connect': 98,
            'accept': 99,
            'getpriority': 100,
            'rt_sigreturn': 101,
            'rt_sigaction': 102,
            'rt_sigprocmask': 103,
            'rt_sigpending': 104,
            'rt_sigtimedwait': 105,
            'rt_sigqueueinfo': 106,
            'rt_sigsuspend': 107,
            'setresuid32': 108,
            'getresuid32': 109,
            'setresgid32': 110,
            'getresgid32': 111,
            'setregid32': 112,
            'recvmsg': 113,
            'sendmsg': 114,
            'getgroups32': 115,
            'gettimeofday': 116,
            'getrusage': 117,
            'getsockopt': 118,
            'getcwd': 119,
            'readv': 120,
            'writev': 121,
            'settimeofday': 122,
            'fchown': 123,
            'fchmod': 124,
            'recvfrom': 125,
            'setreuid': 126,
            'setregid': 127,
            'rename': 128,
            'truncate': 129,
            'ftruncate': 130,
            'flock': 131,
            'lstat64': 132,
            'sendto': 133,
            'shutdown': 134,
            'socketpair': 135,
            'mkdir': 136,
            'rmdir': 137,
            'utimes': 138,
            'stat64': 139,
            'getpeername': 141,
            'gettid': 143,
            'getrlimit': 144,
            'setrlimit': 145,
            'pivot_root': 146,
            'prctl': 147,
            'pciconfig_read': 148,
            'pciconfig_write': 149,
            'getsockname': 150,
            'poll': 153,
            'getdents64': 154,
            'fcntl64': 155,
            'statfs': 157,
            'fstatfs': 158,
            'umount': 159,
            'getdomainname': 162,
            'setdomainname': 163,
            'quotactl': 165,
            'mount': 167,
            'ustat': 168,
            'setsid': 175,
            'fchdir': 176,
            'sigpending': 183,
            'query_module': 184,
            'setpgid': 185,
            'tkill': 187,
            'uname': 189,
            'init_module': 190,
            'personality': 191,
            'getppid': 197,
            'sigaction': 198,
            'sgetmask': 199,
            'ssetmask': 200,
            'sigsuspend': 201,
            'oldlstat': 202,
            'uselib': 203,
            'readdir': 204,
            'readahead': 205,
            'socketcall': 206,
            'syslog': 207,
            'waitpid': 212,
            'swapoff': 213,
            'sysinfo': 214,
            'ipc': 215,
            'sigreturn': 216,
            'clone': 217,
            'adjtimex': 219,
            'sigprocmask': 220,
            'create_module': 221,
            'delete_module': 222,
            'get_kernel_syms': 223,
            'getpgid': 224,
            'bdflush': 225,
            'sysfs': 226,
            'afs_syscall': 227,
            'setfsuid': 228,
            'setfsgid': 229,
            '_newselect': 230,
            'time': 231,
            'stime': 233,
            '_llseek': 236,
            'mlock': 237,
            'munlock': 238,
            'mlockall': 239,
            'munlockall': 240,
            'sched_setparam': 241,
            'sched_getparam': 242,
            'sched_setscheduler': 243,
            'sched_getscheduler': 244,
            'sched_yield': 245,
            'sched_get_priority_max': 246,
            'sched_get_priority_min': 247,
            'sched_rr_get_interval': 248,
            'nanosleep': 249,
            'mremap': 250,
            '_sysctl': 251,
            'getsid': 252,
            'fdatasync': 253,
            'nfsservctl': 254,
            'aplib': 255,
        }, 
    }

    # XXX KLUDGE
    _syscall_table['2.2'] = _syscall_table['2.4']
    _syscall_table['2.6'] = _syscall_table['2.4']
    
    _aliases_table = [
        # WARNING: this could lead to problems on very old kernels...
        ('SYS__exit', 'SYS_exit'),
        ('SYS_lchown', 'SYS_lchown32'),
        ('SYS_fchown', 'SYS_fchown32'),
        ('SYS_chown', 'SYS_chown32'),
        ('SYS_getuid', 'SYS_getuid32'),
        ('SYS_getgid', 'SYS_getgid32'),
        ('SYS_geteuid', 'SYS_geteuid32'),
        ('SYS_getegid', 'SYS_getegid32'),
        ('SYS_setreuid', 'SYS_setreuid32'),
        ('SYS_setgroups', 'SYS_setgroups32'),
        ('SYS_setuid', 'SYS_setuid32'),
        ('SYS_setgid', 'SYS_setgid32'),
        ('SYS_setfsuid', 'SYS_setfsuid32'),
        ('SYS_setfsgid', 'SYS_setfsgid32'),
        ('SYS_setresuid', 'SYS_setresuid32'),
        ('SYS_getresuid', 'SYS_getresuid32'),
        ('SYS_setresgid', 'SYS_setresgid32'),
        ('SYS_getresgid', 'SYS_getresgid32'),
        ('SYS_setregid', 'SYS_setregid32'),
        ('SYS_getgroups', 'SYS_getgroups32'),
    ]

    def __init__(self, version = None):
        Linux.__init__(self, version)
        
        self.localfunctions["syscallN"] = ("asm", """
            syscallN:
                save %sp,-96,%sp
                mov %i0, %g1 !local syscall number from first argument
                mov %i1, %o0
                mov %i2, %o1
                mov %i3, %o2
                mov %i4, %o3
                mov %i5, %o4
                ta 16        !call syscall
                mov %o0, %i0 ! store return value (errno on failure)
                bcc,a syscall_noerror
                nop
                ret
                !restore  %g0, -1, %o0 ! macro not MOSDEF supported
                restore
            syscall_noerror:
                retl
                nop
        """)
        # XXX TODO: use that syscallN once retl is supported.
        self.localfunctions["_syscallN"] = ("asm", """
            syscallN:
                mov %i0, %g1 !local syscall number from first argument
                mov %i1, %o0
                mov %i2, %o1
                mov %i3, %o2
                mov %i4, %o3
                mov %i5, %o4
                ta 16        !call syscall
                bcc,a syscall_noerror
                nop
                save %sp, -96, %sp
            syscallN_checkerror:
                call syscallN_checkerror
                nop
                st %i0, [ %o0 ]
                restore
                retl
                mov -1, %o0
            syscall_noerror:
                retl
                nop
        """)

class Linux_sparc64(Linux_sparc):
    
    _syscall_table = {
        '2.4': {
            'exit': 1,
            'fork': 2,
            'read': 3,
            'write': 4,
            'open': 5,
            'close': 6,
            'wait4': 7,
            'creat': 8,
            'link': 9,
            'unlink': 10,
            'execv': 11,
            'chdir': 12,
            'chown': 13,
            'mknod': 14,
            'chmod': 15,
            'lchown': 16,
            'brk': 17,
            'perfctr': 18,
            'lseek': 19,
            'getpid': 20,
            'capget': 21,
            'capset': 22,
            'setuid': 23,
            'getuid': 24,
            'ptrace': 26,
            'alarm': 27,
            'sigaltstack': 28,
            'pause': 29,
            'utime': 30,
            'access': 33,
            'nice': 34,
            'sync': 36,
            'kill': 37,
            'stat': 38,
            'sendfile': 39,
            'lstat': 40,
            'dup': 41,
            'pipe': 42,
            'times': 43,
            'umount2': 45,
            'setgid': 46,
            'getgid': 47,
            'signal': 48,
            'geteuid': 49,
            'getegid': 50,
            'acct': 51,
            'memory_ordering': 52,
            'ioctl': 54,
            'reboot': 55,
            'symlink': 57,
            'readlink': 58,
            'execve': 59,
            'umask': 60,
            'chroot': 61,
            'fstat': 62,
            'getpagesize': 64,
            'msync': 65,
            'vfork': 66,
            'pread': 67,
            'pwrite': 68,
            'mmap': 71,
            'munmap': 73,
            'mprotect': 74,
            'madvise': 75,
            'vhangup': 76,
            'mincore': 78,
            'getgroups': 79,
            'setgroups': 80,
            'getpgrp': 81,
            'setitimer': 83,
            'swapon': 85,
            'getitimer': 86,
            'sethostname': 88,
            'dup2': 90,
            'fcntl': 92,
            'select': 93,
            'fsync': 95,
            'setpriority': 96,
            'socket': 97,
            'connect': 98,
            'accept': 99,
            'getpriority': 100,
            'rt_sigreturn': 101,
            'rt_sigaction': 102,
            'rt_sigprocmask': 103,
            'rt_sigpending': 104,
            'rt_sigtimedwait': 105,
            'rt_sigqueueinfo': 106,
            'rt_sigsuspend': 107,
            'setresuid': 108,
            'getresuid': 109,
            'setresgid': 110,
            'getresgid': 111,
            'recvmsg': 113,
            'sendmsg': 114,
            'gettimeofday': 116,
            'getrusage': 117,
            'getsockopt': 118,
            'getcwd': 119,
            'readv': 120,
            'writev': 121,
            'settimeofday': 122,
            'fchown': 123,
            'fchmod': 124,
            'recvfrom': 125,
            'setreuid': 126,
            'setregid': 127,
            'rename': 128,
            'truncate': 129,
            'ftruncate': 130,
            'flock': 131,
            'sendto': 133,
            'shutdown': 134,
            'socketpair': 135,
            'mkdir': 136,
            'rmdir': 137,
            'utimes': 138,
            'getpeername': 141,
            'gettid': 143,
            'getrlimit': 144,
            'setrlimit': 145,
            'pivot_root': 146,
            'prctl': 147,
            'pciconfig_read': 148,
            'pciconfig_write': 149,
            'getsockname': 150,
            'poll': 153,
            'getdents64': 154,
            'statfs': 157,
            'fstatfs': 158,
            'umount': 159,
            'getdomainname': 162,
            'setdomainname': 163,
            'utrap_install': 164,
            'quotactl': 165,
            'mount': 167,
            'ustat': 168,
            'getdents': 174,
            'setsid': 175,
            'fchdir': 176,
            'sigpending': 183,
            'query_module': 184,
            'setpgid': 185,
            'tkill': 187,
            'uname': 189,
            'init_module': 190,
            'personality': 191,
            'getppid': 197,
            'sigaction': 198,
            'sgetmask': 199,
            'ssetmask': 200,
            'sigsuspend': 201,
            'oldlstat': 202,
            'uselib': 203,
            'readdir': 204,
            'readahead': 205,
            'socketcall': 206,
            'syslog': 207,
            'waitpid': 212,
            'swapoff': 213,
            'sysinfo': 214,
            'ipc': 215,
            'sigreturn': 216,
            'clone': 217,
            'adjtimex': 219,
            'sigprocmask': 220,
            'create_module': 221,
            'delete_module': 222,
            'get_kernel_syms': 223,
            'getpgid': 224,
            'bdflush': 225,
            'sysfs': 226,
            'afs_syscall': 227,
            'setfsuid': 228,
            'setfsgid': 229,
            '_newselect': 230,
            'time': 231,
            'stime': 233,
            '_llseek': 236,
            'mlock': 237,
            'munlock': 238,
            'mlockall': 239,
            'munlockall': 240,
            'sched_setparam': 241,
            'sched_getparam': 242,
            'sched_setscheduler': 243,
            'sched_getscheduler': 244,
            'sched_yield': 245,
            'sched_get_priority_max': 246,
            'sched_get_priority_min': 247,
            'sched_rr_get_interval': 248,
            'nanosleep': 249,
            'mremap': 250,
            '_sysctl': 251,
            'getsid': 252,
            'fdatasync': 253,
            'nfsservctl': 254,
            'aplib': 255,
        }, 
    }

class Linux_mips(Linux):
    
    Endianness = 'big'
    
    # <asm/socket.h>
    
    SOCK_DGRAM     = 1
    SOCK_STREAM    = 2
    SOCK_RAW       = 3
    SOCK_RDM       = 4
    SOCK_SEQPACKET = 5
    SOCK_PACKET    = 10
    
    SOL_SOCKET = 0xffff
    
    SO_DEBUG        = 0x0001
    SO_REUSEADDR    = 0x0004
    SO_KEEPALIVE    = 0x0008
    SO_DONTROUTE    = 0x0010
    SO_BROADCAST    = 0x0020
    SO_LINGER       = 0x0080
    SO_OOBINLINE    = 0x0100
    SO_TYPE         = 0x1008
    SO_STYLE        = SO_TYPE
    SO_ERROR        = 0x1007
    SO_SNDBUF       = 0x1001
    SO_RCVBUF       = 0x1002
    SO_SNDLOWAT     = 0x1003
    SO_RCVLOWAT     = 0x1004
    SO_SNDTIMEO     = 0x1005
    SO_RCVTIMEO     = 0x1006
    SO_ACCEPTCONN   = 0x1009
    SO_NO_CHECK     = 11
    SO_PRIORITY     = 12
    SO_BSDCOMPAT    = 14
    SO_PASSCRED     = 17
    SO_PEERCRED     = 18
    SO_BINDTODEVICE = 25
    SO_PEERNAME     = 28
    SO_TIMESTAMP    = 29
    
    # <bits/mman.h>
    
    PROT_NONE  = 0x0
    PROT_READ  = 0x1
    PROT_WRITE = 0x2
    PROT_EXEC  = 0x4
    
    MAP_SHARED    = 0x001
    MAP_PRIVATE   = 0x002
    MAP_FIXED     = 0x010
    MAP_RENAME    = 0x020
    MAP_AUTOGROW  = 0x040
    MAP_LOCAL     = 0x080
    MAP_AUTORSRV  = 0x100
    
    MAP_NORESERVE  = 0x0400
    MAP_ANONYMOUS  = 0x0800
    MAP_GROWSDOWN  = 0x1000
    MAP_DENYWRITE  = 0x2000
    MAP_EXECUTABLE = 0x4000
    MAP_LOCKED     = 0x8000
    
    MAP_ANON      = MAP_ANONYMOUS
    MAP_FILE      = 0
    
    # <bits/poll.h>
    
    POLLIN     = 0x0001 
    POLLPRI    = 0x0002
    POLLOUT    = 0x0004
    POLLERR    = 0x0008
    POLLHUP    = 0x0010
    POLLNVAL   = 0x0020
    POLLRDNORM = 0x0040
    POLLRDBAND = 0x0080
    POLLWRNORM = POLLOUT
    POLLWRBAND = 0x0100
    POLLMSG    = 0x0400
    
    # <bits/resource.h>
    
    RLIMIT_CPU     = 0
    RLIMIT_FSIZE   = 1
    RLIMIT_DATA    = 2
    RLIMIT_STACK   = 3
    RLIMIT_CORE    = 4
    RLIMIT_NOFILE  = 5
    RLIMIT_AS      = 6
    RLIMIT_RSS     = 7
    RLIMIT_NPROC   = 8
    RLIMIT_MEMLOCK = 9
    RLIMIT_LOCKS   = 10
    
    def __init__(self, version = None):
        Linux.__init__(self, version)

class Linux_mips64(Linux_mips):
    
    def __init__(self, version = None):
        Linux_mips.__init__(self, version)

class Linux_mipsel(Linux_mips):
    
    Endianness = 'little'
    
    """
    NOT TESTED!!!
    TODO: verify endianness + #defines
    """
    
    def __init__(self, version = None):
        Linux.__init__(self, version)

class Linux_powerpc(Linux, ppc):
    
    Endianness = 'big'
    
    # <asm/socket.h>
    
    SOCK_STREAM    = 1
    SOCK_DGRAM     = 2
    SOCK_RAW       = 3
    SOCK_RDM       = 4
    SOCK_SEQPACKET = 5
    SOCK_PACKET    = 10
    
    SOL_SOCKET = 1
    
    SO_DEBUG        = 1
    SO_REUSEADDR    = 2
    SO_TYPE         = 3
    SO_ERROR        = 4
    SO_DONTROUTE    = 5
    SO_BROADCAST    = 6
    SO_SNDBUF       = 7
    SO_RCVBUF       = 8
    SO_KEEPALIVE    = 9
    SO_OOBINLINE    = 10
    SO_NO_CHECK     = 11
    SO_PRIORITY     = 12
    SO_LINGER       = 13
    SO_BSDCOMPAT    = 14
    SO_REUSEPORT    = 15
    SO_RCVLOWAT     = 16
    SO_SNDLOWAT     = 17
    SO_RCVTIMEO     = 18
    SO_SNDTIMEO     = 19
    SO_PASSCRED     = 20
    SO_PEERCRED     = 21
    SO_BINDTODEVICE = 25
    SO_PEERNAME     = 28
    SO_TIMESTAMP    = 29
    SO_ACCEPTCONN   = 30
    
    FIOSETOWN  = 0x8901
    SIOCSPGRP  = 0x8902
    FIOGETOWN  = 0x8903
    SIOCGPGRP  = 0x8904
    SIOCATMARK = 0x8905
    SIOCGSTAMP = 0x8906
    
    # <bits/mman.h>
    
    PROT_NONE  = 0x0
    PROT_READ  = 0x1
    PROT_WRITE = 0x2
    PROT_EXEC  = 0x4
    
    MAP_SHARED    = 0x01
    MAP_PRIVATE   = 0x02
    MAP_TYPE      = 0x0f
    MAP_FIXED     = 0x10
    MAP_ANONYMOUS = 0x20
    MAP_RENAME    = MAP_ANONYMOUS
    MAP_NORESERVE = 0x40
    MAP_LOCKED    = 0x80
    
    MAP_GROWSDOWN  = 0x0100
    MAP_DENYWRITE  = 0x0800
    MAP_EXECUTABLE = 0x1000
    
    MAP_ANON      = MAP_ANONYMOUS
    MAP_FILE      = 0
    
    # <bits/confname.h>
    
    _SC_PAGESIZE = 0x1000
    
    # <bits/resource.h>
    
    RLIMIT_CPU     = 0
    RLIMIT_FSIZE   = 1
    RLIMIT_DATA    = 2
    RLIMIT_STACK   = 3
    RLIMIT_CORE    = 4
    RLIMIT_RSS     = 5
    RLIMIT_NPROC   = 6
    RLIMIT_NOFILE  = 7
    RLIMIT_MEMLOCK = 8
    RLIMIT_AS      = 9
    RLIMIT_LOCKS   = 10
    
    # <bits/poll.h>
    
    POLLIN     = 0x0001 
    POLLPRI    = 0x0002
    POLLOUT    = 0x0004
    POLLERR    = 0x0008
    POLLHUP    = 0x0010
    POLLNVAL   = 0x0020
    POLLRDNORM = 0x0040
    POLLRDBAND = 0x0080
    POLLWRNORM = 0x0100
    POLLWRBAND = 0x0200
    POLLMSG    = 0x0400
    
    # <asm-ppc/unistd.h>
    
    _syscall_table = {
        '2.6': {
            'restart_syscall': 0,
            'exit': 1,
            'fork': 2,
            'read': 3,
            'write': 4,
            'open': 5,
            'close': 6,
            'waitpid': 7,
            'creat': 8,
            'link': 9,
            'unlink': 10,
            'execve': 11,
            'chdir': 12,
            'time': 13,
            'mknod': 14,
            'chmod': 15,
            'lchown': 16,
            'break': 17,
            'oldstat': 18,
            'lseek': 19,
            'getpid': 20,
            'mount': 21,
            'umount': 22,
            'setuid': 23,
            'getuid': 24,
            'stime': 25,
            'ptrace': 26,
            'alarm': 27,
            'oldfstat': 28,
            'pause': 29,
            'utime': 30,
            'stty': 31,
            'gtty': 32,
            'access': 33,
            'nice': 34,
            'ftime': 35,
            'sync': 36,
            'kill': 37,
            'rename': 38,
            'mkdir': 39,
            'rmdir': 40,
            'dup': 41,
            'pipe': 42,
            'times': 43,
            'prof': 44,
            'brk': 45,
            'setgid': 46,
            'getgid': 47,
            'signal': 48,
            'geteuid': 49,
            'getegid': 50,
            'acct': 51,
            'umount2': 52,
            'lock': 53,
            'ioctl': 54,
            'fcntl': 55,
            'mpx': 56,
            'setpgid': 57,
            'ulimit': 58,
            'oldolduname': 59,
            'umask': 60,
            'chroot': 61,
            'ustat': 62,
            'dup2': 63,
            'getppid': 64,
            'getpgrp': 65,
            'setsid': 66,
            'sigaction': 67,
            'sgetmask': 68,
            'ssetmask': 69,
            'setreuid': 70,
            'setregid': 71,
            'sigsuspend': 72,
            'sigpending': 73,
            'sethostname': 74,
            'setrlimit': 75,
            'getrlimit': 76,
            'getrusage': 77,
            'gettimeofday': 78,
            'settimeofday': 79,
            'getgroups': 80,
            'setgroups': 81,
            'select': 82,
            'symlink': 83,
            'oldlstat': 84,
            'readlink': 85,
            'uselib': 86,
            'swapon': 87,
            'reboot': 88,
            'readdir': 89,
            'mmap': 90,
            'munmap': 91,
            'truncate': 92,
            'ftruncate': 93,
            'fchmod': 94,
            'fchown': 95,
            'getpriority': 96,
            'setpriority': 97,
            'profil': 98,
            'statfs': 99,
            'fstatfs': 100,
            'ioperm': 101,
            'socketcall': 102,
            'syslog': 103,
            'setitimer': 104,
            'getitimer': 105,
            'stat': 106,
            'lstat': 107,
            'fstat': 108,
            'olduname': 109,
            'iopl': 110,
            'vhangup': 111,
            'idle': 112,
            'vm86': 113,
            'wait4': 114,
            'swapoff': 115,
            'sysinfo': 116,
            'ipc': 117,
            'fsync': 118,
            'sigreturn': 119,
            'clone': 120,
            'setdomainname': 121,
            'uname': 122,
            'modify_ldt': 123,
            'adjtimex': 124,
            'mprotect': 125,
            'sigprocmask': 126,
            'create_module': 127,
            'init_module': 128,
            'delete_module': 129,
            'get_kernel_syms': 130,
            'quotactl': 131,
            'getpgid': 132,
            'fchdir': 133,
            'bdflush': 134,
            'sysfs': 135,
            'personality': 136,
            'afs_syscall': 137,
            'setfsuid': 138,
            'setfsgid': 139,
            '_llseek': 140,
            'getdents': 141,
            '_newselect': 142,
            'flock': 143,
            'msync': 144,
            'readv': 145,
            'writev': 146,
            'getsid': 147,
            'fdatasync': 148,
            '_sysctl': 149,
            'mlock': 150,
            'munlock': 151,
            'mlockall': 152,
            'munlockall': 153,
            'sched_setparam': 154,
            'sched_getparam': 155,
            'sched_setscheduler': 156,
            'sched_getscheduler': 157,
            'sched_yield': 158,
            'sched_get_priority_max': 159,
            'sched_get_priority_min': 160,
            'sched_rr_get_interval': 161,
            'nanosleep': 162,
            'mremap': 163,
            'setresuid': 164,
            'getresuid': 165,
            'query_module': 166,
            'poll': 167,
            'nfsservctl': 168,
            'setresgid': 169,
            'getresgid': 170,
            'prctl': 171,
            'rt_sigreturn': 172,
            'rt_sigaction': 173,
            'rt_sigprocmask': 174,
            'rt_sigpending': 175,
            'rt_sigtimedwait': 176,
            'rt_sigqueueinfo': 177,
            'rt_sigsuspend': 178,
            'pread64': 179,
            'pwrite64': 180,
            'chown': 181,
            'getcwd': 182,
            'capget': 183,
            'capset': 184,
            'sigaltstack': 185,
            'sendfile': 186,
            'getpmsg': 187,
            'putpmsg': 188,
            'vfork': 189,
            'ugetrlimit': 190,
            'readahead': 191,
            'mmap2': 192,
            'truncate64': 193,
            'ftruncate64': 194,
            'stat64': 195,
            'lstat64': 196,
            'fstat64': 197,
            'pciconfig_read': 198,
            'pciconfig_write': 199,
            'pciconfig_iobase': 200,
            'multiplexer': 201,
            'getdents64': 202,
            'pivot_root': 203,
            'fcntl64': 204,
            'madvise': 205,
            'mincore': 206,
            'gettid': 207,
            'tkill': 208,
            'setxattr': 209,
            'lsetxattr': 210,
            'fsetxattr': 211,
            'getxattr': 212,
            'lgetxattr': 213,
            'fgetxattr': 214,
            'listxattr': 215,
            'llistxattr': 216,
            'flistxattr': 217,
            'removexattr': 218,
            'lremovexattr': 219,
            'fremovexattr': 220,
            'futex': 221,
            'sched_setaffinity': 222,
            'sched_getaffinity': 223,
            'tuxcall': 225,
            'sendfile64': 226,
            'io_setup': 227,
            'io_destroy': 228,
            'io_getevents': 229,
            'io_submit': 230,
            'io_cancel': 231,
            'set_tid_address': 232,
            'fadvise64': 233,
            'exit_group': 234,
            'lookup_dcookie': 235,
            'epoll_create': 236,
            'epoll_ctl': 237,
            'epoll_wait': 238,
            'remap_file_pages': 239,
            'timer_create': 240,
            'timer_settime': 241,
            'timer_gettime': 242,
            'timer_getoverrun': 243,
            'timer_delete': 244,
            'clock_settime': 245,
            'clock_gettime': 246,
            'clock_getres': 247,
            'clock_nanosleep': 248,
            'swapcontext': 249,
            'tgkill': 250,
            'utimes': 251,
            'statfs64': 252,
            'fstatfs64': 253,
            'fadvise64_64': 254,
            'rtas': 255,
            'sys_debug_setcontext': 256,
            'mq_open': 262,
            'mq_unlink': 263,
            'mq_timedsend': 264,
            'mq_timedreceive': 265,
            'mq_notify': 266,
            'mq_getsetattr': 267,
            'kexec_load': 268,
            'add_key': 269,
            'request_key': 270,
            'keyctl': 271,
            'syscalls': 272,
        }, 
    }
    
    # XXX KLUDGE
    _syscall_table['2.2'] = _syscall_table['2.6']
    _syscall_table['2.4'] = _syscall_table['2.6']
    
    _aliases_table = [
        ('SYS__exit', 'SYS_exit'),
        ('SYS_mmap', 'SYS_mmap2'),           # we dont want to use old_mmap
        ('SYS_getrlimit', 'SYS_ugetrlimit'), # we dont want to use old_getrlimit
        ('SYS_select', 'SYS__newselect'),
    ]
    
    def __init__(self, version = None):
        Linux.__init__(self, version)
        ppc.__init__(self)
        
        # TODO: check if it works on 64bits (should)
        self.localfunctions["syscallN"] = ("asm", """
            syscallN: ! sp [0:r1][4:r2][...][208:
                !mflr r19
                ! linkage = 24
                ! params = upto 6? = 6*4=32
                ! local = 0
                ! gpr * 4 = 32 * 4 = 128
                ! total = 24 + 32 + 128 = ...
                ! 13 * 4*4 = 208
                stwu r1, -256(r1)      ! alloc 208 bytes
                stmw r2, 8(r1)         ! save regs
                lmw r3, 4(r2)          ! set args 3 ... 10
                lwz r0, 0(r2)          ! set syscall num
                sc                     ! if fails SO is true, errno is in r3
                stw r3, 12(r1)         ! save retval r3
                lmw r2, 8(r1)          ! restore regs
                mr r13, r3             ! r13 for MOSDEF retval
                lwz r1, 0(r1)          ! restore sp

                ! bnslr 
                .byte 0x4c
                .byte 0x83
                .byte 0x00
                .byte 0x20
               
                ! failed .. so r13 should be -1 .. errno is r3
                li r3, -1
                mr r13, r3

                blr
        """)
        self.localfunctions["socketcall"] = ("asm", """
            socketcall:
                lwz r0, 0(r2)          ! set syscall num
                lwz r3, 4(r2)          ! set socketcall num
                addi r4, r2, 8         ! args on the stack
                sc
                mr r13, r3             ! save retval r3
                blr
        """)

class Linux_powerpc64(Linux_powerpc):
    
    # <asm-ppc64/unistd.h>
    
    _syscall_table = {
        '2.6': {
            'restart_syscall': 0,
            'exit': 1,
            'fork': 2,
            'read': 3,
            'write': 4,
            'open': 5,
            'close': 6,
            'waitpid': 7,
            'creat': 8,
            'link': 9,
            'unlink': 10,
            'execve': 11,
            'chdir': 12,
            'time': 13,
            'mknod': 14,
            'chmod': 15,
            'lchown': 16,
            'break': 17,
            'oldstat': 18,
            'lseek': 19,
            'getpid': 20,
            'mount': 21,
            'umount': 22,
            'setuid': 23,
            'getuid': 24,
            'stime': 25,
            'ptrace': 26,
            'alarm': 27,
            'oldfstat': 28,
            'pause': 29,
            'utime': 30,
            'stty': 31,
            'gtty': 32,
            'access': 33,
            'nice': 34,
            'ftime': 35,
            'sync': 36,
            'kill': 37,
            'rename': 38,
            'mkdir': 39,
            'rmdir': 40,
            'dup': 41,
            'pipe': 42,
            'times': 43,
            'prof': 44,
            'brk': 45,
            'setgid': 46,
            'getgid': 47,
            'signal': 48,
            'geteuid': 49,
            'getegid': 50,
            'acct': 51,
            'umount2': 52,
            'lock': 53,
            'ioctl': 54,
            'fcntl': 55,
            'mpx': 56,
            'setpgid': 57,
            'ulimit': 58,
            'oldolduname': 59,
            'umask': 60,
            'chroot': 61,
            'ustat': 62,
            'dup2': 63,
            'getppid': 64,
            'getpgrp': 65,
            'setsid': 66,
            'sigaction': 67,
            'sgetmask': 68,
            'ssetmask': 69,
            'setreuid': 70,
            'setregid': 71,
            'sigsuspend': 72,
            'sigpending': 73,
            'sethostname': 74,
            'setrlimit': 75,
            'getrlimit': 76,
            'getrusage': 77,
            'gettimeofday': 78,
            'settimeofday': 79,
            'getgroups': 80,
            'setgroups': 81,
            'select': 82,
            'symlink': 83,
            'oldlstat': 84,
            'readlink': 85,
            'uselib': 86,
            'swapon': 87,
            'reboot': 88,
            'readdir': 89,
            'mmap': 90,
            'munmap': 91,
            'truncate': 92,
            'ftruncate': 93,
            'fchmod': 94,
            'fchown': 95,
            'getpriority': 96,
            'setpriority': 97,
            'profil': 98,
            'statfs': 99,
            'fstatfs': 100,
            'ioperm': 101,
            'socketcall': 102,
            'syslog': 103,
            'setitimer': 104,
            'getitimer': 105,
            'stat': 106,
            'lstat': 107,
            'fstat': 108,
            'olduname': 109,
            'iopl': 110,
            'vhangup': 111,
            'idle': 112,
            'vm86': 113,
            'wait4': 114,
            'swapoff': 115,
            'sysinfo': 116,
            'ipc': 117,
            'fsync': 118,
            'sigreturn': 119,
            'clone': 120,
            'setdomainname': 121,
            'uname': 122,
            'modify_ldt': 123,
            'adjtimex': 124,
            'mprotect': 125,
            'sigprocmask': 126,
            'create_module': 127,
            'init_module': 128,
            'delete_module': 129,
            'get_kernel_syms': 130,
            'quotactl': 131,
            'getpgid': 132,
            'fchdir': 133,
            'bdflush': 134,
            'sysfs': 135,
            'personality': 136,
            'afs_syscall': 137,
            'setfsuid': 138,
            'setfsgid': 139,
            '_llseek': 140,
            'getdents': 141,
            '_newselect': 142,
            'flock': 143,
            'msync': 144,
            'readv': 145,
            'writev': 146,
            'getsid': 147,
            'fdatasync': 148,
            '_sysctl': 149,
            'mlock': 150,
            'munlock': 151,
            'mlockall': 152,
            'munlockall': 153,
            'sched_setparam': 154,
            'sched_getparam': 155,
            'sched_setscheduler': 156,
            'sched_getscheduler': 157,
            'sched_yield': 158,
            'sched_get_priority_max': 159,
            'sched_get_priority_min': 160,
            'sched_rr_get_interval': 161,
            'nanosleep': 162,
            'mremap': 163,
            'setresuid': 164,
            'getresuid': 165,
            'query_module': 166,
            'poll': 167,
            'nfsservctl': 168,
            'setresgid': 169,
            'getresgid': 170,
            'prctl': 171,
            'rt_sigreturn': 172,
            'rt_sigaction': 173,
            'rt_sigprocmask': 174,
            'rt_sigpending': 175,
            'rt_sigtimedwait': 176,
            'rt_sigqueueinfo': 177,
            'rt_sigsuspend': 178,
            'pread64': 179,
            'pwrite64': 180,
            'chown': 181,
            'getcwd': 182,
            'capget': 183,
            'capset': 184,
            'sigaltstack': 185,
            'sendfile': 186,
            'getpmsg': 187,
            'putpmsg': 188,
            'vfork': 189,
            'ugetrlimit': 190,
            'readahead': 191,
            'pciconfig_read': 198,
            'pciconfig_write': 199,
            'pciconfig_iobase': 200,
            'multiplexer': 201,
            'getdents64': 202,
            'pivot_root': 203,
            'madvise': 205,
            'mincore': 206,
            'gettid': 207,
            'tkill': 208,
            'setxattr': 209,
            'lsetxattr': 210,
            'fsetxattr': 211,
            'getxattr': 212,
            'lgetxattr': 213,
            'fgetxattr': 214,
            'listxattr': 215,
            'llistxattr': 216,
            'flistxattr': 217,
            'removexattr': 218,
            'lremovexattr': 219,
            'fremovexattr': 220,
            'futex': 221,
            'sched_setaffinity': 222,
            'sched_getaffinity': 223,
            'tuxcall': 225,
            'io_setup': 227,
            'io_destroy': 228,
            'io_getevents': 229,
            'io_submit': 230,
            'io_cancel': 231,
            'set_tid_address': 232,
            'fadvise64': 233,
            'exit_group': 234,
            'lookup_dcookie': 235,
            'epoll_create': 236,
            'epoll_ctl': 237,
            'epoll_wait': 238,
            'remap_file_pages': 239,
            'timer_create': 240,
            'timer_settime': 241,
            'timer_gettime': 242,
            'timer_getoverrun': 243,
            'timer_delete': 244,
            'clock_settime': 245,
            'clock_gettime': 246,
            'clock_getres': 247,
            'clock_nanosleep': 248,
            'swapcontext': 249,
            'tgkill': 250,
            'utimes': 251,
            'statfs64': 252,
            'fstatfs64': 253,
            'rtas': 255,
            'mbind': 259,
            'get_mempolicy': 260,
            'set_mempolicy': 261,
            'mq_open': 262,
            'mq_unlink': 263,
            'mq_timedsend': 264,
            'mq_timedreceive': 265,
            'mq_notify': 266,
            'mq_getsetattr': 267,
            'add_key': 269,
            'request_key': 270,
            'keyctl': 271,
            'syscalls': 272,
        }, 
    }

    _aliases_table = [
        ('SYS__exit', 'SYS_exit'),
    ]
    
    def __init__(self, version = None):
        Linux_powerpc.__init__(self, version)

class Linux_alpha(Linux):
    
    Endianness = 'big'
    
    # <asm/socket.h>
    
    SOCK_STREAM    = 1
    SOCK_DGRAM     = 2
    SOCK_RAW       = 3
    SOCK_RDM       = 4
    SOCK_SEQPACKET = 5
    SOCK_PACKET    = 10
    
    SOL_SOCKET = 0xffff
    
    SO_DEBUG     = 0x0001
    SO_REUSEADDR = 0x0004
    SO_KEEPALIVE = 0x0008
    SO_DONTROUTE = 0x0010
    SO_BROADCAST = 0x0020
    SO_LINGER    = 0x0080
    SO_OOBINLINE = 0x0100
    
    SO_SNDBUF     = 0x1001
    SO_RCVBUF     = 0x1002
    SO_ERROR      = 0x1007
    SO_TYPE       = 0x1008
    SO_RCVLOWAT   = 0x1010
    SO_SNDLOWAT   = 0x1011
    SO_RCVTIMEO   = 0x1012
    SO_SNDTIMEO   = 0x1013
    SO_ACCEPTCONN = 0x1014
    
    SO_PEERNAME  = 28
    SO_TIMESTAMP = 29
    
    # <bits/mman.h>
    
    PROT_NONE  = 0x0
    PROT_READ  = 0x1
    PROT_WRITE = 0x2
    PROT_EXEC  = 0x4
    
    MAP_SHARED    = 0x01
    MAP_PRIVATE   = 0x02
    MAP_FIXED     = 0x100
    MAP_ANONYMOUS = 0x10
    MAP_ANON      = MAP_ANONYMOUS
    MAP_FILE      = 0
    
    # <bits/poll.h>
    
    POLLIN     = 1 
    POLLPRI    = 2
    POLLOUT    = 4
    POLLERR    = 8
    POLLHUP    = 16
    POLLNVAL   = 32
    POLLRDNORM = 64
    POLLRDBAND = 128
    POLLWRNORM = 256
    POLLWRBAND = 512
    POLLMSG    = 1024
    
    # <bits/resource.h>
    
    RLIMIT_CPU     = 0
    RLIMIT_FSIZE   = 1
    RLIMIT_DATA    = 2
    RLIMIT_STACK   = 3
    RLIMIT_CORE    = 4
    RLIMIT_RSS     = 5
    RLIMIT_NOFILE  = 6
    RLIMIT_AS      = 7
    RLIMIT_NPROC   = 8
    RLIMIT_MEMLOCK = 9
    RLIMIT_LOCKS   = 10
    
    def __init__(self, version = None):
        Linux.__init__(self, version)

class Linux_parisc(Linux):
    
    Endianness = 'big'
    
    SO_DEBUG =     0x0001
    SO_REUSEADDR = 0x0004
    SO_KEEPALIVE = 0x0008
    SO_LINGER =    0x0080
    SO_ERROR =     0x1007
    SO_TYPE =      0x1008
    
    # <asm/socket.h>
    
    SOCK_STREAM    = 1
    SOCK_DGRAM     = 2
    SOCK_RAW       = 3
    SOCK_RDM       = 4
    SOCK_SEQPACKET = 5
    SOCK_PACKET    = 10
    
    SOL_SOCKET = 0xffff
    
    SO_DEBUG        = 0x0001
    SO_REUSEADDR    = 0x0004
    SO_KEEPALIVE    = 0x0008
    SO_DONTROUTE    = 0x0010
    SO_BROADCAST    = 0x0020
    SO_LINGER       = 0x0080
    SO_OOBINLINE    = 0x0100
    SO_REUSEPORT    = 0x0200
    SO_SNDBUF       = 0x1001
    SO_RCVBUF       = 0x1002
    SO_SNDLOWAT     = 0x1003
    SO_RCVLOWAT     = 0x1004
    SO_SNDTIMEO     = 0x1005
    SO_RCVTIMEO     = 0x1006
    SO_ERROR        = 0x1007
    SO_TYPE         = 0x1008
    SO_PEERNAME     = 0x2000

    SO_NO_CHECK     = 0x400b
    SO_PRIORITY     = 0x400c
    SO_BSDCOMPAT    = 0x400e
    SO_PASSCRED     = 0x4010
    SO_PEERCRED     = 0x4011
    SO_TIMESTAMP    = 0x4012
    SO_BINDTODEVICE = 0x4019
    SO_ACCEPTCONN   = 0x401c
    
    # <bits/mman.h>
    
    PROT_NONE  = 0x0
    PROT_READ  = 0x1
    PROT_WRITE = 0x2
    PROT_EXEC  = 0x4
    
    MAP_SHARED    = 0x01
    MAP_PRIVATE   = 0x02
    MAP_TYPE      = 0x03
    MAP_FIXED     = 0x04
    MAP_ANONYMOUS = 0x10
    
    MAP_DENYWRITE  = 0x0800
    MAP_EXECUTABLE = 0x1000
    MAP_LOCKED     = 0x2000
    MAP_NORESERVE  = 0x4000
    MAP_GROWSDOWN  = 0x8000
    
    MAP_ANON      = MAP_ANONYMOUS
    MAP_FILE      = 0
    MAP_VARIABLE  = 0
    
    # <bits/poll.h>
    
    POLLIN     = 0x0001 
    POLLPRI    = 0x0002
    POLLOUT    = 0x0004
    POLLERR    = 0x0008
    POLLHUP    = 0x0010
    POLLNVAL   = 0x0020
    POLLRDNORM = 0x0040
    POLLRDBAND = 0x0080
    POLLWRNORM = 0x0100
    POLLWRBAND = 0x0200
    POLLMSG    = 0x0400
    
    # <bits/resource.h>
    
    RLIMIT_CPU     = 0
    RLIMIT_FSIZE   = 1
    RLIMIT_DATA    = 2
    RLIMIT_STACK   = 3
    RLIMIT_CORE    = 4
    RLIMIT_RSS     = 5
    RLIMIT_NPROC   = 6
    RLIMIT_NOFILE  = 7
    RLIMIT_MEMLOCK = 8
    RLIMIT_AS      = 9
    RLIMIT_LOCKS   = 10
    
    def __init__(self, version = None):
        Linux.__init__(self, version)

class Linux_arm(Linux):
    
    Endianness = 'big'
    
    # <asm/socket.h>
    
    SOCK_STREAM    = 1
    SOCK_DGRAM     = 2
    SOCK_RAW       = 3
    SOCK_RDM       = 4
    SOCK_SEQPACKET = 5
    SOCK_PACKET    = 10
    
    SOL_SOCKET = 1
    
    SO_DEBUG        = 1
    SO_REUSEADDR    = 2
    SO_TYPE         = 3
    SO_ERROR        = 4
    SO_DONTROUTE    = 5
    SO_BROADCAST    = 6
    SO_SNDBUF       = 7
    SO_RCVBUF       = 8
    SO_KEEPALIVE    = 9
    SO_OOBINLINE    = 10
    SO_NO_CHECK     = 11
    SO_PRIORITY     = 12
    SO_LINGER       = 13
    SO_BSDCOMPAT    = 14
    SO_REUSEPORT    = 15
    SO_PASSCRED     = 16
    SO_PEERCRED     = 17
    SO_RCVLOWAT     = 18
    SO_SNDLOWAT     = 19
    SO_RCVTIMEO     = 20
    SO_SNDTIMEO     = 21
    SO_BINDTODEVICE = 25
    SO_PEERNAME     = 28
    SO_TIMESTAMP    = 29
    SO_ACCEPTCONN   = 30
    
    # <bits/mman.h>
    
    PROT_NONE  = 0x0
    PROT_READ  = 0x1
    PROT_WRITE = 0x2
    PROT_EXEC  = 0x4
    
    MAP_SHARED    = 0x01
    MAP_PRIVATE   = 0x02
    MAP_FIXED     = 0x10
    MAP_ANONYMOUS = 0x20
    MAP_ANON      = MAP_ANONYMOUS
    MAP_FILE      = 0
    
    # <bits/poll.h>
    
    POLLIN     = 0x0001 
    POLLPRI    = 0x0002
    POLLOUT    = 0x0004
    POLLERR    = 0x0008
    POLLHUP    = 0x0010
    POLLNVAL   = 0x0020
    POLLRDNORM = 0x0040
    POLLRDBAND = 0x0080
    POLLWRNORM = 0x0100
    POLLWRBAND = 0x0200
    POLLMSG    = 0x0400
    
    # <bits/resource.h>
    
    RLIMIT_CPU     = 0
    RLIMIT_FSIZE   = 1
    RLIMIT_DATA    = 2
    RLIMIT_STACK   = 3
    RLIMIT_CORE    = 4
    RLIMIT_RSS     = 5
    RLIMIT_NPROC   = 6
    RLIMIT_NOFILE  = 7
    RLIMIT_MEMLOCK = 8
    RLIMIT_AS      = 9
    RLIMIT_LOCKS   = 10
    
    def __init__(self, version = None):
        Linux.__init__(self, version)

class Linux_armel(Linux_arm):
    
    Endianness = 'little'
    
    OABI_SYSCALL_BASE = 0x900000
    SYSCALL_BASE = OABI_SYSCALL_BASE
    
    _syscall_table = {
        '2.6': {
            'restart_syscall': 0,
            'exit': 1,
            'fork': 2,
            'read': 3,
            'write': 4,
            'open': 5,
            'close': 6,
            'creat': 8,
            'link': 9,
            'unlink': 10,
            'execve': 11,
            'chdir': 12,
            'time': 13,
            'mknod': 14,
            'chmod': 15,
            'lchown': 16,
            'lseek': 19,
            'getpid': 20,
            'mount': 21,
            'umount': 22,
            'setuid': 23,
            'getuid': 24,
            'stime': 25,
            'ptrace': 26,
            'alarm': 27,
            'pause': 29,
            'utime': 30,
            'access': 33,
            'nice': 34,
            'sync': 36,
            'kill': 37,
            'rename': 38,
            'mkdir': 39,
            'rmdir': 40,
            'dup': 41,
            'pipe': 42,
            'times': 43,
            'brk': 45,
            'setgid': 46,
            'getgid': 47,
            'geteuid': 49,
            'getegid': 50,
            'acct': 51,
            'umount2': 52,
            'ioctl': 54,
            'fcntl': 55,
            'setpgid': 57,
            'umask': 60,
            'chroot': 61,
            'ustat': 62,
            'dup2': 63,
            'getppid': 64,
            'getpgrp': 65,
            'setsid': 66,
            'sigaction': 67,
            'setreuid': 70,
            'setregid': 71,
            'sigsuspend': 72,
            'sigpending': 73,
            'sethostname': 74,
            'setrlimit': 75,
            'getrlimit': 76,
            'getrusage': 77,
            'gettimeofday': 78,
            'settimeofday': 79,
            'getgroups': 80,
            'setgroups': 81,
            'select': 82,
            'symlink': 83,
            'readlink': 85,
            'uselib': 86,
            'swapon': 87,
            'reboot': 88,
            'readdir': 89,
            'mmap': 90,
            'munmap': 91,
            'truncate': 92,
            'ftruncate': 93,
            'fchmod': 94,
            'fchown': 95,
            'getpriority': 96,
            'setpriority': 97,
            'statfs': 99,
            'fstatfs': 100,
            'socketcall': 102,
            'syslog': 103,
            'setitimer': 104,
            'getitimer': 105,
            'stat': 106,
            'lstat': 107,
            'fstat': 108,
            'vhangup': 111,
            'syscall': 113,
            'wait4': 114,
            'swapoff': 115,
            'sysinfo': 116,
            'ipc': 117,
            'fsync': 118,
            'sigreturn': 119,
            'clone': 120,
            'setdomainname': 121,
            'uname': 122,
            'adjtimex': 124,
            'mprotect': 125,
            'sigprocmask': 126,
            'create_module': 127,
            'init_module': 128,
            'delete_module': 129,
            'get_kernel_syms': 130,
            'quotactl': 131,
            'getpgid': 132,
            'fchdir': 133,
            'bdflush': 134,
            'sysfs': 135,
            'personality': 136,
            'setfsuid': 138,
            'setfsgid': 139,
            '_llseek': 140,
            'getdents': 141,
            '_newselect': 142,
            'flock': 143,
            'msync': 144,
            'readv': 145,
            'writev': 146,
            'getsid': 147,
            'fdatasync': 148,
            '_sysctl': 149,
            'mlock': 150,
            'munlock': 151,
            'mlockall': 152,
            'munlockall': 153,
            'sched_setparam': 154,
            'sched_getparam': 155,
            'sched_setscheduler': 156,
            'sched_getscheduler': 157,
            'sched_yield': 158,
            'sched_get_priority_max': 159,
            'sched_get_priority_min': 160,
            'sched_rr_get_interval': 161,
            'nanosleep': 162,
            'mremap': 163,
            'setresuid': 164,
            'getresuid': 165,
            'query_module': 167,
            'poll': 168,
            'nfsservctl': 169,
            'setresgid': 170,
            'getresgid': 171,
            'prctl': 172,
            'rt_sigreturn': 173,
            'rt_sigaction': 174,
            'rt_sigprocmask': 175,
            'rt_sigpending': 176,
            'rt_sigtimedwait': 177,
            'rt_sigqueueinfo': 178,
            'rt_sigsuspend': 179,
            'pread64': 180,
            'pwrite64': 181,
            'chown': 182,
            'getcwd': 183,
            'capget': 184,
            'capset': 185,
            'sigaltstack': 186,
            'sendfile': 187,
            'vfork': 190,
            'ugetrlimit': 191,
            'mmap2': 192,
            'truncate64': 193,
            'ftruncate64': 194,
            'stat64': 195,
            'lstat64': 196,
            'fstat64': 197,
            'lchown32': 198,
            'getuid32': 199,
            'getgid32': 200,
            'geteuid32': 201,
            'getegid32': 202,
            'setreuid32': 203,
            'setregid32': 204,
            'getgroups32': 205,
            'setgroups32': 206,
            'fchown32': 207,
            'setresuid32': 208,
            'getresuid32': 209,
            'setresgid32': 210,
            'getresgid32': 211,
            'chown32': 212,
            'setuid32': 213,
            'setgid32': 214,
            'setfsuid32': 215,
            'setfsgid32': 216,
            'getdents64': 217,
            'pivot_root': 218,
            'mincore': 219,
            'madvise': 220,
            'fcntl64': 221,
            'gettid': 224,
            'readahead': 225,
            'setxattr': 226,
            'lsetxattr': 227,
            'fsetxattr': 228,
            'getxattr': 229,
            'lgetxattr': 230,
            'fgetxattr': 231,
            'listxattr': 232,
            'llistxattr': 233,
            'flistxattr': 234,
            'removexattr': 235,
            'lremovexattr': 236,
            'fremovexattr': 237,
            'tkill': 238,
            'sendfile64': 239,
            'futex': 240,
            'sched_setaffinity': 241,
            'sched_getaffinity': 242,
            'io_setup': 243,
            'io_destroy': 244,
            'io_getevents': 245,
            'io_submit': 246,
            'io_cancel': 247,
            'exit_group': 248,
            'lookup_dcookie': 249,
            'epoll_create': 250,
            'epoll_ctl': 251,
            'epoll_wait': 252,
            'remap_file_pages': 253,
            'set_tid_address': 256,
            'timer_create': 257,
            'timer_settime': 258,
            'timer_gettime': 259,
            'timer_getoverrun': 260,
            'timer_delete': 261,
            'clock_settime': 262,
            'clock_gettime': 263,
            'clock_getres': 264,
            'clock_nanosleep': 265,
            'statfs64': 266,
            'fstatfs64': 267,
            'tgkill': 268,
            'utimes': 269,
            'arm_fadvise64_64': 270,
            'pciconfig_iobase': 271,
            'pciconfig_read': 272,
            'pciconfig_write': 273,
            'mq_open': 274,
            'mq_unlink': 275,
            'mq_timedsend': 276,
            'mq_timedreceive': 277,
            'mq_notify': 278,
            'mq_getsetattr': 279,
            'waitid': 280,
            'socket': 281,
            'bind': 282,
            'connect': 283,
            'listen': 284,
            'accept': 285,
            'getsockname': 286,
            'getpeername': 287,
            'socketpair': 288,
            'send': 289,
            'sendto': 290,
            'recv': 291,
            'recvfrom': 292,
            'shutdown': 293,
            'setsockopt': 294,
            'getsockopt': 295,
            'sendmsg': 296,
            'recvmsg': 297,
            'semop': 298,
            'semget': 299,
            'semctl': 300,
            'msgsnd': 301,
            'msgrcv': 302,
            'msgget': 303,
            'msgctl': 304,
            'shmat': 305,
            'shmdt': 306,
            'shmget': 307,
            'shmctl': 308,
            'add_key': 309,
            'request_key': 310,
            'keyctl': 311,
            'semtimedop': 312,
            'vserver': 313,
            'ioprio_set': 314,
            'ioprio_get': 315,
            'inotify_init': 316,
            'inotify_add_watch': 317,
            'inotify_rm_watch': 318,
            'mbind': 319,
            'get_mempolicy': 320,
            'set_mempolicy': 321,
        }, 
    }
    
    def __init__(self, version = None):
        Linux.__init__(self, version)
        
        self.localfunctions["syscallN"] = ("asm", """
            @ %r0 is arg0
            @ %r1 is arg1
            @ %r2 is arg2
            @ ...
            syscallN: ! sp [0:r1][4:r2][...][208:
                mov ip, sp			@ save %sp in general register ip=%r12
                stmdb sp!, {r4, r5, r6}		@ multi store on stack
                ldmia ip, {r4, r5, r6}		@ multi load from %r12
                swi 0x00900071			@ SYS_syscall (SoftWare Interrupt OABI_SYSCALL_BASE + 113)
                ldmia sp!, {r4, r5, r6}
                cmn r0, #4096			@ compare retval with -4096 = 0xfffff000
                movcc pc, lr			@ mov lr (return address) to pc (program counter)
                b somewhere			@ in case of error
        """)

