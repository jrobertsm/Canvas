#!/usr/bin/python

import sys
if "." not in sys.path: sys.path.append(".")

from threading import Thread
import os
import time 

#try to get uname so we know windows/linux and up2date python or not
try:
    import platform
    uname=str(platform.uname())+"_"+platform.python_version()
except:
    uname="None"
    
import base64
import urllib

from engine.config import canvas_root_directory
from internal import *

class versionchecker(Thread):
    """
    Calls out to a remote 
    """
    def __init__(self, engine):
        self.engine=engine
        self.URL="https://www.immunityinc.com/cgi-bin/current_canvas_version.py"
        Thread.__init__(self)
        return 

    def check(self, URL):
        if not self.engine.config["VersionCheck"]:
            devlog("versionchecker","No version check due to configuration")
            return False 
        try:
            #print "URL: %s"%URL
            f = urllib.urlopen(URL)
            version=f.read()
            #no trailing \n
            version=version.strip()
            if version!=self.currentversion:
                self.engine.log("Current version is: %s, your version is %s. You might want to upgrade to a more current version." % (version, self.currentversion))
                return True
            else:
                devlog("versionchecker","Version is current version on server")
        except:
            #import traceback
            #traceback.print_exc(file=sys.stderr)
            devlog("versionchecker", "Failed to connect to remote machine for version check")
            return False
        return False

    def run(self):
        """
        Calls the self.realrun function but catches 
        when sys.exit is called
        """
        i=1
        try:
            self.realrun()
        except:
            #true will be "none" when sys.exit(1) is called
            if devlog!=None:
                print "Reraising"
                raise 
        return 

    def realrun(self):
        #get the             
        userdatafilename=os.path.join(canvas_root_directory,"userdata")
        try:
            expiredate,contactemail,username=file(userdatafilename,"r").readlines()[:3]
        except:
            expiredate,contactemail,username=("None","None","None")
        username=username.strip()
        changelogname=os.path.join(canvas_root_directory,"Changelog.txt")
        currentversion=file(changelogname,"r").readline()
        currentversion=currentversion.strip()
        self.currentversion=currentversion
        alldata=str(uname)+"_"+str(username)+"_"+str(currentversion)
        devlog("versionchecker", "Checking version: %s"%alldata)
        session=base64.encodestring(alldata).replace("\n","")
        devlog("versionchecker", "Session: %s"%session)
        URL=self.URL+"?id=%s"%session
        if not self.check(URL):
            pass
            #self.engine.log("Running CANVAS Version: %s"%currentversion)
        return 
    
if __name__=="__main__":
    #testing our version checker
    import canvasengine
    from internal import debug 
    debug.add_debug_level("versionchecker")
    myengine=canvasengine.canvasengine()
    myversionchecker=versionchecker(myengine)
    myversionchecker.run()
    time.sleep(5)
        