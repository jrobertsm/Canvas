#! /usr/bin/env python
"""
    httpclientside.py
    
    HTTP Client side exploit that works with httpserver (derivated from tcpexploit)
"""
import os,getopt
import sys
import socket
from exploitutils import *


from tcpexploit import tcpexploit

class httpclientside(tcpexploit):
    def __init__(self):
        tcpexploit.__init__(self)
        self.UserAgent = [ ]
        self.searchMethod = self.AcceptAll
        self.cangzip=1
        self.datatype="binary/octet-stream"
        self.mimetype = None
        
    def AcceptAll(self, useragent):
        self.log("Accepting any useragent: %s"%prettyprint(useragent))
        return 1
    
    def SearchBrowserType(self, useragent):
        self.log("Searching browser type for %s"%(str(useragent)))
        (type, version) = self.getBrowser(useragent)
        if not type and not version:
            return 0
        type=type.replace(" ","")
        #print "Type=%s"%type
        self.log("Browser type=%s"%type)
        for a in self.UserAgent:
            if a == type:
                return 1
        return 0
            
    def SearchBrowserVersion(self, useragent):
        self.log("Searching browser version")
        (type, version) = self.getBrowser(useragent)
        if not type and not version:
            return 0
        version=version.replace(" ","") #ignore spaces here
        self.log("Target version: %s"%version)
        for a in self.UserAgent:
            if a == version:
                return 1
        return 0
    
    def CmpAnyTag(self, useragent):
        self.log("Comparing any tag: %s"%prettyprint(useragent))
        (browser, tags, extrainfo) = useragent
        for a in self.UserAgent:
            if a == tags:
                return 1
        return 0

    def CmpBrowser_CmpAnyTag_CmpExtraInfo(self, useragent):
        self.log("CmpBrowser_CmpAny_CmpExtraInfo %s"%useragent)
        (browser, tags, extrainfo) = useragent

        for a in self.UserAgent:
            (a_type, a_tag, a_extrainfo) = a
            if browser == a_type and extrainfo == a_extrainfo and a_tag in tags:
                return 1
        return 0

    def CmpBrowser_FindAnyTag_CmpExtraInfo(self, useragent):
        (browser, tags, extrainfo) = useragent

        for a in self.UserAgent:
            (a_type, a_tag, a_extrainfo) = a
            if browser == a_type and extrainfo == a_extrainfo:
                for a in tags:
                    if a.find(a_tag)>-1:
                        return 1
        return 0

    def FindBrowser_FindAnyTag_CmpExtraInfo(self, useragent):
        # XXX: fix for init from CheckUserAgent("") httpserver.py
        if useragent == "":
            return 0
        if len(useragent)<3:
            return 0
        (browser, tags, extrainfo) = useragent

        for a in self.UserAgent:
            #print "Useragent value: %s"%str(a)
            (a_type, a_tag, a_extrainfo) = a
            if browser.find(a_type) > -1 and extrainfo == a_extrainfo:
                for a in tags:
                    #print "Tag: %s"%a 
                    if a.find(a_tag)>-1:
                        return 1
                    #print "Tag %s not found in %s"%(a, a_tag)
        return 0
    
    
    def CmpAnyTags(self, useragent):
        self.log("CmpAnyTags")
        (browser, tags, extrainfo) = useragent

        for a in self.UserAgent:
            if a in tags:
                return 1
        return 0
            
        
    """ removed on 07/27/2006, approved by nico, he will restore it later.
    def getBrowser(self, useragent):
        from db.UserAgent import UserAgent
        (browser, tags, extrainfo) = useragent
        for browser_type in UserAgent.keys():

            for browser_version in UserAgent[browser_type].keys():
                try:
                    for (ua_type, ua_tags, ua_extra) in UserAgent[browser_type][browser_version]:
                        if browser == ua_type and tags == ua_tags and extrainfo == ua_extra:
                            return (browser_type, browser_version)
                except ValueError:
                    #print tbl
                    (ua_type, ua_tags, ua_extra) = tbl[0]
                    sys.exit(0)
        return ('', '')
    """


