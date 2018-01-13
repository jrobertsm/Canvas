#!/usr/bin/env python
"""
reporting.py

This reporting library takes in state information from a running module or canvas engine and
stores it, outputting formatted HTML when required.

"""
import html

#we need to encode any data we put in the report!
from exploitutils import xmlencode

class report:
    """
    Holds all the information for one scan/exploit assessment
    """
    def __init__(self, tpref="", sil_flag=False):
        self.targets={}
        self.starttime=None
        self.endtime=None
        #dictionaries of target type we use to store our successes and failures
        self.successes={}
        self.failures={}
        self.html = html.HTML(sil_flag)
        self.images = {}
        self.os_stats={}
        self.tpref = tpref
        self.sil_flag=sil_flag
        self.extras = False
        self.pofhosts = []
        return

    def newhost(self,target):
        """
        Add a new host to our list of hosts we know about
        """
        self.targets[target]=[]
        return

    def note(self,target,note):
        """
        Add a note about a host, for example "This host appears to be a web server"
        """
        self.targets[target]+=[("",note)]
        return

    def report_os(self,os, ip=False):
        """
        Send us a canvasos please
        """
        myos=str(os)
        myip=str(ip)

        self.os_stats[myos]=myip
        #if myos not in self.os_stats.keys():
        #    self.os_stats[myos]=0
        #self.os_stats[myos]+=1
        return

    def report_success(self,host,usedvuln):
        """
        When you break into a machine, you call this function
        We want host to be an object, not  a string 
        """
        self.successes[host]=usedvuln
        os=host.get_knowledge("OS")
        ip=host.get_knowledge("IP")
        if os:
            self.report_os(os, ip)
        return

    def setImage(self, target, ret):
        self.images[target] = ret

    def report_failure(self,host):
        self.failures[host]=True
        os=host.get_knowledge("OS")
        ip=host.get_knowledge("IP")
        if os:
            self.report_os(os,ip)
        return

    def generate_html_header(self):
        if self.sil_flag:
            ttag = "SILICA"
        else:
            ttag = "CANVAS"

        """Generate a header including the start and end time if found"""
        if (self.starttime!=None and self.endtime!=None):
            #if we have a start time and an end time
            title="%s Report (%s to %s)"%(ttag, self.starttime,self.endtime)
        else:
            #no start or end time
            title=ttag+ " Report"

        if(self.tpref!=""):
            title+=" "+ self.tpref

        self.html.setTitle(title)
        return self.html.raw()

    def add_extras(self, xdata):
        self.extras = xdata
        return


    # This function appends hosts found by POF but not from the vulnassess list
    def append_pof_hosts(self):
        tl = []
        tb = []
        # Generate list of IPs found from VulnAssess
        try:   
            for xhost in self.targets.keys():
                    ip = str(xhost.get_knowledge("IP")).split(' ')[2]
                    tl.append(ip)
        except IndexError:
                pass

        # Check what IPs weren't in the list and add them
        for ip_p in self.pofhosts:
            if ip_p not in tl:
                tb.append(("Host: %s<br>\nOS: Windows<br>\n"%xmlencode(ip_p), 0))
        
        if tb:
            self.html.addVuln("Passive OS detection", "", [], tb)
        
        return
    
    
    def html_from_host(self,host, success=""):
        """
        returns a string of htmlized interesting data from the target object
        """
        tbl = []
        kprim = host.get_knowledge("TCPPORTS")
        user_pass = str(host.get_knowledge("user_pass"))
        ip_data = str(host.get_knowledge("IPDATA"))

        
        openports=[]
        if kprim:
            openports = kprim.known

        if(openports == []):
            ports = ""
        else:
            ports = "Open Ports: %s<br>\n" % openports

        #if you call self.note() this is where it gets used
        #this loop just looks for notes our module has explicitly set with self.node("something")
        for attribute,value in self.targets[host]:
            ttbuf = "%s" %(xmlencode(value))
            ttbuf = ttbuf.replace("Known: ", "")
            tbl.append((ttbuf, 0))

        tip=host.get_knowledge("IP")
        tos=str(host.get_knowledge("OS","Unknown"))
        # If vulnassess fails then fail back to passive os detection
        if tos == "Unknown" and (tip in self.pofhosts):
            tos="Windows"

        tbl.append( ("%s<br>\n"%xmlencode(tos), 0) )
        if user_pass:
            tbl.append(("%s<br>\n"%xmlencode(user_pass), 0))
        if ip_data:
            tbl.append(("%s<br>\n"%xmlencode(ip_data), 0))

        if ports:
            ap_port = [ports]
        else:
            ap_port = []
            
        self.html.addVuln( str(host.interface), success, ap_port, tbl )
        if self.images.has_key(host):
            ret = self.images[host]
            for a in ret:
                for b in a:
                    f = b[2] #./My_Screenshots/screengrab-427.bmp'
                    f = f.replace("conf", "bmp")
                    f="."+f #make this ../My_Screenshots
                    self.html.addVulnImage(f)
        return 


    def generate_vulnassess_html(self):
        """
        Returns HTML reporting information
        """
        #TODO: Escape all this data so no one releases lame advisory on css in our reports
        self.generate_html_header()
        for host in self.targets.keys():
            self.html_from_host(host)
        self.append_pof_hosts()
        return self.html.raw()


    def generate_summary(self):
        """
        Tell the use how many alive hosts we found, how many hosts we owned, and what the OS's were that
        we found.
        """
        total=len(self.successes.keys())+len(self.failures.keys())
        self.html.addSummary("Total Hosts Found","%d"%total)
        tbl=[]
        for oses in self.os_stats.keys():
            #create a little summary line of how any of that type of OS we found 
            tbl+=["%s: %s"%(xmlencode(oses),str(self.os_stats[oses]))]
        self.html.addSummary("OS Summary",tbl)
        if self.extras:
            self.html.addSummary("Results", xmlencode(self.extras))
        return 

    def generate_massattack_html(self):
        """
       Specific HTML for mass attack module
       """
        self.generate_html_header()
        self.generate_summary()

        for target in self.successes:
            self.html_from_host(target, "Broke into %s with %s" % (target.interface,self.successes[target]))
        return self.html.raw()




