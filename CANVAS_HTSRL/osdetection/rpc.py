import libs.addressdb as addressdb
import libs.dtspcd_client as dtspcd_client
import libs.canvasos as canvasos

class dtspcd_detect(object):
    """
    Connects to dtspcd and detects the remote operating system
    """
    def do_dtspc(self):
        """ do solaris detection """

        result = None

        try:
            dtuname = dtspcd_client.DTSPCDClient(self.host,exploit=self)
            dtuname.setup()
            unamedict = dtuname.get_uname()
            self.log("RPC DETECT: unamedict from dtspcd = %s" % unamedict)

            if unamedict["os"].find("SunOS") != -1:

                solDict={}
                solDict[-2] = "Solaris" #unknown Solaris telnet banner
                solDict[6] = "2.6"
                for i in range(7, 11):
                    solDict[i] = "%d" % i
                
                norm = addressdb.SolarisAddress()
                rel = norm.rel_normalize(unamedict["version"])
                result = canvasos.new("Solaris")
                #XXX: where does soldict com from ?!?!?
                result.version = solDict[rel]
                
                if unamedict["arch"] == "i86pc":
                    self.log("RPC DETECT: Arch found: x86")
                    result.arch = "x86"
                    
                if unamedict["arch"] == "sun4u":
                    self.log("RPC DETECT: Arch found: SPARC")
                    result.arch = "SPARC"

                self.log('RPC DETECT: dtspcd returned: %s' % result)
            else:
                #do nothing for now! when the AiX, HP-UX or others
                #use it ...
                pass

        except Exception, msg:
            self.log("RPC DETECT: dtspcd OS detection returned: %s" % str(msg))
            
        return result
    
class rpcdetect:
        
    def __init__(self):
        return
    
    def do_rpcdump(self):
        result = None        
        try:
            rpcd = self.engine.getModuleExploit("rpcdump")
            rpcd.link(self)
            rpcd.setPort(111)
            rpcd.run()
            found_os = rpcd.get_os()
            if found_os.base.lower() != "unknown":
                result = found_os
        except:
            pass
        
        return result
    
    
    def run_rpcdetect(self):     
        result = None
        result = self.do_dtspc()
        
        if not result:
            result = self.do_rpcdump()
            
        return result

