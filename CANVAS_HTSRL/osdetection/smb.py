import libs.canvasos as canvasos
import msrpc

class smbdetect:
    
    def __init__(self):
        self.user = None
        self.password = None
        return

    def do_smb(self):
        """ do windows SMB detection """

        result = None
        
        self.log("SMB DETECT: Doing SMB OS Detection")
        #set default port here
        for port in [139, 445]:
            smbobj = msrpc.SMB(self.host, port=port, getsock=self)
            smbobj.covertness = self.covertness
            smbobj.username = self.user
            smbobj.password = self.password
            
            ret = smbobj.connect()
            
            self.log('SMB DETECT: SMB OS Detection (port=%d) returned %s' % (port, smbobj.os))
                    
            if smbobj.lanman.lower() != 'unknown':
                
                self.log("SMB DETECT: Adding lanman knowledge: %s" % smbobj.lanman)
                self.target.add_knowledge("Lanman", smbobj.lanman, 100)
                
                self.log("SMB DETECT: Adding domain knowledge: %s" % smbobj.domain)
                self.target.add_knowledge("SMBDomain", smbobj.domain, 100)
                
                self.log("SMB DETECT: Adding server knowledge: %s" % smbobj.server)
                self.target.add_knowledge("SMBServer", smbobj.server, 100)
                break 

                

        # check native OS, assume Linux for SAMBA

        if 'UNIX' in smbobj.os.upper():

            #When you assume...
            #if 'SAMBA' in smbobj.lanman.upper():
            #    self.log("SMB DETECT: found Unix SAMBA, assuming Linux OS")
            #    result = canvasos.new("Linux")
            
            if 'SUSE' in smbobj.lanman.upper():
                result = canvasos.new("Linux")
                result.version = "SuSE"

        # Windows SMB muck

        elif 'VISTA' in smbobj.os.upper():
            result = canvasos.new('Windows')
            result.version = 'Vista'
            for subversion in ['Ultimate']:
                if smbobj.os.find(subversion) != -1:
                    result.family = subversion

        elif 'LAN MANAGER 4.0' in smbobj.os.upper():
            result = canvasos.new('Windows')
            result.version = 'NT 4.0'
                
        elif 'WINDOWS' in smbobj.os.upper():
            result = canvasos.new('Windows')

            if smbobj.os.find('Windows 5.0') != -1:
                result.version = '2000'

            elif smbobj.os.find('Windows 5.1') != -1:
                result.version = 'XP'

            elif smbobj.os.find('Windows .NET 5.2') != -1:
                result.version = '.NET RC2'

            elif smbobj.os.find('Windows NT 4.0') != -1:
                result.version = 'NT'

            elif smbobj.os.find('Windows 4.0') != -1:
                result.version = '9x'

            elif smbobj.os.find('Windows Server 2003') != -1:
                result.version = '2003'
                if smbobj.os.find('Service Pack 1') != -1:
                    result.servicepack.append('SP1')
                elif smbobj.os.find('Service Pack 2') != -1:
                    result.servicepack.append('SP2')
                else:
                    result.servicepack.append('SP0')

        return result

    def run_smbdetect(self):     
        result = None
        result = self.do_smb()
        return result
