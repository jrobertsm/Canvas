#! /usr/bin/env python

"""
hostknowledge.py - contains a fuzzy logic representation of what I know about a host
"""

#for uint32
from exploitutils import *
#for saving/loading hosts
import cPickle
import os.path
import socket
import time
import sys
from canvaserror import *

class lineList:
    def __init__(self,parent):
        self.parent=parent
        self.children=[]
        self._text=""
        self._activated_text=""
        self.pix=""
        self.gui=None
        self.engine=None
        self.activated=0
        self.amselected = self.activated # XXX
        self.activate_text()
        #text depends on our activation state, so we cannot pickle it
        self.text=""
        self.pickledefaults={"text": "Just Unpickled", "parent": None, "gui": None, "activated": 0, "amselected": 0, "_activated_text": "", "engine": None}
        
    def __getstate__(self):
        """used for pickle
        
        We don't want to show the "(current callback)" part if we've
        just unpickled, because it's untrue, so we manually set self.text here in
        our pickle dictionary.
        """
        self.pickledefaults["text"]=self._text
        dontpickle=self.pickledefaults.keys()
        newdict=filterdict(dontpickle, self.__dict__)
        for key in dontpickle:
            newdict[key]=self.pickledefaults[key]
        return newdict
        #return (self.parent,self.children,self._text,self.pix)
        
    def set_all_parents(self, obj):
        self.parent=obj
        self.gui=obj.gui
        self.engine=obj.engine
        for c in self.children:
            c.set_all_parents(self)
        return 
        
    def old__setstate__(self,state):
        """takes in a tuple state from the pickle operation"""
        p,c,t,pix=state
        self.parent=p
        self.children=c
        self.text=t
        self.pix=pix
        self.engine=None
        self._text=t
        self.activated=0
        self.amselected=0
        self.gui=None
        
    def activate_text(self):
        """
        Construct self.text which is the line shown by the GUI
        
        """

        if self.activated:
            self.text = self._text + self._activated_text
        else:
            self.text = self._text
    
    def get_pix(self):
        return self.pix
    
    def update_pix(self):
        """used to set a different picture if we're busy, etc"""
        return
    
    def get_text(self):
        return self.text
    
    def get_children(self):
        return self.children
    
    def get_menu(self):
        """Gets a list of strings which will be made into a menu"""
        return []
    
    def menu_response(self, widget, astring):
        #print "Got %s"%astring
        pass
        
    def add(self,child):
        self.children+=[child]
        child.parent=self
        
    def delete(self,child):
        """
        Deletes a child line from the GUI
        
        Should be safe to call from any thread since we just use gui_queue. Of course
        this means the actual delete may get postponed until the Main thread runs.
        This may not be what you really intended, but there's no easy way around it. We
        could sleep() to trigger the main thread, I guess.
        """
        try:
            index=self.children.index(child)
        except ValueError:
            devlog("hostKnowledge", "child is not in the list of children????")
            return 
        del self.children[index]
        if self.gui and self.engine:
            #self.gui.delete(child)
            self.engine.gui.gui_queue_append("deleteLine", [ child ] )
        time.sleep(0.1)
        if child in self.children:
            devlog("hostKnowledge", "Child is still in children - this is incorrect!")
        return

    def update_gui(self):
        """
        It's perfectly ok to call this from any thread - update_gui just
        adds to the gui_queue such that the GUI updates whatever line we are
        """
        #check to see if this has changed because we may have recently become 
        #activated or loaded from a pickle
        self.activate_text()
        if self.gui:
            #self.gui is a newgui reference. We don't want to call this directly
            #self.gui.update_object(self) #never do this because of threading issues
            devlog("gui","Updating gui for %s %s"%(self.text,self.pix))
            self.engine.update(self)
        else:
            #print "No gui to update"
            pass
        if self.parent and self.parent!=self:
            self.parent.update_gui()
        return 
    
    def set_engine(self,engine):
        self.engine=engine
        return
    
class hostKnowledge(lineList):
    """
    A list of knowledge primitives. Contained within a knowledgeContainer
    """
    def __init__(self,interface,parent):
        self.additional=False
        self.resolved_from=interface
        
        # XXX: route maps for every host interface
        #self.route = []
        #trace = self.engine.getModuleExploit('traceroute')
        #trace.link(self)
        #trace.target = interface
        #trace.run()
        
        #interface is the interface from the current node. 127.0.0.1 is, of course, the localhost
        devlog("hostKnowledge", "interface=%s"%interface)
        if interface==None:
            print "Interface is set to none, which should not happen!"
            import traceback
            traceback.print_exc(file=sys.stderr)
            sys.exit(1)
        
        lineList.__init__(self,parent)

        # XXX: ipv6 mod
        if ":" in interface:
            pass
        else:
            # XXX: end
            #not IPv6 - so doing IPv4 resolution
            try:
                interface2 = socket.gethostbyname(interface)
            except:
                interface2="127.0.0.2" #ERROR

            interface=interface2 #swap them
            
        self.interface=interface
        self.pix=""
        self._activated_text = " (current target)"
        self.pickledefaults["_activated_text"]=self._activated_text
        self._text = "Host: %s" % self.interface
        self.activate_text()

    def get_sort_value(self):
        return self.interface
    
    def get_pix(self):
        #print "get_pix called for host %s"%self.interface
        for c in self.children:
            #knowledge about the OS is used to set our icon
            known=str(c.known)
            #print "tag=%s"%c.tag
            #print "known is %s"%c.known
            
            if c.tag!="OS":
                continue
            #we don't differentiate versions yet
            if known.count("Windows"):
                return "Win32Host"
            elif known.count("Linux"):
                return "LinuxHost"
            elif known.count("Solaris"):
                return "SolarisHost"
            elif known.count("Embedded"):
                return "EmbeddedHost"

    def get_knowledge(self, tag, defaultret=None):
        """
        Get information from the hostKnowledge - we return an object, not a string
        O(N) operation here - could be fixed with a dictionary
        """
        for c in self.children:
            if c.tag == tag:
                return c
        return defaultret
    

    def forget(self, tag):
        """
        
        """
        
    def get_all_knowledge_as_text(self):
        """
        Every so often you'll want to get all the knowledge in easy
        to print out form, and this is how
        """
        ret=""
        for c in self.children:
            ret+=str(c)+"\n"
        return ret
            

    def get_menu(self):
        """
        Get menu strings for hostKnowledge - select as target, etc
        """
        menu=["Forget this host knowledge", "Save host to file","Add note to host"]
        #if we're not already a target, let's add these options to the front
        if not self.activated:
            menu=["Set as additional target host"]+menu
        menu=["Set as target host"]+menu
        if self.additional:
            menu+=["Unset as targeted host"]
        if self.get_knowledge("MOSDEFService",None):
            #we have a MOSDEFService installed on this box, so we should offer the user the ability
            #to connect to it
            menu+=["Connect to MOSDEF Service"]
        return menu

    def set_as_target(self,t=1):
        """
        Sets or unsets myself as a target and updates
        the engine and gui to know such a thing - doesn't 
        actually remove from the engine's self.target_hosts list
        """
        self.activated=t
        self.activate_text()
        self.update_gui()
        self.update_engine()        
        
    def unset_as_target(self):
        """
        Remove myself from the engine's target_hosts list
        and unset myself as an additional target or target
        """
        self.additional=False 
        if self.engine:
            self.engine.unset_target_host(self)
        self.set_as_target(0)
        return 
            
    def update_engine(self):
        if self.engine:
            if self.activated:
                if self.additional:
                    #additional target
                    self.engine.set_additional_target_host(self)
                else:
                    #primary target
                    self.engine.set_target_host(self)
         
                
            
    def save_to_file(self):
        """
        Uses pickle to save this object to a file
        
        We don't want to save self.parent though, since that will include a lot of
        information we don't need. We don't want to save self.gui or self.engine either.
        We don't need activated or amselected. These would in fact be bad to store.
        
        We do want self.children, which is all our knowledge (if we have any)
        """
        if self.parent:
            node=self.parent.parent #get our parent node for its name
            nodename=node.get_name()
        else:
            nodename="standalone"
        hostname=nodename+"_"+self.interface #construct a unique name
        #BUG: need to make this respect canvasengine.canvas_root_directory
        filename=os.path.join("Saved_Hosts",hostname)
        cPickle.dump(self,file(filename,"wb"))
        print "Saved host to file %s"%filename
        return 
    
    def menu_response(self, widget, astring):
        """
        Handles all the menu responses (sent to us a string such as "Save to File")
        """
        #print "Got %s"%astring
        if astring=="Set as target host":
            self.additional=False
            self.set_as_target()
        elif astring=="Set as additional target host":
            #don't set as additional host if we already are
            #either a primary or secondary host
            if not self.activated:
                self.additional=True 
                self.set_as_target()
        elif astring=="Unset as targeted host":
            #only do this is we are the secondary target since we 
            #always have at least ONE target selected
            if self.additional:
                self.unset_as_target()
        elif astring=="Forget this host knowledge":
            if self.interface=="127.0.0.1":
                self.engine.log("Don't try to delete the loopback interface, please")
            else:
                self.parent.delete(self)
        elif astring=="Save host to file":
            #print "Not yet supported, sorry"
            if 1:
                self.save_to_file()

        elif astring=="Add note to host":
            if self.gui:
                #self.gui is newgui.
                self.gui.engine.gui.gui_queue_append("add note to host", [self])
        elif astring=="Connect to MOSDEF Service":
            self.gui.engine.gui.gui_queue_append("load host from file", [self])
        else:
            print "Unknown string in menu_response: %s"%astring

    def forget(self, tag):
        """
        Forgets a tag, if we have it
        returns True if we've found it, false if it was not here 
        """
        for c in self.children:
            if c.tag == tag:
                self.delete(c)
                return True 
        return False 
        
    def replace_knowledge(self,tag,knowledge,percentage,invisible=0):
        "if knowledge is already known replaces it, otherwise, adds it"
        #print "Replace_knowledge %s:%s"%(tag,knowledge)
        for c in self.children:
            if c.tag == tag:
                if not c.invisible:
                    #print "Delete line %s:%s"%(tag,c.known)
                    if self.engine:
                        self.engine.deleteLine(c)
                c.known=knowledge
                c.percentage=percentage
                c.invisible=invisible
                #print "About to add line. Invisible=%d"%invisible
                if not invisible:
                    if self.engine:
                        self.engine.addLine(c)
                c.update_gui()
                return c
        #print "Defaulting to add_knowledge"
        #otherwise, default to add_knowledge
        return self.add_knowledge(tag,knowledge,percentage,invisible=invisible)
    
    def add_knowledge(self, tag, knowledge, percentage, invisible=0):
        "adds knowledge but does not replace it"
        devlog('hostKnowledge::add_knowledge', "%s %s %s"%(tag,knowledge,invisible))
        for c in self.children:
            if tag == c.tag:
                #we already know something about this - we need to adjust it,
                #but for now we'll replace it
                devlog('hostKnowledge::add_knowledge',"replacing %s knowledge in gui"%tag)                
                return self.replace_knowledge(tag,knowledge,percentage,invisible)

            
        thing=knowledgePrimitive(self, tag, knowledge,percentage)
        thing.invisible=invisible
        self.add(thing)
        if self.engine and not invisible:
            devlog('hostKnowledge::add_knowledge',"adding %s knowledge to gui"%tag)
            self.engine.addLine(thing)
        else:
            devlog('hostKnowledge::add_knowledge',"Not adding %s knowledge to gui. Self.engine: %s"%(tag,self.engine))
        thing.update_gui()
        self.update_gui()
        return thing
    
    def add_to_knowledge(self, tag, newknowledge):
        "adds a fact to a knowledge line (such as a port)"
        #print "add_to_knowledge(%s,%s)"%(tag,newknowledge)
        knowledge=self.get_knowledge(tag)
        if knowledge==None:
            #add it anew
            #print "add knowledge about to be called"
            self.add_knowledge(tag,newknowledge,100)
            return
        #print "knowledge.known=%s"%knowledge.known
        knowledge.known+=newknowledge
        knowledge.known=uniquelist(knowledge.known)
        #print "Replace knowledge about to be called"
        self.replace_knowledge(tag,knowledge.known,100)
        
        return
        
    def open_tcpport(self,port):
        "Returns 1 if the port is open on this host, else, zero"
        #quick TCP function
        ports=self.get_knowledge("TCPPORTS",[])
        #I have no idea why ports would not be a list
        #but if it's not, we don't want to error out
        if not ports or type(ports) != type([]):
            return 0
        
        if port in ports:
            return 1
        return 0
    
    def add_note(self,note):
        self.replace_knowledge("Note",note,100)
        
    def get_note(self):
        ret=self.get_knowledge("Note","")
        if ret:
            ret=ret.known
        return ret
        
class knowledgeContainer(lineList):
    """
    A list of hosts we know about, typically my parent is a Node, my children are hostKnowledge objects
    """
    def __init__(self,parent):
        lineList.__init__(self,parent)
        self._text="Knowledge"
        
    def get_menu(self):
        return ["Add new host", "Forget all knowledge", "Load host from file", "Load all hosts"]

    def load_all_hosts(self,prefix=""):
        dirname="Saved_Hosts"
        try:
            hostlist=os.listdir(dirname)
        except:
            print "Could not find %s so creating it"%dirname
            os.mkdir(dirname)
            hostlist=[]
            
        #cull out the files that are not hosts
        for f in ["CVS","README.txt"]:
            if f in hostlist:
                hostlist.remove(f)

        for f in hostlist:
            #skip all hosts that don't start with 0_ for localNode
            if prefix and f[:len(prefix)]!=prefix:
                #print "did not match prefix: Prefix=*%s* f[:len(prefix)]=*%s*"%(prefix,f[:len(prefix)])
                continue
                
            newhost=cPickle.load(file(os.path.join(dirname,f)))
            print "newhost's children: %s"%newhost.children
            #set up all the children to have the correct parent again
            newhost.set_all_parents(self.parent.hostsknowledge)
            self.parent.add_hostKnowledge(newhost)
        return
        
    def menu_response(self, widget, astring):
        #print "Got %s"%astring
        if astring=="Add new host":
            if self.gui:
                #self.gui is newgui.
                self.gui.engine.gui.gui_queue_append("add host", [self])
        if astring=="Load host from file":
            #pop up a dialog box and select the file (from the gui)
            self.gui.engine.gui.gui_queue_append("load host from file", [self])            
        if astring=="Load all hosts":
            self.load_all_hosts()
            
    def get_all_known_hosts(self):
        """
        returns a list of all the hosts I know about
        This is used by the engine to maintain uniqueness
        of the hosts in the container
        """
        ret=[]
        for c in self.children:
            ret.append(c.interface)
            
        return ret
    
    def forget(self, tag):
        """
        Forgets information from  a tag in our localhost 
        """
        localhost = self.get_localhost()
        localhost.forget(tag)
        return 
        
    def get_first_known_host(self):
        if len(self.children)==0:
            return None
        return self.children[0]
    
    def get_localhost(self):
        """
        Returns the local host in this container - essentially 127.0.0.1
        """
        #should always exist 
        return self.get_known_host("127.0.0.1")
        
    def get_known_host(self, ip):
        """
        Returns a hostKnowledge or None if none found that matched that ip 
        """
        for c in self.children:
            if c.interface==ip:
                return c
        return None 



class knowledgePrimitive(lineList):
    """
    Each host has many of these
    """
    def __init__(self,parent, tag, known,percentage):
        lineList.__init__(self,parent)
        self.tag = tag
        self.known=known
        self.percentage=percentage
        self.invisible=0
        known_text=str_from_object(self.known)
        devlog("hostKnowledge", "Known Text: %s"%known_text)
        self._text="Known: %s: %s <%s%%>"%(self.tag, known_text ,self.percentage)
        self.all_text="" #used only when we call self.get_all_text()
        self.known_text=known_text #just the portion of text we use for the known value

    def __str__(self):
        return self.text
    
    def old__getstate__(self):
        """used for pickling"""
        state=(lineList.__getstate__(self),self.tag,self.known,self.percentage,self.invisible,self.text)
        return state
    

    def get_known_text(self):
        """
        Returns only the text for the known string - not the percentage of certainty.
        Has to handle the case when our known is a list or a string, essentially
        """
        known=str_from_object(self.known)
        devlog("hostKnowledge","get_known_text returning: %s"%known)
        self.known_text=known
        return known
    
    def get_text(self):
        """
        Gets the text representation of this known value, including the percentage
        of certainty, and then formats it for the screen. Also assigns some internal
        variables for use by people hooking this object.
        
        If all you want to use is the known text for parsing or whatever, we also have
        get_known_text() available, which will just return the known text.
        
        Also see "get_all_text()" which does not restrict the length of the known text to
        50 characters (and self.all_text).
        """
        known=self.get_known_text()
        #self.text is truncated to fit into a screen nicely. 
        self.text="Known: %s: %s <%s%%>"%(self.tag, str(known)[:50],self.percentage)
        #self.all_text is used by some people who want to parse text instead of access the self.known object directly.
        self.all_text="Known: %s: %s <%s%%>"%(self.tag, str(known),self.percentage)
        return self.text
    
    def get_all_text(self):
        """
        Calls self.get_text() to set internal variables, then returns self.all_text - a longish
        representation of what we know.
        """
        self.get_text()
        return self.all_text
    
    def get_menu(self):
        return ["Forget this knowledge", "Print knowledge"]
       
    def menu_response(self, widget, astring):
        #print "Got %s"%astring
        if astring=="Forget this knowledge":
            #done in self.parent.delete() - should be thread safe 
            #self.gui.engine.gui.gui_queue_append("deleteLine",[self])
            self.parent.delete(self)
        elif astring=="Print knowledge":
            self.engine.log("Knowledge: %s"%self.get_all_text())
        return 
        
class interfaceLine(lineList):
    def __init__(self, ifc, nat, startport, endport, parent):
        lineList.__init__(self,parent)
        #print "ifc=%s"%ifc
        self.interface=ifc[0]
        self.ip=ifc[1]
        self.netmask=ifc[2]
        #self.text="%s  %s (netmask: %x)"%(self.interface,self.ip,uint32(self.netmask))
        # IPv6 support
        if ":" in self.ip:
            self._text="%s  %s (%s)" % (self.interface, self.ip, self.netmask)
        else:
            self._text="%s  %s (%s)" % (self.interface, self.ip, int32toIpstr(self.netmask))
        self.activate_text()
        self.isNAT=nat
        #for NAT's these can be a smaller range of portforwarded ports
        self.startport=startport
        self.endport=endport
        self._activated_text = " (current callback)"
        self.pickledefaults["_activated_text"]=self._activated_text
 
    def __str__(self):
        """
        Return the IP - possibly would be better to return a "%s %s %s"%(self.ip,self.netmask,self.isNAT) or something...
        """
        return str(self.ip)

    def isSpecial(self):
        """
        Return true if we are a special kind of interface (NAT, for example)
        The other kind of special interface is one that's not local to a LocalNode.
        
        If this returns True, the engine will not choose a different interface
        when doing auto-interface selection.
        See canvasengine::autoListener()
        """
        if self.isNAT:
            return True
        if self.parent.parent.nodetype!="LocalNode":
            return True
        return False
    
    def get_menu(self):
        return ["Set as callback interface"]

    def set_as_callback(self,t=1):
        self.activated=t
        self.activate_text()
        self.update_gui()
        self.update_engine()        
        
    def unset_as_callback(self):
        self.set_as_callback(0)
            
    def update_engine(self):
        if self.engine:
            self.engine.set_callback_interface(self)
                
    def menu_response(self, widget, astring):
        #print "Got %s"%astring
        if astring=="Set as callback interface":
            self.set_as_callback()
            
    def getListenerBySock(self,sock):
        #print "in getListenerBySock for listener %s"%self.text
        #print "Number of listeners: %s"%len(self.children)
        for c in self.children:
            #print "Comparing %s to %s"%(sock,c.sock)
            if sock==c.sock:
                return c
        return None
            
class interfacesList(lineList):
    """
    Parent is usually a CANVASNode
    """
    def __init__(self,parent):
        lineList.__init__(self,parent)
        self._text="Interfaces"
        self.activate_text()
        
    def all_ips(self):
        """
        Returns a list of the ip addresses
        """
        ips=[]
        for interfs in self.children:
            ips+=[interfs.ip]
        return ips
    
    def all_interfaces(self):
        """
        Returns a list of the ip interfaces
        """
        ips=[]
        for interfs in self.children:
            ips+=[interfs.interface]
        return ips
 
    def all_interface_objects(self):
        return self.children
    
    def get_ip(self,ip):
        """
        If we can find an interface in our list that matches
        that IP, return it, otherwise return None
        """
        devlog("hostKnowledge", 'interfacesList::get_ip', "ip = %s" % ip)
        for interfs in self.children:
            devlog("hostKnowledge", 'interfacesList::get_ip', "intefs=%s %s"%(interfs.interface,interfs.ip))
            if ip==interfs.ip:
                devlog("engine", 'interfacesList::get_ip', "Found...%s"%ip)
                return interfs
        return None
    
    def get_interface(self, iface):
        for child in self.children:
            if iface == child.interface:
                return child
        return None
    
    def get_interesting(self):
        """
        Will return the first interesting interface it finds (as a string)
        This is used by the CANVAS Nodes to make their display more 
        useful to the user
        """
        ret=""
        for child in self.children:
            if child.ip!="127.0.0.1":
                return child.ip
        return "" #nothing found?
        
    def add_ip(self,ifc,nat=0,startport=1,endport=65535):
        """
        An ifc (interface, ip, netmask) is given to me, I make it an object and then add it to my children
        and update the model
        """
        interface=interfaceLine(ifc,nat,startport,endport,self)
        
        # We shouldnt be adding interfaces that already exist in the host knowledge
        for x in self.children:
            if x == interface:
                devlog("hostKnowledge", "Found interface: %s NOT adding again!"%(interface))
                return
            
        self.add(interface)
        if self.engine:
            self.engine.addLine(interface)
        return
    
    def add_listener(self,lst):
        listener=listenerLine(lst,self)
        self.add(listener)
        
    def get_last(self, addrType=None):
        """Pass in an addrType to get the last ipv4 or ipv6 interface, otherwise you get the last interface, whatever it is"""
        #strange error condition
        if self.children==[]:
            return None
        
        if addrType == None:
            return self.children[-1]
        else:
            if addrType not in ["ipv4", "ipv6"]:
                raise CANVASError("Valid addrType values are 'ipv4' or 'ipv6'")
            
            for i in reversed(self.children):
                if addrType == "ipv4":
                    if "." in i.ip:
                        return i
                elif addrType == "ipv6":
                    if ":" in i.ip:
                        return i
        
    def get_menu(self):
        return ["Add interface"]

    def menu_response(self, widget, astring):
        #print "Got %s"%astring
        if astring=="Add interface":
            if self.gui:
                #self.gui is newgui.
                self.gui.engine.gui.gui_queue_append("add interface", [self])
                
class nodesList(lineList):
    def __init__(self,parent):
        lineList.__init__(self,parent)
        self._text="Connected Nodes"
        self.activate_text()

def main():
    myhostKnowledge=hostKnowledge("12.34.56.79",None)
    myhostKnowledge.save_to_file()
    
if __name__=="__main__":
    main()