#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
guiload.py

We call gtk.main here to throw up a tiny window with a progress bar. 
Then we call gtk.quit
And then the main program starts up its own GTK loop.

TODO: Make work. You can't DO this on win32. You need to call
gtk.main() in the main thread to make anything happen.

"""
import sys
if "." not in sys.path: sys.path.append(".")

import gtk
from exploitutils import writeflush
import time
from threading import Thread
from internal import devlog
import gui_queue
import gobject

# gtk.input_add is now deprecated
try:
    gtk_input_add_hook = gobject.io_add_watch
except:
    gtk_input_add_hook = gtk.input_add

class RegisterModulesGTK:

    def __init__(self):
        
        self.modnum = 0
        self.curidx = 0
        self.started = False

        self.gui_queue=gui_queue.gui_queue(self)
        gtk_input_add_hook(self.gui_queue.get_event_socket(), gtk.gdk.INPUT_READ, self.clearqueue)
        #self.init_gtk()
        
        self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)
        self.window.set_icon_from_file("gui/pixmaps/immunity.ico")
        #self.window.set_usize(200, 100)
        self.window.set_title("Loading CANVAS")
        self.window.connect("delete_event", self.destroy)
        self.window.connect("destroy", self.destroy)
        #self.window.connect("show", self.start)
        #self.window.connect("event", self.start)
        #self.window.connect("expose-event", self.start)
        self.window.set_position(gtk.WIN_POS_CENTER_ALWAYS)

        vbox = gtk.VBox(False, 1)
        self.window.add(vbox)
        vbox.show()

        img = gtk.Image()
        img.set_from_file("gui/pixmaps/canvas.gif")
        vbox.pack_start(img, True, True, 0)
        img.show()

        self.pbar = gtk.ProgressBar()
        vbox.pack_start(self.pbar, True, True, 0)
        self.pbar.show()

        self.sbar = gtk.Statusbar()
        #self.sbar.set_flags(gtk.MAPPED|gtk.VISIBLE|gtk.APP_PAINTABLE)
        vbox.pack_start(self.sbar, True, True, 0)
        self.sbar.show()
        self.ctxid = self.sbar.get_context_id("module loaded")
        self.sbar.push(self.ctxid, "Initializing") #have to push because we pop first
        self.window.show()

    def clearqueue(self,source,condition):
        """Our callback for gui events"""
        self.gui_queue.clearqueue()

        #print "End of clearqueue"
        return 1
    
    def handle_gui_queue(self,command, args):
        """
        Callback the gui_queue uses whenever it recieves a command for us.
        command is a string
        args is a list of arguments for the command
        """
        gtk.threads_enter()
        #threadcheckMain("handle_gui_queue")
        devlog('guiload', "command=<%s> args=%s" % (command, args))
        if command=="log":
            #print "setting label"
            name=args[0]
            self.do_log(name)
        elif command=="done":
            self.close()
        else:
            print "Unrecognized command %s"%command
        #devlog("guiload","leaving")
        gtk.threads_leave()
        return

    def init_gtk(self):
        try:
            gtk.threads_init()
        except:
            print "No threading was enabled when you compiled pyGTK!"
            sys.exit(1)
        
    def quit_gtk(self):
        gtk.main_quit()
        
    def run(self):
        self.init_gtk()
        gtk.threads_enter()
        print "Gtk main calling..."
        gtk.main()
        gtk.threads_leave()

    def setcuridx(self,num):
        self.curidx=num
        
    def setmax(self, maxnum):
        self.modnum = maxnum

    def log(self,name):
        self.gui_queue.append("log",[name])
        
    def do_log(self, name):
        astr="Loading %s ...%s" % (name, ' ' * (80 - 19 - 2 - len(name)))
        #print astr
        #writeflush(astr)
        #gtk.threads_enter()
        self.sbar.pop(self.ctxid)
        self.sbar.push(self.ctxid, name)
        self.setstatus(name)
        self.window.show()
        #gtk.threads_leave()
        #time.sleep(0.4)
        
    def setstatus(self, name, succeeded = True):
        self.curidx += 1
        #devlog( "Name: %s Curidx=%s"%(name,self.curidx))
        r = float(float(self.curidx) / float(self.modnum))
        self.pbar.set_fraction(r)
        out = {True: " ok ", False: "fail"}
        #writeflush("[" + out[succeeded] + "]\n")
        #devlog("curidx = %d modnum = %d"%(self.curidx,self.modnum))
        if self.curidx == self.modnum:
            self.sbar.push(self.ctxid, "Done.")
            self.close()
            
    def succeeded(self, name):
        self.setstatus(name)

    def failed(self, name):
        self.setstatus(name, False)
        
    def close(self):
        self.window.destroy()
        
    def destroy(self, widget,*args):
        devlog("Called destroy")
        self.quit_gtk()
        pass
        
def main():
    """
    Used for testing our logger GUI
    """
    logger=RegisterModulesGTK()
    logger.init_gtk()
    logger.setmax(10)
    logger.run()
    #logger.start() #new thread
    for i in range(0,10):
        print "I=%d"%i
        logger.log("Hello %d"%i)
        time.sleep(1)
        
if __name__=="__main__":
    main()