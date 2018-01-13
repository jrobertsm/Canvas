#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

canvas_coders = "Bas Alberts, Dave Aitel, Sinan Eren, Kostya Kortchinsky and Nicolas Waisman"
canvas_gui_style = "default"

import sys, os, string, re, time
from internal import *

import canvasengine
from exploitutils import bugtracker, iso8859toascii, threadcheckMain, threadchecknonMain, writeflush, utf16toascii, prettyprint
from exploitutils import expiredate, contactemail

add_python_paths()
from threading import Thread

import newgui #this is the standard gui...it's newer than the one we never use.:>

#little binary function
def b(mystr):
    mydict={"1":1,"0":0}
    tmp=0
    for c in mystr:
        value=mydict[c]
        tmp=(tmp<<1)+value
    return tmp

def get_glade_file():
    __glade_file = "canvasgui2_%s.glade" % canvas_gui_style
    moddir = os.path.dirname(sys.modules[__name__].__file__)
    if moddir != "":
        __glade_file = moddir + os.path.sep + __glade_file
    return __glade_file
#This program requires a recent GTK 2
#make sure the python in your current path can use GTK 2.X - check to make sure
#/usr/bin/python and /usr/local/bin/python are the same if you have problems
#on one account (such as root) and not on others.

def try_import():
    """tries to import gtk and if successful, returns 0"""
    import sys
    from internal import pathlist
    sys.path = pathlist(sys.path)
    writeflush("Loading gtk ...%s" % (' ' * (80 - 22)))
    # To require 1.2
    try:
        import pygtk
    except:
        writeflush("[fail]\n")
        print "pyGTK not found. You need GTK 2 to run this."
        if not os.getenv('PYTHONPATH'):
            print "Did you \"export PYTHONPATH=/usr/local/lib/python2.2/site-packages/\" first?"
        print "Perhaps you have GTK2 but not pyGTK, so I will continue to try loading."
        return 1

    if sys.modules.has_key('gtk'):
        devlog('all', "weird, gtk module already imported... wherefrom?")
        #del gtk
    pygtk.require("2.0") # raise AssertionError if not found

    try:
        import gtk
    except RuntimeError, errinst:
        writeflush("[fail]\n")
        if errinst.args[0] == 'could not open display':
            print "Can not open display, check your $DISPLAY environment variable"
            sys.exit(0)
        return 1
    except KeyboardInterrupt:
        writeflush("[fail]\n")
        return 2
    except:
        writeflush("[fail]\n")
        import traceback,sys
        traceback.print_exc(file=sys.stdout)
        print "Path = %s" % sys.path
        print "I'm sorry, you apparantly do not have GTK2 installed - I tried"
        print "to import gtk, gtk.glade, and gobject, and I failed."
        print "Please contact Immunity CANVAS Support and let them know what version you have"
        return 1

    try:
        import gtk.glade
        import atk,pango #for py2exe
        import gobject
    except:
        writeflush("[fail]\n")
        import traceback,sys
        traceback.print_exc(file=sys.stdout)
        print "Path = %s" % sys.path
        print "I'm sorry, you apparantly do not have GTK2 installed - I tried"
        print "to import gtk, gtk.glade, and gobject, and I failed."
        print "Please contact Immunity CANVAS Support and let them know what version you have"
        return 1
    writeflush("[ ok ]\n")
    return 0

__gtk_imported = 0


def loadgtk():
    global __gtk_imported
    if __gtk_imported:
        return
    __gtk_imported = 1

    if try_import():
        site_packages=0
        retry_import = 1
        #for k in sys.path:
        #    if k.count("site-packages"):
        #        print "existing site-packages path %s found\n"%k
        #        site_packages=1
        if site_packages == 0:
            print "no site-packages path set, checking.\n"
            check_lib = ["/usr/sfw/lib/python2.4/site-packages/"]
            if debug_enabled:
                check_lib += [
                    "/usr/local/lib/python2.3/site-packages/",
                    "/usr/sfw/lib/python2.3/site-packages/",
                    "/usr/sfw/lib/python2.4/site-packages/"
                ]
            for k in check_lib:
                try:
                    path=os.path.join(k,"pygtk.py")
                    #print "Path=%s"%path
                    if open(path)!=None:
                        print "appending", k
                        sys.path=[k]+sys.path
                        if try_import() != 1:
                            retry_import = 0
                            break
                except:
                    pass
        if retry_import and try_import():
            print "Couldn't load pyGTK - exiting!"
            sys.exit(0)

# imported in try_import() but lack in global namespace...
import gtk,gtk.glade
gtk_glade_hook = gtk.glade
import atk,pango #for py2exe
import gobject
__gtk_imported = 1

import gui_queue

#(canvasguigtk2.py:14604): libglade-WARNING **: unknown property `focus_on_map' for class `GtkWindow'
#import warnings
#warnings.filterwarnings('once', "unknown property .* for class .*", Warning)

# gtk.input_add is now deprecated
try:
    gtk_input_add_hook = gobject.io_add_watch
except:
    gtk_input_add_hook = gtk.input_add

# this goal of this class is to define gtk.TreeStore function
# that were added in pygtk 2.2
class gtk_TreeStore_hook(gtk.TreeStore):
    def __init__(self, *args):
        self._gtk22comp = True
        self.move_after_orig = None

        # KLUDGE for move_after()
        # this has to be used ONLY in special case
        # when you know why you use it
        # WARNING
        # using it make code undebugable, and give headaches
        self.broken_move_after = False

        # where we come from
        gtk.TreeStore.__init__(self, *args)

        # check for unexisting functions
        self.version_capabilities_check()

    # here we try to resolv function that can be not existing in old pygtk
    # if we get an exception, we bind it to a hook
    def version_capabilities_check(self):
        pygtk22_newfunc = [
            'move_before',
            #'move_after', KLUDGEd
            'swap',
        ]
        for func in pygtk22_newfunc:
            if not hasattr(self, func):
                print "hooking gtk.TreeStore.%s" % func
                setattr(self, func, getattr(self, "%s_hook" % func))
                self._gtk22comp = False

        # KLUDGE for move_after()
        if hasattr(self, 'move_after'):
            self.move_after_orig = self.move_after
        self.move_after = self.move_after_hook

    def sortable(self):
        return self._gtk22comp

    # move_after: special case, maybe broken implementation
    def move_after_hook(self, iter, position):
        if self.broken_move_after or not self.move_after_orig:
            return
        return self.move_after_orig(iter, position)

    # move_before: actually does nothing
    def move_before_hook(self, iter, position):
        return

    # swap: actually does nothing
    def swap_hook(self, iter, position):
        return

def reorder_model(model):

    # sorry, too broken on Darwin for now.
    if sys.platform == "darwin":
        return

    model._kludge_security_count = 0
    def reorder_node(model, path, iter, data):
        assert type(iter) == gtk.TreeIter, "gtk.TreeIter expected for iter, we got %s" % type(iter)
        # <KLUDGE KLUDGE KLUDGE KLUDGE KLUDGE KLUDGE>
        # remove that only if you REALLY understand why, you are warned.
        if model._kludge_security_count > 2000:
            print "\n\n\n\nGTK::reorder_model probably entered in infinite loop... aborting.\n\n\n\n"
            sys.exit(109) # $GTK_INFINITE_LOOP_ERROR in osxruncanvas.sh
        model._kludge_security_count += 1
        # </KLUDGE KLUDGE KLUDGE KLUDGE KLUDGE KLUDGE>

        # we want to reorder "All" leaf to top of branch
        if model.iter_has_child(iter) and model.get_value(iter, 0) == "All":
            # we only reorder if we are not 1st node
            # with gtk.TreeIter: len(get_path(get_iter_root())) == 1, then len(...) > 1, so [-1] is valid
            if model.get_path(iter)[-1]:
                try:
                    model.move_after(iter, None)
                except TypeError:
                    # dangerous KLUDGE
                    model.broken_move_after = True
                    # to be reported by customer:
                    print "TypeError exception calling move_after(%s, None)" % type(iter)
                    print "iter is: %s" % iter

    ts = time.time()
    model.foreach(reorder_node, None)
    devlog('gtk::reorder_model', "reorder time: %ss" % (time.time() - ts))

def insert_row(model,parent,firstcolumn,secondcolumn, thirdcolumn=None, top=0, allow_dup=False):
    """
    new func, insert at bottom by default
    (previous at top by default)
    set top= to insert at top
    """

    # avoid duplicated entries (maybe that code has to be in addIter() )
    if not allow_dup:
        child = model.iter_children(parent)
        while child:
            name = model.get_value(child, 0)
            desc = model.get_value(child, 1)
            if firstcolumn == name and secondcolumn == desc:
                devlog('insert_row', "trying to insert an already existing row: %s (%s)" % (name, desc))
                return child
            child = model.iter_next(child)


    # insert row in list
    if top:
        myiter=model.insert_after(parent,None)
    else:
        myiter=model.insert_before(parent,None)

    # set column value
    model.set_value(myiter,0,firstcolumn)
    model.set_value(myiter,1,secondcolumn)
    if thirdcolumn != None:
        model.set_value(myiter,2,thirdcolumn)

    return myiter

"""
# vu!!! use uniqlist instead...
def uniquelist(alist):
    outlist=[]
    outdict={}
    for a in alist:
        outdict[a]="bob"
    outlist=outdict.keys()
    return outlist
"""

def backwardcompatibility(name):
    # BACKWARD COMPATIBILITY (YACK!)
    backward = {'userentry': "user", 'entry1': "host", 'callbackport_spinbutton': "callbackport",
                'spinbutton1': "port", 'passwordentry': "password", 'commandentry': "command",
                'domainentry': "domain", 'filenameentry': "filename", 'sourceentry': "source",
                'directoryentry': "directory", 'sslcheckbutton': "ssl"}
    if backward.has_key(name):
        return backward[name]
    return name

def runAnExploit_gtk2(widget,wTree2,engine,module):
    """
    Gathers the required information to run the exploit from the dialog box
    and runs it
    Specific to the GTK2 GUI
    """
    #print "runAnExploitGTK2()"
    engine.log("Running %s Exploit Version %s"%(module.DESCRIPTION,module.VERSION))
    argsDict={}
    argsDict["version"]=0
    argsDict["method"]=0

    wlist=wTree2.get_widget_prefix("")

    #need to clear this off - otherwise radiobuttons don't get processed correctly
    for a in wlist:
        if hasattr(a,'_RBprocessed'):
            del a._RBprocessed

    for a in wlist:
        #for each widget
        name = a.name
        gtk_type = type(a)
        devlog('argsDict::setup', "name: %s is %s" % (name, gtk_type))

        if gtk_type in [gtk.Table, gtk.Label, gtk.Dialog, gtk.VBox, gtk.HBox, gtk.HSeparator, gtk.Button, gtk.HButtonBox]:
            continue

        elif gtk_type == gtk.SpinButton:
            argsDict[backwardcompatibility(name)] = float(a.get_value())

        elif gtk_type == gtk.CheckButton:
            argsDict[backwardcompatibility(name)]  = a.get_active()

        elif gtk_type == gtk.RadioButton and not hasattr(a, '_RBprocessed'):
            # yo, that code was probably one of the ugliest i have seen
            # i tried to clean it, but i dunno how many exploits expect it working like it was designed.
            # comment was "in doubt it let it as it..."
            # so take care, this part is tagged KLUDGE KLUDGE KLUDGE KLUDGE
            for radiobutton in a.get_group():
                import string
                if radiobutton.get_active():
                    argsDict[name + '_value'] = radiobutton.get_label()
                _name = radiobutton.get_name()
                for b in range(len(_name)-1, 0, -1):
                    if _name[b] in string.digits:
                        continue
                    num = _name[b+1:]
                    devlog("argsDict::setup","Radiobutton check number: %s"%num)
                    if num:
                        if name.find("radiobutton") > -1:
                            if radiobutton.get_active():
                                devlog("argsDict::setup","Radiobutton setting version to: %s"%(int(num)-1))
                                argsDict["version"] = int(num)-1
                        else:
                            if radiobutton.get_active():
                                argsDict[_name[:b+1]] = int(num)
                    else:
                        if not argsDict.has_key(_name):
                            argsDict[_name] = _name
                    break
            a._RBprocessed = True
            # end of KLUDGE part

        elif gtk_type == gtk.Entry:
            argsDict[backwardcompatibility(name)] = a.get_text()
        elif gtk_type == gtk.TextView:
            buffer=a.get_buffer() #get GTK.TextBuffer 
            argsDict[backwardcompatibility(name)] = buffer.get_text(buffer.get_start_iter(),buffer.get_end_iter())

        elif gtk_type == gtk.ToggleButton:
            argsDict[backwardcompatibility(name)]  = a.get_active()

        elif gtk_type == gtk.ComboBoxEntry:
            try:
                entry = a.get_child()
                text = entry.get_text()
                argsDict[name]=text
                devlog("gui", "Combobox: %s %s"%(name,text))
            except:
                # FIXME pyGTK 2.6?
                devlog("gui", "can not set argsDict[%s] for gtk.ComboBoxEntry" % name)
                pass

        elif gtk_type == gtk.ComboBox:
            try:
                #pyGTK 2.6, I believe.
                if hasattr(a, 'get_active_text'):
                    # gtk.ComboBox.get_active_text
                    # NOTE: This method is available in PyGTK 2.6 and above
                    # NOTE: that you can only use this function with combo
                    # boxes constructed with the gtk.combo_box_new_text() function.
                    text = a.get_active_text()
                else:
                    text = a.get_model().get_value(a.get_active_iter(),0)
                argsDict[name]=text
            except:
                pass # Python 2.4?

        else:
            if not argsDict.has_key(name): # KLUDGE
                devlog('argsDict::errors', "can not set argsDict[%s] for %s" % (name, gtk_type))

    devlog('runAnExploit_gtk2', "running module=%s engine=%s argsDict=%s" % (module, engine, argsDict))
    newthread=canvasengine.runExploitClass(engine, module, argsDict)
    ret=bugtracker(newthread.start)

    #print "Ending runAnExploit()"
    return ret


class HandlersReloadHack:
    def __init__(self):
        self.handlers = {}
        self.handlersExt = {}
    def __setitem__(self, tkey, val):
        if type(tkey) == type(()):
            self.handlersExt[tkey[0]] = val
        else:
            self.handlers[tkey] = val
    def __getitem__(self, key):
        if self.handlersExt.has_key(key):
            return self.handlersExt[key].mod
        else:
            return self.handlers[key]
    def __delitem__(self, key):
        if self.handlersExt.has_key(key):
            del self.handlersExt[key]
        if self.handlers.has_key(key):
            del self.handlers[key]
    def has_key(self, key):
        return self.handlersExt.has_key(key) or self.handlers.has_key(key)


from gui.text_with_markup import insert_text_with_markup
from gui.file_browser import browser_window

from defaultgui import defaultgui

class canvasgui(defaultgui):
    # Sniffer Window Icons
    show = [
        "11 17 3 1",
        "  c None",
        ". c #11a44f",
        "1 c #000000",
        "         1 ",	    
        "        11 ",
        "       111 ",
        "      1111 ",
        "     11111 ",
        "    111111 ",
        "   1111111 ",
        "  11111111 ",	    
        " 111111111 ",
        "  11111111 ",
        "   1111111 ",
        "    111111 ",            
        "     11111 ",
        "      1111 ",
        "       111 ",
        "        11 ",
        "         1 "
    ]
    hide= [
        "11 17 3 1",
        "  c None",
        ". c #11a44f",
        "1 c #000000",
        " 1         ",
        " 11        ",
        " 111       ",
        " 1111      ",
        " 11111     ",
        " 111111    ",
        " 1111111   ",
        " 11111111  ",
        " 111111111 ",
        " 11111111  ",
        " 1111111   ",
        " 111111    ",
        " 11111     ",
        " 1111      ",	    
        " 111       ",
        " 11        ",
        " 1         "
    ]

    def __init__(self):
        defaultgui.__init__(self)
        self.notnewgui=0
        self.init_app()
        #self.iters = {}
        ##Rich mod
        self.search_dict=None
        return

    def init_app (self):
        "Initialise the application."

        # related to the New Exploit NodeTree
        self.newExpTitle = "New Exploits"
        self.newExpDesc = "New Monthly CANVAS Modules"
        self.newfilemods = os.path.join(canvasengine.canvas_resources_directory, "newmodules.txt")
        
        self.newmods = self.ReadNewModsFile(self.newfilemods)

        self.set_module_name = ""
        
        ##Rich mod - Favorite exploits tab
        self.favExpTitle = "Favorite Exploits"
        self.favExpDesc = "User Defined Favorite CANVAS Modules"
        self.favfilemods = os.path.join(canvasengine.canvas_resources_directory,"favmodules.txt")
        
        self.favmods = self.ReadNewModsFile(self.favfilemods)
        
        
        self.nodegui=None
        self.image_filename="" #none for default screenshot display
        devlog("gui","canvasengine=%s"%canvasengine)
        if canvasengine.CanvasConfig['sound']:
            canvasengine.sound.configsound()
        self.gui_queue=gui_queue.gui_queue(self) #our new gui queue
        gtk_input_add_hook(self.gui_queue.get_event_socket(), gtk.gdk.INPUT_READ, self.clearqueue)
        self.logwindow=None
        self.mycanvasengine=None
        #window1 must be the main app window!!!
        self.wTree = gtk_glade_hook.XML(get_glade_file(), "window1")
        # XXX on OSX:
        # Warning: Two different plugins tried to register 'BasicEngineFc'.
        # Warning: g_object_new: assertion `G_TYPE_IS_OBJECT (object_type)' failed
        # Failed to load Pango module for id: 'BasicScriptEngineFc'
        self.wTree2 = gtk_glade_hook.XML(get_glade_file(), "window2")
        dic = {"on_quit_button_clicked"        : self.quit,
               "on_exit1_activate"             : self.quit,
               "on_exit_canvas_gui1_activate" : self.quit,
               "on_reload_modules_activate" : self.reload_modules,
               "on_window1_destroy" : (self.quit),
               "on_module_treeview_button_press_event": self.moduletree_press,
               #"on_hosts_treeview_button_press_event": self.selectHost,
               "on_callback_entry_changed": self.callback_entry_changed,
               "on_target_entry_changed" : self.target_entry_changed,
               "on_kill_listener1_activate": self.kill_listener,
               "on_killall_listeners1_activate": self.killall_listeners,
               "on_halt_current_exploit1_activate" : self.halt_bruteforce,
               "on_start_new_listener1_activate": self.new_listener_dialogue,
               "on_save_entire_canvas_desktop1_activate": self.save_desktop,
               "on_adjust_network_dump_colorization1_activate": self.adjust_dump_colorization,
               "on_save_this_log1_activate": self.save_log,
               "on_stop_network_dump1_activate": self.stop_dump,
               "on_filter_network_dump1_activate": self.filter_dump,
               "on_start_network_dump1_activate": self.start_dump,
               "on_add_host1_activate":self.add_host,
               "on_covertbar_value_changed":self.covertbar_changed,
               "on_listener_treeview_button_press_event": self.listener_press,
               "on_button55_pressed": self.hide_dump,
               "on_Bmyscreenshot_released": self.open_screenshot,
               "on_connect1_activate": self.cws_connect,
               "on_set_os_detection_options": self.set_os_detection_options,
               #targeting buttons
               "target_button_clicked_cb": self.target_button,
               "add_target_button_clicked_cb": self.add_target_button,
               "remove_target_button_clicked_cb": self.remove_target_button,

               "on_commandline_entry_key_press_event"   : self.commandline_entry_key_press,
               "on_commandline_entry_activate"      : self.commandline_entry_activate,

               ##Search stuff
               "on_data_treeview_button_press_event": self.dataview_press,
               "on_button_search_clicked": self.search_modules,
               "on_treeview_search_button_press_event": self.searchtree_press,
               }
        self.commandline_entry = self.wTree.get_widget("commandline_entry")
        if not self.commandline_entry:
            devlog("engine", "Could not find commandline entry in GUI!")
            #ERROR 
            
        # gui commandline support
        self.commandline            = ''
        self.commandline_history    = []
        self.current_cl_history=0

        self.window=self.wTree.get_widget("window1") # sure there must be another way
        self.handlers = HandlersReloadHack()
        self.handlers["Listener-Shell"]=self.do_listener_shell
        #
        # if you want to handle a file.py with a different name in the gtkTree, you have to set
        #     handlers_multinames['diff name'] = "file"
        #
        # then use node_resolv("diff name") to resolv it.
        #
        self.handlers_multinames={}        
        # Right Click Menu
        mlist=self.wTree.get_widget("menubar2").get_children()
        for a in mlist:
            name=a.get_children()[0].get_label()
            if name=="Exploit Action":
                self.menu=a.get_submenu()
                break        

        self.moduletree=self.wTree.get_widget("module_treeview")
        self.fillmoduletree(self.wTree)
        self.listenertreeview=self.wTree.get_widget("listener_treeview")
        self.initlistenerlist(self.listenertreeview)
        
        ##Search stuff
        self.searchtree=self.wTree.get_widget("treeview_search")
        self.initsearchlist(self.searchtree)

        self.mycanvasengine=canvasengine.canvasengine(self)
        self.hostsview=self.wTree.get_widget("hosts_treeview")

        # target widget for new graph layout of nodetree ..
        self.CanvasFrame = self.wTree.get_widget("CanvasFrame")
        self.TargetFrame = self.wTree.get_widget("TargetFrame")

        #this is where we hook the treeview so you can select targets, listeners, etc
        self.initnodetreeview(self.hostsview,self.mycanvasengine.localnode)
        dic["on_nodetree_button_press_event"]=self.nodegui.line_press

        #connect dictionary here
        self.wTree.signal_autoconnect (dic)

        self.heliumclist=self.wTree.get_widget("heliumclist")
        self.localip=self.wTree.get_widget("callback_entry").get_text()
        self.targetip=self.wTree.get_widget("target_entry").get_text()

        #setup the log window
        self.logwindowview=self.wTree.get_widget("textlog")
        self.logwindow=gtk.TextBuffer(None)
        self.logwindowview.set_buffer(self.logwindow)

        #setup debug window
        self.debugwindowview=self.wTree.get_widget("textdebug")
        self.debugwindow=gtk.TextBuffer(None)
        self.debugwindowview.set_buffer(self.debugwindow)

        # related to the Data View tab
        # setup data view
        self.dataviewwindow = self.wTree.get_widget("data_treeview")
        self.searchtreeview = self.wTree.get_widget("treeview_search")

        #setup the dump window
        self.dumpwindow=gtk.TextBuffer(None)
        self.dumpwindowview=self.wTree2.get_widget("dump_textview")
        self.dumpwindowview.set_buffer(self.dumpwindow)
        self.handlerdepth=0
        self.dumpscroll=self.wTree2.get_widget("dump_scrolledwindow")
        #self.dumpscroll.hide()
        # XXX wtf is self.top2??
        #self.top2=gtk_glade_hook.XML(get_glade_file(), "window2")
        #self.top2.get_widget("window2").hide()

        #setup the Documentation window
        self.documentationwindow = gtk.TextBuffer(None)
        self.documentationwindowview = self.wTree.get_widget("documentation_textview")
        self.documentationwindowview.set_buffer(self.documentationwindow)
        self.selection = self.moduletree.get_selection()
        self.selection.connect('changed', self.columns_changed)

        ##Search Stuff
        self.selection1 = self.searchtreeview.get_selection()
        self.selection1.connect('changed', self.search_columns_changed)

        # prepare covertbar
        self.covertbar=self.wTree.get_widget("covertbar")
        self.covertbar.set_value(self.mycanvasengine.covertness)
        self.covertbar.set_digits(1)
        self.covertbar.set_draw_value(True)
        self.covertbar.set_increments(1, 1)
        self.covertbar.set_range(1, 12)

        #we give the engine a reference to us so he can call back into us

        self.mycanvasengine.log("Your use of CANVAS is subject to certain terms and conditions, as specified in the CANVAS License. By using CANVAS, you agree to these terms.")
        self.mycanvasengine.log("One of these conditions is that the CANVAS license, as included with this package, is the sole description of your rights.")
        #self.mycanvasengine.log("You hereby agree that any attached conditions to your Purchase Order are disregarded.")
        self.mycanvasengine.log("CANVAS is brought to you by: %s" % canvas_coders)
        self.mycanvasengine.log("Local IP=%s"%self.localip)
        #these two variables come from exploitutils for now
        self.mycanvasengine.log("Your CANVAS subscription expires %s."%expiredate.strip())
        self.mycanvasengine.log("Your CANVAS subscription is registered to %s"%contactemail.strip())
        self.mycanvasengine.log("If you are getting close to expiring, contact 212-534-0857 or admin@immunityinc.com to renew!")
        self.dialogs={}
        self.wTree2Dict={}
        self.play("WELCOME")
        if canvasengine.CanvasConfig['gui_maximize_on_startup']:
            self.window.maximize() #got annoying during debugging

        if len(canvasengine.exploitPacks):
            self.setupExploitPackWindow()
            if not os.path.exists(canvasengine.EXPLOITPACK_LICENSE_FLAG):
                self.showExploitPackWindow()        

        # we show the whole window after all get initialized (before it was hidden while we load it).
        self.window.show()
        return

    def quit(self,args):
        "we're done!"
        self.mycanvasengine.shutdown()
        try:
            gtk.main_quit()
        except:
            gtk.mainquit()
        return

    def reload_modules(self, args):
        canvasengine.reloadAllModules()

    def clearqueue(self,source,condition):
        """Our callback for gui events"""
        self.gui_queue.clearqueue()

        #print "End of clearqueue"
        return 1

    def open_screenshot(self, command):
        import stat, time
        wTreeTmp=gtk_glade_hook.XML(get_glade_file(), "myscreenshots")
        wid = wTreeTmp.get_widget("myscreenshots")
        # on_ImageTree_button_press_event
        dic= { "on_ImageTree_button_press_event": self.show_Images}

        wTreeTmp.signal_autoconnect (dic)

        iTree=wTreeTmp.get_widget("ImageTree")

        model=gtk.TreeStore(gobject.TYPE_STRING, gobject.TYPE_STRING, gobject.TYPE_STRING)

        for a in os.listdir("My_Screenshots/"):
            if a == "." or a == ".." or a[len(a)-4:] != ".bmp":
                continue

            date= time.ctime(os.stat("My_Screenshots/"+a)[stat.ST_CTIME])
            des=""
            try:
                f=open("My_Screenshots/"+a[:len(a)-3]+"conf")
                arg= f.readline().split(":", 2)
                des="%sx%s  %s" % (arg[0], arg[1], arg[2]) 
            except IOError:
                des="No description"
            insert_row(model,None,a, date, des)            

        iTree.set_model(model)
        iTree.set_headers_visible(True)

        renderer=gtk.CellRendererText()
        column=gtk.TreeViewColumn("FileName",renderer, text=0)
        column.set_resizable(True)
        iTree.append_column(column)

        renderer=gtk.CellRendererText()
        column=gtk.TreeViewColumn("Date",renderer, text=1)
        column.set_resizable(True)
        iTree.append_column(column)

        renderer=gtk.CellRendererText()
        column=gtk.TreeViewColumn("Description",renderer, text=2)
        column.set_resizable(True)
        iTree.append_column(column)
        self.iTree = iTree
        iTree.show()
        return

    def show_Images(self, obj, event):
        if event.type==gtk.gdk._2BUTTON_PRESS:
            model,iter=self.iTree.get_selection().get_selected()
            if not iter:
                return
            description = model.get_value(iter,2)
            self.image_filename = model.get_value(iter,0)
            wTemp = gtk_glade_hook.XML(get_glade_file(), "sImage")

            window=wTemp.get_widget("sImage")
            window.set_title(description)

            (width,height) = description.split(" ", 1)[0].split("x")

            self.Iwidth=int(width)
            self.Iheight=int(height)
            #print "Image width=%d height=%d"%(self.Iwidth,self.Iheight)
            self.drawingarea_image = wTemp.get_widget("drawingarea_image")
            #should use CANVAS base path here first...
            image_filename=os.path.join("My_Screenshots",self.image_filename)
            #print "Loading file from: %s"%image_filename
            self.drawingarea_image.set_from_file(image_filename)
            return 

    def handle_gui_queue(self,command, args):
        """
        Callback the gui_queue uses whenever it receives a command for us.
        command is a string
        args is a list of arguments for the command
        """
        gtk.gdk.threads_enter()
        threadcheckMain("handle_gui_queue")
        devlog('gtk::gui::handle_gui_queue', "command=<%s> args=%s" % (command, args))
        if command=="set_label":
            #print "setting label"
            obj=args[0]
            label=args[1]
            obj.set_label(label)
        elif command=="do_listener_shell":
            shell=args[0]
            #print "doing a listener shell"
            self.do_listener_shell(shell)

        elif command == "browse_filesystem":
            node    = args[0]
            self.launch_filesystem_browser(node)
        #browser handler functions
        elif command=="browser_handler":
            browser=args[0]
            fname=args[1]
            browser_args=args[2:]
            browser.browser_handler(fname, browser_args)
        #end browser handler functions
            
        elif command=="logmessage":
            msg=args[0]
            color=args[1]
            #print "logmessage: %s"%msg
            self.log(msg,color)
        elif command=="debugmessage":
            msg=args[0]
            color=args[1]
            #print "logmessage: %s"%msg
            self.debuglog(msg,color)
        elif command=="snifferlogmessage":
            msg=args[0]
            color=args[1]
            #self.addSnifferLine(msg,color=color)
            #ignored - causes annoying loops
        elif command=="update listener info":
            lst=args[0]
            self.setListenerInfo(lst)
        elif command=="shellwindow log":
            shellwindow=args[0]
            text=args[1]
            self.listener_log(shellwindow,text)
        elif command=="add note to host":
            hostobj=args[0]
            dname="note_dialog"
            wTree2= gtk_glade_hook.XML(get_glade_file() ,dname)
            dialog = wTree2.get_widget(dname)
            if dialog==None:
                print "Did not find note dialog, fatal error! (old .glade file?)"
            dialog.set_position(gtk.WIN_POS_CENTER_ALWAYS)
            mywid=wTree2.get_widget("mytext")
            mywid.realize()
            #set the current contents to be what we had before
            mywid.get_buffer().set_text(hostobj.get_note()) 
            response=dialog.run()
            dialog.hide()
            if response == gtk.RESPONSE_OK:
                buffer=mywid.get_buffer()
                mytext=buffer.get_text(buffer.get_start_iter(),buffer.get_end_iter())
                hostobj.add_note(mytext)

        elif command=="set local ip":
            self.setLocalIP(args[0])

        elif command == "set target ip":

            self.setTargetIP(args[0])
            
        # when adding a host via the button, we want to use this gui command
        # and not just blindly run the module, this gives us more control on
        # what to do with the newly added host!
        elif command=="add host":
            #a bit more complex than usual
            dname       = 'exploit_dialog'
            gladefile   = 'exploits'+os.sep+'addhost'+os.sep+self.handlers['addhost'].GTK2_DIALOG
            wTree2      = gtk_glade_hook.XML(gladefile,dname)
            dialog      = wTree2.get_widget(dname)
            # enter->ok
            connectdict = { 'on_enter_clicked' : (self.gtk_ok_response, dialog) }
            wTree2.signal_autoconnect(connectdict)
            dialog.set_position(gtk.WIN_POS_CENTER_ALWAYS)
            response = dialog.run()
            dialog.hide()
            if response == gtk.RESPONSE_OK:
                host                    = wTree2.get_widget('entry1').get_text()
                argsDict                = {}
                argsDict['host']        = host
                argsDict['passednodes'] = self.mycanvasengine.passednodes                  
                app                     = self.mycanvasengine.getModuleExploit('addhost')
                app.argsDict            = argsDict
                app.engine              = self.mycanvasengine
                app.log                 = self.mycanvasengine.log
                app.run()
                # activate the hostknowledge child as target
                for c in self.mycanvasengine.passednodes[0].hostsknowledge.children:
                    # addhost resolves to IP in app.result
                    if c.interface == app.result:
                        c.set_as_target(t=1)

        elif command=="add interface":
            #a bit more complex than usual
            obj=args[0]
            dname="interface_dialog"
            wTree2= gtk_glade_hook.XML(get_glade_file(), dname)
            dialog = wTree2.get_widget(dname)
            if dialog==None:
                print "DID NOT FIND DIALOG - FATAL ERROR: %s"%dname
            dialog.set_position(gtk.WIN_POS_CENTER_ALWAYS)
            response=dialog.run()
            dialog.hide()
            if response == gtk.RESPONSE_OK:
                name=wTree2.get_widget("name_entry").get_text()
                ip=wTree2.get_widget("ip_entry").get_text()
                netmask_bits=int(wTree2.get_widget("netmask").get_value())
                netmask=long(b("1"*netmask_bits))<<(32-netmask_bits) #create integer out of /24
                nat=wTree2.get_widget("nat_checkbox").get_active()
                startport=int(wTree2.get_widget("startport").get_value())
                endport=int(wTree2.get_widget("endport").get_value())
                obj.add_ip((name,ip,netmask),nat,startport,endport)

        elif command=="addLine":
            #print "addLine called in canvasguigtk2.py"
            obj=args[0]
            self.addLine(obj)

        elif command=="Register New Exploit":
            newexploit=args[0]
            self.registerNewExploit(newexploit)

        elif command=="Remove Listener":
            listener=args[0]
            self.removeListener(listener)

        elif command=="deleteLine":
            obj=args[0]
            self.deleteLine(obj)

        elif command=="addNode":
            node=args[0]
            self.addNode(node)

            #print "done here 123123"
        elif command=="update":
            line=args[0]
            self.updateLine(line)


        # related to the Data View tab
        elif command=="set_data_view_columns":
            titles=args[0]
            self.SetDataViewColumns(titles)

        elif command=="set_data_view_info":
            titles=args[0]
            self.SetDataViewInfo(titles)

        elif command=="check_listener_for_connection":
            print "Check for connection...from gui thread"
            listener=args[0]
            #start in a new thread because this could block potentially
            newthread=Thread(target=listener.check)
            newthread.start()

        elif command == "launch_exploit":

            # Fire up an exploit GUI of your choice
            name=args[0]
            glade_file="exploits/"+name+"/"+self.handlers[name].GTK2_DIALOG
            self.display_exploit_dialog(name,gladefile=glade_file)

        else:
            print "Did not recognize action to take %s: %s"%(command,args)
        #print "Done handling gui queue"
        devlog('gtk::gui::handle_gui_queue', "Done: command=<%s> args=%s" % (command, args))
        gtk.gdk.threads_leave()
        return 1

    # related to the Data View tab
    def SetDataViewColumns(self, args):

        # delete columns, fresh start...
        l = self.dataviewwindow.get_columns()
        for x in l:
            self.dataviewwindow.remove_column(x)

        # Add columns
        i=0
        for c in args:
            self.AddDataViewColumn(c,i)
            i += 1
        self.dataviewwindow.show()
        return

    def AddDataViewColumn(self, title, cid):

        model=gtk.ListStore(gobject.TYPE_STRING)

        model.clear()
        
        self.dataviewwindow.set_model(model)
        self.dataviewwindow.set_headers_visible(True)

        renderer=gtk.CellRendererText()
        column=gtk.TreeViewColumn(title,renderer, text=cid)
        column.set_resizable(True)
        self.dataviewwindow.append_column(column)
        return

    def SetDataViewInfo(self, args):

        # up to 5 columns
        c = len(args[0])
        if c == 1:
            model=gtk.ListStore(gobject.TYPE_STRING)
        elif c == 2:
            model=gtk.ListStore(gobject.TYPE_STRING,gobject.TYPE_STRING)
        elif c == 3:
            model=gtk.ListStore(gobject.TYPE_STRING,gobject.TYPE_STRING,gobject.TYPE_STRING)
        elif c == 4:
            model=gtk.ListStore(gobject.TYPE_STRING,gobject.TYPE_STRING,gobject.TYPE_STRING,gobject.TYPE_STRING)
        elif c == 5:
            model=gtk.ListStore(gobject.TYPE_STRING,gobject.TYPE_STRING,gobject.TYPE_STRING,gobject.TYPE_STRING,gobject.TYPE_STRING)
        elif c == 6:
            model=gtk.ListStore(gobject.TYPE_STRING,gobject.TYPE_STRING,gobject.TYPE_STRING,gobject.TYPE_STRING,gobject.TYPE_STRING,gobject.TYPE_STRING)
        else:
            model=gtk.ListStore(gobject.TYPE_STRING)

        self.dataviewwindow.set_model(model)
        model.clear()

        # fill rows
        v = 0
        for a in args:
            i = 0
            myiter=model.insert(v)
            for data_members in a:
                model.set_value(myiter,i,data_members)
                i += 1
            v += 1
        return

    def gui_queue_append(self,command,args):
        self.gui_queue.append(command,args)
        #give up thread, perhaps?
        #time.sleep(0.1) #not needed, I believe
        return 1


    def threads_enter(self):
        print "Threads enter called"
        gtk.threads_enter()


    def threads_leave(self):
        print "Threads leave called"
        gtk.threads_leave()

    def save_desktop(self,obj):
        return

    def adjust_dump_colorization(self,obj):
        return

    def save_log(self,obj):
        return

    def stop_dump(self,obj):
        self.mycanvasengine.closeSniffer()
        return

    def filter_dump(self,obj):
        self.display_exploit_dialog("filterstring")
        return

    def start_dump(self,obj):
        self.mycanvasengine.openSniffer()
        return

    def add_host(self,obj):
        devlog("gui","Called add_host")
        # use the gui queue to handle this, so we have more control ...
        self.gui_queue_append('add host', [None]);
        #gladefile="exploits/"+"addhost"+"/"+self.handlers["addhost"].GTK2_DIALOG
        #self.display_exploit_dialog("addhost",gladefile=gladefile)  
        return
    
    def set_os_detection_options(self,obj):
        """
        Sets the options for OS Detection - not really a module per-se, but
        we might as well put it as one
        """
        devlog("gui","Called set os detection options")
        name="set_os_detection_options"
        glade_file="exploits/"+name+"/"+self.handlers[name].GTK2_DIALOG
        self.display_exploit_dialog(name,gladefile=glade_file)
        return

    def cws_connect(self,obj):
        self.log("Called cws_connect","black")
        wTree2= gtk_glade_hook.XML(get_glade_file(), "cws_connect")
        exploitdialog = wTree2.get_widget("cws_connect")
        exploitdialog.set_position(gtk.WIN_POS_CENTER_ALWAYS)
        #print "Before exploitdialog.run()"
        response=exploitdialog.run()
        #print "After exploitdialog.run()"
        #print "Serving exploit dialog"
        #print "Hiding dialog"
        exploitdialog.hide()
        if response == gtk.RESPONSE_OK:
            try:
                username=wTree2.get_widget("cws_username").get_text()
                password=wTree2.get_widget("cws_password").get_text()
                host=wTree2.get_widget("cws_host").get_text()
                port=wTree2.get_widget("cws_port").get_value()
                port=int(port)
                self.mycanvasengine.connectcws(username,password,host,port)
            except:
                self.mycanvasengine.log("WARNING: Unhandled Exception caught in exploit...")
                import traceback
                print '-'*60
                traceback.print_exc(file=sys.stdout)
                print '-'*60


    def get_input_read(self):
        return gtk.gdk.INPUT_READ

    def addknownhost(self,host,os,status):
        """called by engine to add a host to our list"""
        print "addknownhost called!"
        self.addLine(host)
        return 

    def addLine(self,line):
        """add a new node or line of some sort"""
        #print "canvasguigtk2.py::addLine called"
        if self.nodegui:
            self.nodegui.addLine(line)
        else:
            devlog("ERROR: trying to add a line with no nodegui!")

    def deleteLine(self,line):
        """deletes a line from the node gui"""
        self.nodegui.delete(line)

    def updateLine(self,line):
        self.nodegui.update_object(line)

    def addNode(self,node):
        """add a new node or line of some sort"""
        #print "canvasguigtk2.py::addNode called"
        self.nodegui.addNode(node)


    def log(self,message,color,enter="\n", check=1):
        """
        logs a message to the log window
        right now it just ignores the color argument

        READTHIS:
        You cannot call gtk.mainiteration while inside a handler spawned by input_add()
        This freezes up the whole system. So instead, set check=0 if you are potentially called via that
        path. Otherwise we check for events, which allows us to update the screen and handle
        any socket events upon any log message
        """
        sys.stdout.flush() #flush stdout in case a print is waiting on it
        #print "Entered log function. message=%s Self.handlerdepth=%d check=%d"%(message,self.handlerdepth,check)
        if len(message) and message[-1] == enter:
            message = iso8859toascii(message)
        else:
            message = iso8859toascii(message + enter)
        #We still get this error sometimes:
        #canvasguigtk2.py:1025: GtkWarning: gtk_text_buffer_emit_insert: assertion `g_utf8_validate (text, len, NULL)' failed
        #self.logwindow.insert(iter, message,len(message))
        #stripping out nulls is the wrong thing to do...nulls should be valid unicode!
        #message = message.replace("\x00","")
        #self.logwindow.insert_defaults(message+"\n")
        devlog("logwindow", "Message: %s"%prettyprint(message))
        if self.logwindow==None:
            #no logwindow - don't do anything
            return 
        buffer = self.logwindow
        iter = buffer.get_end_iter()
        #gtk versioning avoidance
        if color != "black":
            tag = buffer.create_tag()
            tag.set_property("foreground", color)
            self.logwindow.insert_with_tags(buffer.get_end_iter(), message, tag)	
        else:
            try:
                self.logwindow.insert(iter, message,len(message))
            except:
                self.logwindow.insert(iter, message)

        mark = buffer.create_mark("end", buffer.get_end_iter(), False)

        self.logwindowview.scroll_to_mark(mark,0.05,True,0.0,1.0)
        #print "Exited log function"
        return

    def debuglog(self,message,color,enter="\n", check=1):
        """
        logs a message to the log window
        right now it just ignores the color argument
        """
        message = iso8859toascii(message + enter)
        buffer = self.debugwindow
        iter = buffer.get_end_iter()

        if color != "black":
            tag = buffer.create_tag()
            tag.set_property("foreground", color)
            self.debugwindow.insert_with_tags(buffer.get_end_iter(), message, tag)	
        else:
            try:
                self.debugwindow.insert(iter, message,len(message))
            except:
                self.debugwindow.insert(iter, message)

        mark = buffer.create_mark("end", buffer.get_end_iter(), False)

        self.debugwindowview.scroll_to_mark(mark,0.05,True,0.0,1.0)
        return



    def addSnifferLine(self,line,color="BLACK"):
        #line=line+"\n"
        try:
            self.dumpwindow.insert_at_cursor(line,len(line))
        except:
            self.dumpwindow.insert_at_cursor(line)

        buffer=self.dumpwindow
        mark = buffer.create_mark("end", buffer.get_end_iter(), False)

        self.dumpwindowview.scroll_to_mark(mark,0.05,True,0.0,1.0)

        return

    def covertbar_changed(self, covertbarobj):
        covertbarobj.set_value(self.mycanvasengine.set_covert_value(covertbarobj.get_value()))
        return

    def setLocalIP(self,IP):
        """
        Sets the local IP in the entry box for display and also in our local storage
        """
        self.localip=IP
        self.wTree.get_widget("callback_entry").set_text(IP)
        return

    def setTargetIP(self, IP):
        self.targetip = IP
        self.wTree.get_widget("target_entry").set_text(IP)
        return


    def initlistenerlist(self,view):
        """
        This is the exploits list on the bottom pane
        """
        model = gtk.TreeStore(gobject.TYPE_PYOBJECT, gtk.gdk.Pixbuf, gobject.TYPE_STRING, gobject.TYPE_STRING, gobject.TYPE_STRING, gobject.TYPE_STRING)        
        self.listenerlistmodel=model

        view.set_headers_visible(True)

        view.set_model(model)

        renderer=gtk.CellRendererPixbuf()
        column=gtk.TreeViewColumn("Status", renderer, pixbuf=1)
        column.set_resizable(True)
        view.append_column(column)

        renderer=gtk.CellRendererText()
        column=gtk.TreeViewColumn("Action",renderer, text=2)
        column.set_resizable(True)
        view.append_column(column)

        renderer=gtk.CellRendererText()
        column=gtk.TreeViewColumn("Start Time",renderer, text=3)
        column.set_resizable(True)
        view.append_column(column)

        renderer=gtk.CellRendererText()
        column=gtk.TreeViewColumn("End Time",renderer, text=4)
        column.set_resizable(True)
        view.append_column(column)

        renderer=gtk.CellRendererText()
        column=gtk.TreeViewColumn("Information",renderer, text=5)
        column.set_resizable(True)
        view.append_column(column)

        view.show()
        return

    # related to search treeview
    def initsearchlist(self,view):
        model = gtk.TreeStore(gobject.TYPE_STRING, gobject.TYPE_STRING)        
        self.searchlistmodel=model

        view.set_headers_visible(True)

        view.set_model(model)

        renderer=gtk.CellRendererText()
        column=gtk.TreeViewColumn("Name",renderer, text=0)
        column.set_resizable(True)
        view.append_column(column)

        renderer=gtk.CellRendererText()
        column=gtk.TreeViewColumn("Description",renderer, text=1)
        column.set_resizable(True)
        view.append_column(column)

        view.show()
        return

    def initnodetreeview(self,view,local):
        # integrating graph frame support ...
        self.nodegui=newgui.nodegui(view,local,self.mycanvasengine, CanvasFrame=self.CanvasFrame, TargetFrame=self.TargetFrame)
        assert self.nodegui != None, "Serious error: Nodegui should never been None here"

    def inithostslist(self,view):

        #must have a column for each data type
        model=gtk.ListStore(gobject.TYPE_STRING, gobject.TYPE_STRING, gobject.TYPE_STRING)
        self.hostsmodel=model

        view.set_headers_visible(True)

        view.set_model(model)

        renderer=gtk.CellRendererText()
        column=gtk.TreeViewColumn("Host",renderer, text=0)
        column.set_resizable(True)
        view.append_column(column)

        renderer=gtk.CellRendererText()
        column=gtk.TreeViewColumn("OS",renderer, text=1)
        column.set_resizable(True)
        view.append_column(column)

        renderer=gtk.CellRendererText()
        column=gtk.TreeViewColumn("Status",renderer, text=2)
        column.set_resizable(True)
        view.append_column(column)

        view.show()
        return

    # TODO: normalize (Generic) + normalize_OS

    def proclist_normalize(self, list):
        nnl = [
            # TODO: regexp here
            { 'proc': "i386",   'names': ["intel", "i86pc", "x86", "i486", "i586", "i686"] },
            { 'proc': "sparc",  'names': ["sparc32", "sparc64"] },
            { 'proc': "ppc",    'names': ["ppc64"] },
            { 'proc': "alpha",  'names': ["alpha64"] },
            { 'proc': "rs6000", 'names': ["rs6k", "rs-6000", "rs-6k"] },
            { 'proc': "parisc", 'names': ["pa-risc", "hp-pa", "hppa"] },
        ]

        nl = []
        for proc in list:
            if proc[0] == '_': # _proc is vuln but no exploit for it yet
                continue
            added = 0
            proc = proc.lower()
            for dp in nnl:
                tp = dp['proc']
                for cp in dp['names']:
                    if proc == cp and not nl.count(tp):
                        nl.append(tp)
                        added = 1
            if not added:
                nl.append(proc)
        return nl

    def proclist_expand(self, proclist):

        if not len(proclist):
            return

        OS_Proc_list = {
            'Linux': ["i386", "sparc", "mipsel"],
            'Solaris': ["sparc", "i86pc"],
            'Windows': [],
            'FreeBSD': [],
            'AIX': [],
        }

        if OS_Proc_list.has_key(proclist[0]):
            for proc in OS_Proc_list[proclist[0]]:
                if not proc in proclist:
                    proclist.append(proc)


    def addIter(self, model, iter):
        """
           gtk menu in *logical* order"

           iter = [ var name / parent / desc1 / desc2 / {top} ]

        """

        if len(iter) < 4:
            print "Iter list incomplete"
            return None

        if len(iter) > 4:
            (name, parent, desc1, desc2, top) = iter
        else:
            (name, parent, desc1, desc2) = iter
            top = None

        if desc1 == None:
            if name:
                desc1 = name.capitalize()
            else:
                # hmmm...
                desc1 = "unknown"

        # TODO lame hack, check why i can't init it in __init__
        try:
            s = self.iters
        except AttributeError:
            self.iters = {}

        (parent, parentstr) = self.IterExt(parent)
        if parent==None:
            devlog("gui::fillmoduletree", "Adding Iter: %s:%s %s"%(desc1, desc1, parent))

        row = insert_row(model, parent, desc1, desc2, top=top)

        # hack
        if parentstr == None:
            parentstr = ""

        # if we have 'name', we want to remember that row in our dict
        if name:
            iterstr = "%s/%s" % (parentstr, name)
            if parentstr == "":
                parentstr = "/"
            self.iters[iterstr] = (row, parentstr)
            #print "[%s] = %s" % (iterstr, (row, parentstr))

        return row

    def IterExt(self, name, parent=None):

        if name == None:
            return (None, None)

        if parent == None:
            parent = "/"
        if parent[0] is not '/':
            parent = "/" + parent
        if parent[-1] is not '/':
            parent += '/'
        parentname = parent + name

        devlog("gui::fillmoduletree","looking for %s" % parentname)

        if not self.iters.has_key(parentname):
            devlog("gui::fillmoduletree", "ITER %s NOT FOUND (%s)" % (name, parentname))
            return (None, None)

        devlog("gui::fillmoduletree",">> found [%s] with <%s>" % (name, parentname))
        return (self.iters[parentname][0], parentname)

    def Iter(self, name, parent=None):
        # short version of IterExt

        iter = self.IterExt(name, parent)
        if iter == None:
            return None
        return iter[0]

    def addIters(self, model, iterlist):

        for iter in iterlist:
            self.addIter(model, iter)

    # related to the New Exploit NodeTree & Favorite Exploit Node tree
    def ReadNewModsFile(self, fn):            
        # Read txt file of exploit names for use in new exploits, favorite exploits etc
        infile = open(fn,"r")
        mod_list=[]
        for t in infile.readlines():
            line = t.rstrip()
            if line == "#":
                continue
            elif line == "\x20":
                continue
            elif line == "\n":
                continue
            else:
                if line != '':
                    mod_list.append(line)
        infile.close()
        return mod_list


    def fillmoduletree(self,obj):

        self.moduletreeCallbacks = {}

        ctree=self.moduletree
        #                       (name,                description,         background color)
        model=gtk_TreeStore_hook(gobject.TYPE_STRING, gobject.TYPE_STRING, gobject.TYPE_STRING)
        self.exploitsmodel=model

        # Core tree nodes, which there will only ever be one of.
        items = [
            # Rich mod - favorites node
            dict(name=self.favExpTitle, desc=self.favExpDesc),
            # related to the New Exploit NodeTree
            dict(name=self.newExpTitle, desc=self.newExpDesc),
            dict(name="Exploits", desc="CANVAS Exploits"),
        ]
        endItems = [
            dict(name="Listener Shells", desc="Control the active listener"),                                            
            dict(name="Listener-Shell", desc="Pop up a listener shell for the active node", parent="Listener Shells")
        ]

        exploitPacks = [dict(name="3rd Party", desc="3rd Party Exploit Packs")]

        # These are processed once globally, and then once for each
        # of the exploit packs, which might bring their own Recon tools
        extraItems = [
            dict(name="Commands", desc="Commands to run on Nodes"),
            dict(name="Trojans", desc="Various commands for control and deployment."),
            dict(name="Tools", desc="Various tools"),
            dict(name="Recon", desc="Reconnaissance tools"),
            dict(name="Local", desc="Local recon tools that run on a node", parent="Recon"),
            dict(name="Remote", desc="Remote recon tools that run against a target", parent="Recon"),            
            dict(name="DoS", desc="Denial of service attacks"),
            dict(name="Configuration", desc="CANVAS configuration modules"),
            dict(name="Servers", desc="CANVAS servers"),
            dict(name="Fuzzers", desc="Modules to stress test a protocol"),
            dict(name="ImportExport", desc="Interface CANVAS with other tools"),
            dict(name="Post-Intrusion", desc="Various tools for use post-intrusion."),
        ]

        # Exploits are handled specially, because they get auto categorised by os/arch/etc
        exploitItems = [            
            dict(name="Local", desc="Local attacks that run against a node"),
            dict(name="Clientside", desc="Client side attacks"),
            dict(name="Remote", desc="Remote attacks"),
            dict(name="Windows", desc="Attacks against Microsoft platforms"),
            dict(name="Unix", desc="Attacks against unix platforms"),
            dict(name="Web Exploits", desc="Attacks against web applications"),
        ]        

        def makeIter(x, bp=""):
            makeIters([x], bp)
            return pathOf(x, bp)

        def pathOf(z, bp):
            return parentPathOf(z, bp) + "/" + z["name"]

        def parentPathOf(z, bp):

            if z.has_key("parent"):
                p = z["parent"]
            else:
                p = ""

            if bp != "":
                if p != "":
                    if not bp.endswith("/"):                        
                        bp += "/"                        
                    p = bp + p
                else:
                    p = bp
            return p


        def makeIters(x, bp="", only=None):            
            for z in x:
                if only != None and z['name'] != only:
                    continue
                self.addIter(model, (z["name"], parentPathOf(z, bp), z["name"], z["desc"]))                    

        # related to the New Exploit NodeTree
        def handleNewExploits(mod, prop):
            if mod.__name__ in self.newmods:
                insert_row(model, self.Iter(self.newExpTitle), mod.__name__, mod.NAME)                    

        
        #Rich mod - favorites
        def handleFavExploits(mod, prop):
            if mod.__name__ in self.favmods:
                insert_row(model, self.Iter(self.favExpTitle), mod.__name__, mod.NAME)                    

        def handleSite(mod, prop, parent=""):
            siteMap={"Clientside":"Clientside",
                     "Client Side":"Clientside",
                     "Client side":"Clientside",
                     "Local":"Local",
                     "Remote":"Remote"}
            try:
                site = siteMap[prop['SITE']]
            except KeyError:
                # :/
                site = siteMap["Remote"]

            makeIters(exploitItems, parent, site)            
            parent += "/" + site 

            return parent

        def handleIgnore(mod, prop):
            pass

        def handleGeneric(mod, prop, rename=None):
            parent = handlePack(mod, prop)
            if rename != None:
                name = rename
            else:
                name = prop['TYPE']

            devlog("gui::fillmoduletree","Name: %s prop: %s"%(name, prop))

            makeIters(extraItems, parent, name)
            if len(parent):
                parent += "/"

            insert_row(model, self.Iter(parent + name), mod.__name__, mod.NAME)                    

        def handleRecon(mod, prop):
            parent = handlePack(mod, prop)
            makeIters(extraItems, parent, prop['TYPE'])
            if len(parent):
                parent += "/"
            parent += prop['TYPE']

            # We dont have any Local Recon modules, so why draw attention to it :)
            #parent = handleSite(mod, prop, parent)            
            #makeIters(exploitItems, parent, prop['SITE'])             

            assert self.Iter(parent) != None
            insert_row(model, self.Iter(parent), mod.__name__, mod.NAME)

        def handleFuzzer(mod, prop):
            devlog("gui::fillmoduletree","handleFuzzer called")
            parent = handlePack(mod, prop)
            makeIters(extraItems, parent, prop['TYPE'])
            if len(parent):
                parent += "/"
            parent += prop['TYPE'] #+="Fuzzer"
            devlog("gui::fillmoduletree"," Handle Fuzzer: parent=%s"%parent)
            assert self.Iter(parent) != None
            insert_row(model, self.Iter(parent), mod.__name__, mod.NAME)

        def handlePack(mod, prop):
            if hasattr(mod, "exploitPack"):
                ep = mod.exploitPack
                parent = "3rd Party/" + ep.name
            else:
                # List of types that should go under the root exploits
                if prop['TYPE'] in ["Exploit", "Web Exploit", "Web Exploits"]:
                    parent = "Exploits"
                else:
                    parent = ""

            return parent

        def handleWebExploit(mod, prop):
            background = None
            if prop['0DAY']:
                background = "#ffb7b7"         

            parent = handlePack(mod, prop)            
            makeIters(exploitItems, parent, "Web Exploits")
            p = parent + "/" + "Web Exploits"

            parent = handleSite(mod, prop, parent)            

            assert self.Iter(p) != None
            insert_row(model, self.Iter(p), mod.__name__, mod.NAME, background)

        def handleExploit(mod, prop):

            # common to 0days
            background = None
            if prop['0DAY']:
                background = "#ffb7b7"         

            parent = handlePack(mod, prop)
            parent = handleSite(mod, prop, parent)    

            addTo = []

            for c in mod.TARGET_CANVASOS_LIST:
                if c.base == "Windows":
                    eOS = "Windows"                    
                else:
                    eOS = "Unix"


                # Now per platform one
                makeIters(exploitItems, parent, eOS, )                


                allIter = makeIter(dict(name="All " + eOS, desc="Exploits for all %s versions" % eOS, parent=eOS), parent)
                addTo.append(allIter)
                if c.base=="Windows":
                    if c.version != "":                    
                        verIter = makeIter(dict(name="%s %s" % (c.base, c.version), desc="Exploits for %s %s" % (c.base, c.version), parent=eOS), parent)
                        addTo.append(verIter)

                else:
                    verIter = makeIter(dict(name="%s" % (c.base), desc="Exploits for %s" % (c.base), parent=eOS), parent)
                    addTo.append(verIter)

            if prop['MSADV'] != "":
                msIter = makeIter(dict(name="MS Advisory", desc="Exploits for Microsoft advisories", parent="Windows"), parent)
                insert_row(model, self.Iter(msIter), prop["MSADV"], mod.NAME, background)
                self.handlers_multinames[prop['MSADV']] = mod.__name__


            for i in set(addTo):                            
                assert self.Iter(i) != None
                insert_row(model, self.Iter(i), mod.__name__, mod.NAME, background)

            return

        propMap = { "Exploit":handleExploit,
                    "Fuzzer": handleFuzzer,
                    "Web Exploit": handleWebExploit,
                    "Web Exploits": handleWebExploit,
                    "Recon":handleRecon,
                    "Tool":lambda x,y: handleGeneric(x,y,"Tools"),
                    "Misc":handleIgnore,                    
                    }

        makeIters(items)
        if len(canvasengine.exploitPacks):
            makeIters(exploitPacks)
            # Note, hardcoded to assume there's only one entry in exploitPacks dict
            self.moduletreeCallbacks[exploitPacks[0]["name"]] = self.showExploitPackWindow
            for ep in canvasengine.exploitPacks.itervalues():
                makeIter(dict(name=ep.name, desc=ep.longName + (ep.demo == "Yes" and " (Demo)" or ""), parent="3rd Party"))

        for name in canvasengine.registeredModuleList():

            exploitmodExt = canvasengine.getModule(name, True)
            exploitmod = canvasengine.getModule(name)
            inserted = False

            if hasattr(exploitmod, "PROPERTY"):
                property = exploitmod.PROPERTY
            else:
                property = {'MISSING': True}


            # related to the New Exploit NodeTree
            # Insert new modules
            handleNewExploits(exploitmod, property)

            # Rich Mod
            handleFavExploits(exploitmod, property)

            try:
                if property['TYPE'] in propMap.keys():
                    propMap[property['TYPE']](exploitmod, property)
                else:                
                    handleGeneric(exploitmod, property)
                inserted = True
            except AssertionError:
                print "Error while wedging module %s into the gui tree. prop:%s" % (exploitmod.__name__, property)

            if inserted:
                self.handlers[name]=exploitmod
                self.handlers[name, 'ext'] = exploitmodExt
                # <very common variables can be set only 1 time to clear the code> (do we need them???)
                if not hasattr(exploitmod, 'GTK2_DIALOG'):
                    exploitmod.GTK2_DIALOG = "dialog.glade2"
                #if not hasattr(exploitmod, 'runExploit'):
                if True: # XXX temporary
                    exploitmod.runExploit = canvasengine.runExploit
                if not hasattr(exploitmod, 'runAnExploit_gtk2'):
                    #exploitmod.runAnExploit_gtk2 = canvasengine.runAnExploit_gtk2
                    exploitmod.runAnExploit_gtk2 = runAnExploit_gtk2
                if hasattr(exploitmod, 'theexploit') and not hasattr(exploitmod.theexploit, 'name') and \
                   hasattr(exploitmod, 'NAME'):
                    exploitmod.theexploit.name = exploitmod.NAME # ne


        makeIters(endItems)
        # TODO: reorder numalpha (Windows esp)

        # move "All" leaf to top of branch
        reorder_model(model)

        #Set this so other modules know we've done the work...
        canvasengine.registeredallmodules=1
        ctree.set_headers_visible(True)

        ctree.set_model(model)

        renderer=gtk.CellRendererText()
        column=gtk.TreeViewColumn("Name",renderer, text=0)
        column.set_resizable(True)
        ctree.append_column(column)
        renderer=gtk.CellRendererText()

        column=gtk.TreeViewColumn("Description",renderer, text=1, background=2)
        column.set_resizable(True)
        ctree.append_column(column)
        ctree.show()
        #print "PATH: %s"%sys.path
        #sys.stdout.flush()
        return


    def __old_fillmoduletree(self,obj):
        """
        This function takes in the main wTree object
        and creates the moduletree GtkCTree stuff by hand
        Theoretically we could do a lot of wacky stuff by
        asking each exploit module what it's description is,
        but we don't have ALL that many modules.

        Edit this to add a new module to the GUI.

        """
        #have to remove this because SILICA also has
        #a module named "scanner" and this is not an
        #exploit, and so will make the GUI very confused
        #for d in ["SILICA/CODE", "SILICA"]:
        #    if d in sys.path:
        #        sys.path.remove(d)
        #devlog("gui","SYS.PATH= %s"%sys.path)

        ctree=self.moduletree
        #                       (name,                description,         background color)
        model=gtk_TreeStore_hook(gobject.TYPE_STRING, gobject.TYPE_STRING, gobject.TYPE_STRING)
        self.exploitsmodel=model


        Iters = [
            # related to the New Exploit NodeTree
            [ self.newExpTitle, None, None, self.newExpDesc ],

            #Rich Mod
            [ self.favExpTitle, None, None, self.favExpDesc ],
            [ "exploits", None, None, "CANVAS Exploits" ],
            [ "3rdparty", None, "3rd Party", "3rd Party Exploit Packs" ],
            [ "commands", None, None, "Commands to run on Nodes" ],
            [ "trojans", None, None, "Various commands for control and deployment"],
            [ "tools", None, None, "Various tools" ],
            [ "recon", None, None, "Various tools for Recon" ],
            [ "dos", None, "DoS", "Denial of service attacks" ],
            [ "listener", None, "Listener Shells", "Control Active Listener" ],
            [ None, "listener", "Listener-Shell", "Pop-up a Listener-Shell" ],
            [ "locals", "exploits", None, "Local attacks that run on nodes" ],
            [ "windows", "exploits", None, "Attacks against Microsoft Platforms" ],
            [ "unix", "exploits", None, "Attacks against Unix Platforms" ],
            # TODO: maybe the following ones have to be added "on demand" if an exploit has to be added in
            [ "unixall", "exploits/unix", "All", "All exploits for all Unix Platforms" ],
            [ "windowsall", "exploits/windows", "All", "All exploits for all Windows versions" ],
            [ "msnum", "exploits/windows", "MS Bulletin", "Windows exploits by their Microsoft Security Bulletin name" ],
            #[ "sql", "exploits", "SQL Injection", "Various tools for exploiting SQL Injection Vulnerabilties" ],
            [ "web", "exploits", "Web Exploits", "Various tools for exploiting custom web applications" ],
            [ "servers", None, None, "CANVAS Servers" ],
            [ "fuzzers", None, None, "Fuzzer Modules"],
            [ "importexport", None, None, "Import-Export tools" ],
            [ "postintrusion", None, None, "Post-Intrusion tools"],
            [ "clientside", "exploits", None, "Client-Side attacks" ],
            [ "local", "recon", None, "Local Recon tools to run on Nodes" ],
            [ "remote", "recon", None, "Remote Recon tools to run on Targets" ], 
            [ "config", None, "Configuration", "Various configuration modules for the engine" ]
        ]
        self.addIters(model, Iters)
        # TODO handle tree branches

        # <transition> // temporal !
        windowsIter = self.Iter("windows", "exploits")
        localsIter = self.Iter("locals", "exploits")
        sqlIter = self.Iter("sql", "exploits")
        webIter = self.Iter("web", "exploits")
        unixIter = self.Iter("unix", "exploits")
        unixallIter = self.Iter("unixall", "exploits/unix")
        windowsallIter = self.Iter("windowsall", "exploits/windows")
        msnumIter = self.Iter("msnum", "exploits/windows")
        commandsIter = self.Iter("commands")
        trojansIter  = self.Iter("trojans")
        reconIter = self.Iter("recon")
        toolsIter = self.Iter("tools")
        dosIter = self.Iter("dos")
        serversIter = self.Iter("servers")
        importexportIter = self.Iter("importexport")
        postintrustionIter = self.Iter("postintrusion")
        clientsideIter = self.Iter("clientside", "exploits")
        locareconIter = self.Iter("local", "recon")
        remotereconIter = self.Iter("remote", "recon")
        configIter = self.Iter("config")
        thirdPartyIter = self.Iter("3rdparty")
        fuzzersIter = self.Iter("fuzzers")
        # </transition>

        exploitpacks = {}

        for name in canvasengine.registeredModuleList():

            # XXX TODO: all the code used to build PROPERTY has to move in engine/something.
            # here we are in _GUI_ and we will only do _GUI_ stuffs, like fill the tree.
            # my name is fillmoduletree() after all.

            exploitmodExt = canvasengine.getModule(name, True)
            exploitmod = canvasengine.getModule(name)
            devlog('FillGTKTree', "parsing module <%s>" % name)

            # new method! check README.coders
            """
                    TODO:
                    =====

                    VERSION

                    if _X warn "exploit not coded!@$#!%"

                    OS/PROC/ENDIAN limiting post check

                    new tree:
                    =========

                    exploits -> OS -> proc -> version
                    |all        |all  |all    |all

                """

            inserted = False
            background = None
            if hasattr(exploitmod, "PROPERTY"):

                property = exploitmod.PROPERTY
            else:
                property = {'MISSING': True}

            if hasattr(exploitmod, "exploitPack"):
                ep = exploitmod.exploitPack
                if ep.name not in exploitpacks.keys():
                    self.addIter(model, (ep.name, "3rdparty", ep.name, ep.longName))
                    for k,v in ep.exploitSections.iteritems():
                        self.addIter(model, (k, "3rdparty/" + ep.name, v["name"], v["description"]))

            # common to 0days
            if property['0DAY']:
                background = "#ffb7b7"

            if property['TYPE'] is "Exploit":

                # Client side exploit                    
                if property.has_key('SITE') and property['SITE'] == "Clientside":

                    # hack, old style method
                    insert_row(model,clientsideIter,name,exploitmod.DESCRIPTION, background)
                    inserted = True

                # LOCAL exploit
                elif property.has_key('SITE') and property['SITE'] == "Local":

                    # hack, old style method
                    insert_row(model,localsIter,name,exploitmod.DESCRIPTION, background)
                    inserted = True

                    # TODO: sort by OS/proc/(version?)

                # all REMOTE
                else:

                    # this if was designed for affectsListExt -> OS/Proc only
                    #
                    if len(property['ARCH']):

                        for OS_Proc in property['ARCH']:
                            devlog('gui::fillmoduletree', "OS_Proc = %s" % OS_Proc)
                            assert type(OS_Proc) == type([]), \
                                   "expecting list[] in PROPERTY['ARCH'][]"
                            assert len(OS_Proc), \
                                   "empty list in PROPERTY['ARCH'][]"
                            OS = OS_Proc[0]

                            assert type(OS) == type(""), \
                                   "expecting string\"\" in PROPERTY['ARCH'][], got %s" % type(OS)
                            if OS[0] is '_':
                                #print "no version of %s for %s" % (name, OS[1:])
                                continue

                            ###################
                            #
                            # Windows exploits
                            #
                            if OS == "Windows":

                                # insert the exploit in windows/all (mess old style tree)
                                insert_row(model,windowsallIter,name,exploitmod.DESCRIPTION, background)
                                inserted = True

                                # sort exploits by VERSION
                                if len(OS_Proc) > 1:

                                    for version in OS_Proc[1:]:
                                        assert type(version) == type(""), \
                                               "expecting a string\"\" in PROPERTY['ARCH']['%s', ...], got %s" % \
                                               (OS, type(version))
                                        if version=="":
                                            #no such version
                                            continue
                                        if version[0] is '_':
                                            #print "no version of %s for %s" % (name, proc[1:])
                                            continue
                                        osPath = "exploits/windows"
                                        versionIter = self.Iter(version, osPath)
                                        if versionIter == None:
                                            versionIter = self.addIter(model, (version, osPath, "Win %s" % version, \
                                                                               "Exploits for Win %s" % version, 1))
                                        insert_row(model,versionIter,name,exploitmod.DESCRIPTION, background)

                                if property['MSADV'] != "":
                                    insert_row(model,msnumIter,property['MSADV'],exploitmod.DESCRIPTION, background)
                                    # another hack...
                                    self.handlers_multinames[property['MSADV']]=name

                            ###################
                            #
                            # Unix exploits
                            #
                            else:

                                devlog('gui::fillmoduletree', "Unix OS = %s" % OS)
                                # insert the exploit in unix/all (mess old style tree)
                                insert_row(model,unixallIter,name,exploitmod.DESCRIPTION, background)
                                inserted = True

                                # create OS if not existing
                                osIter = self.Iter(OS, "exploits/unix")
                                if osIter == None:
                                    osIter = self.addIter(model, (OS, "exploits/unix", OS, \
                                                                  "Attacks against %s Platforms" % OS, 1))

                                # we insert exploit in OS/ALL
                                osPath = "exploits/unix/" + OS
                                osallIter = self.Iter("all", osPath)
                                #if osallIter == None:
                                #    osallIter = self.addIter(model, ("all", osPath, "All", \
                                #             "All exploits against %s Platforms" % OS, 1))
                                #insert_row(model,osallIter,name,exploitmod.DESCRIPTION, background)

                                # and we insert it in OS/PROC
                                # XXX
                                if len(OS_Proc) == 1:
                                    self.proclist_expand(OS_Proc)
                                elif OS_Proc[1] == "All":
                                    OS_Proc = [OS_Proc[0]]

                                devlog('gui::fillmoduletree', "expanded OS_Proc = %s" % OS_Proc)
                                if len(OS_Proc) > 1:
                                    # we insert exploit in OS/Proc

                                    #pl = self.proclist_normalize(property['PROC'])
                                    #for proc in pl:
                                    for proc in OS_Proc[1:]:
                                        assert type(proc) == type(""), \
                                               "expecting a string\"\" in PROPERTY['ARCH']['%s', ...], got %s" % \
                                               (OS, type(proc))
                                        if proc == "All": # previously inserted
                                            continue
                                        if proc[0] is '_':
                                            #print "no version of %s for %s" % (name, proc[1:])
                                            continue
                                        procIter = self.Iter(proc, osPath)
                                        if procIter == None:
                                            procIter = self.addIter(model, (proc, osPath, proc, \
                                                                            "specific for %s Processor" % proc, 1))
                                        insert_row(model,procIter,name,exploitmod.DESCRIPTION, background)
                                else:
                                    # we insert exploit in OS
                                    insert_row(model,osIter,name,exploitmod.DESCRIPTION, background)


                    # we dont have 'OS' key
                    elif property.has_key('Unix hack'):
                        insert_row(model,unixallIter,name,exploitmod.DESCRIPTION, background)
                        inserted = True

            if property['TYPE'] == "Configuration":
                insert_row(model,configIter,name,exploitmod.DESCRIPTION, background)
                inserted = True

            if property['TYPE'] == "Fuzzer":
                devlog("gui::fillmoduletree", "Fuzzer TYPE found")
                insert_row(model,fuzzersIter,name,exploitmod.DESCRIPTION, background)
                inserted = True

            if property['TYPE'] == "Recon":

                if property.has_key('SITE') and property['SITE'] == "Local":

                    # hack, old style method
                    insert_row(model,localreconIter,name,exploitmod.DESCRIPTION, background)
                    inserted = True

                if property.has_key('SITE') and property['SITE'] == "Remote":

                    # hack, old style method
                    insert_row(model,remotereconIter,name,exploitmod.DESCRIPTION, background)
                    inserted = True

            # <transition>

            # old method
            if not inserted:
                if exploitmod.affectsList == "":
                    exploitmod.affectsList = property['TYPE']

                if "Commands" in exploitmod.affectsList:
                    insert_row(model,commandsIter,name,exploitmod.DESCRIPTION)
                    inserted = True
                if "Trojans" in exploitmod.affectsList:
                    insert_row(model,trojansIter,name,exploitmod.DESCRIPTION)
                if "Tools" in exploitmod.affectsList:
                    insert_row(model,toolsIter,name,exploitmod.DESCRIPTION)
                    inserted = True
                if "SQL Injection" in exploitmod.affectsList:
                    insert_row(model,sqlIter,name,exploitmod.DESCRIPTION)
                    inserted = True
                if "Web Exploits" in exploitmod.affectsList:
                    insert_row(model, webIter, name, exploitmod.DESCRIPTION)
                    inserted = True
                if "DoS" in exploitmod.affectsList:
                    insert_row(model,dosIter,name,exploitmod.DESCRIPTION)
                    inserted = True
                if "Servers" in exploitmod.affectsList:
                    insert_row(model,serversIter,name,exploitmod.DESCRIPTION)
                    inserted = True
                if "ImportExport" in exploitmod.affectsList:
                    insert_row(model,importexportIter,name,exploitmod.DESCRIPTION)
                    inserted = True
                if "Post-Intrusion" in exploitmod.affectsList:
                    insert_row( model, postintrustionIter, name, exploitmod.DESCRIPTION)
                    inserted = True
                if "Fuzzers" in exploitmod.affectsList:
                    insert_row(model,fuzzersIter,name,exploitmod.DESCRIPTION)
                    inserted = True
                if exploitmod.affectsList == []:
                    # XXX yo write comment about what is happening here please.
                    # it seems the module is inserted as ghost (not GUI-reachable)
                    inserted = True

            """
                # hack when we dunno where to add it, for debugging purpose only
                if len(property.keys()) and not inserted:
                    lostIter = self.Iter("LOST")
                    if lostIter == None:
                        lostIter = self.addIter(model, ("LOST", None, None, "Lost files", 1))
                    insert_row(model,lostIter,name,exploitmod.DESCRIPTION)
                    #inserted = True
                    print "inserted LOST %s" % name
                    print property
                """

            # </transition>

            # was module inserted ?
            try:
                assert inserted, "no affectsList? missing/broken PROPERTY in module %s?"%name
            except AssertionError, m:
                print m
                continue

            # if a module is inserted, we can handle it now
            self.handlers[name]=exploitmod
            self.handlers[name, 'ext'] = exploitmodExt

            # <very common variables can be set only 1 time to clear the code> (do we need them???)
            if not hasattr(exploitmod, 'GTK2_DIALOG'):
                exploitmod.GTK2_DIALOG = "dialog.glade2"
            #if not hasattr(exploitmod, 'runExploit'):
            if True: # XXX temporary
                exploitmod.runExploit = canvasengine.runExploit
            if not hasattr(exploitmod, 'runAnExploit_gtk2'):
                #exploitmod.runAnExploit_gtk2 = canvasengine.runAnExploit_gtk2
                exploitmod.runAnExploit_gtk2 = runAnExploit_gtk2
            if hasattr(exploitmod, 'theexploit') and not hasattr(exploitmod.theexploit, 'name') and \
               hasattr(exploitmod, 'NAME'):
                exploitmod.theexploit.name = exploitmod.NAME # needed in cmdline exploits? <- ? we are in GUI XXX
            # </very common variables that are very boring...>
            TODO = """
                 del self.handlers[name]
                 canvasengine.delModule(name)
                 del exploitmod
                 del exploitmodExt
                 """

        # here all modules have been added to the tree

        # TODO: if a branch is not handled and is empty (no leaf) it's maybe better to remove it
        #       actually it's easier to only create a branch if it the leaf already exists

        # TODO: reorder numalpha (Windows esp)

        # move "All" leaf to top of branch
        reorder_model(model)

        #Set this so other modules know we've done the work...
        canvasengine.registeredallmodules=1
        ctree.set_headers_visible(True)

        ctree.set_model(model)

        renderer=gtk.CellRendererText()
        column=gtk.TreeViewColumn("Name",renderer, text=0)
        column.set_resizable(True)
        ctree.append_column(column)
        renderer=gtk.CellRendererText()

        column=gtk.TreeViewColumn("Description",renderer, text=1, background=2)
        column.set_resizable(True)
        ctree.append_column(column)
        ctree.show()
        #print "PATH: %s"%sys.path
        #sys.stdout.flush()
        return

    def add_image(self, obj, show):
        pixbuf = gtk.gdk.pixbuf_new_from_xpm_data(show)
        pixmap, mask=pixbuf.render_pixmap_and_mask()
        image = gtk.Image()
        image.set_from_pixmap(pixmap, mask)
        image.show()
        obj.remove(obj.get_children()[0])
        obj.add(image)

    def hide_dump(self, obj):
        if self.hide_dump: 
            self.dumpscroll.show()
            self.logpaned.set_position(500)
            self.hide_dump=0
            self.add_image(obj, self.hide)
        else:
            self.dumpscroll.hide()
            self.logpaned.set_position(989)
            self.hide_dump=1
            self.add_image(obj, self.show)

    #these two wrappers enable the engine to do async socket IO
    #without importing GTK itself
    def input_add(self,fd,activity,callback):
        devlog('canvasgui::asyncsockio', "Input add called. fd=%s" % fd)
        try:
            fno=fd.fileno()
            devlog('canvasgui::asyncsockio', "adding fd %d to input_add list" % fno)
        except:
            return
        result=gtk_input_add_hook(fd,activity,callback)
        devlog('canvasgui::asyncsockio', "result=%d" % result)
        return result

    def input_remove(self,id):
        devlog('canvasgui::asyncsockio', "Removing %d from input_add" % id)
        return gtk.input_remove(id)

    def target_button(self, obj):
        """
        Target button was clicked
        """
        devlog("gui","target button clicked")
        self.nodegui.on_selected("Set as target host", 
                                 "Set as additional target host")
        return 

    def add_target_button(self, obj):
        devlog("gui", "add_target_button_clicked")
        self.nodegui.on_selected("Set as additional target host")
        return 

    def remove_target_button(self, obj):
        devlog("gui", "remove_target_button_clicked")
        self.nodegui.on_selected("Unset as targeted host")
        return 


    def getSelectedHost(self):
        model,iter=self.hostsview.get_selection().get_selected()
        if iter==None:
            return (None,None,None)
        host=model.get_value(iter,0)
        os=model.get_value(iter,1)
        status=model.get_value(iter,2)
        return (host,os,status)

    def getSelectedExploit(self):
        """
        This is the bottom window in the CANVAS gui

        We return which exploit is currently selected (or None)

        This returns an actual EXPLOIT, not an ID
        """
        #print "Getting selected Listener"
        model,iter=self.listenertreeview.get_selection().get_selected()
        if iter==None:
            return None
        lst=model.get_value(iter,0)
        return lst

    def getSelectedListenerIPandPort(self,type):
        """
        returns the selected listener's host and port, if it matches the type
        """
        lst=self.getSelectedListener()
        if lst==None:
            return (None,None)

        listenertype=lst.getType()
        if type!= "" and listenertype!=type:
            return (None,None)
        listenerport=int(lst.getPort())
        return (self.localip,listenerport)

    ##################################################################################
    #EVENT HANDLERS

    # related to the data view tab

    def dataview_press(self, obj, event):

        #print "ON_DATAVIEW_PRESS"

        if event.button == 3:
        #if event.type == gtl.gdk.BUTTON_PRESS:

            x = int(event.x)
            y = int(event.y)

            try:
                path, col, colx, celly= obj.get_path_at_pos(x,y)
            except TypeError:
                return
            obj.grab_focus()
            obj.set_cursor(path, col, 0)

            imenu = gtk.Menu()

            delrow = obj.get_selection().get_selected()
            menu_item = gtk.MenuItem("Delete Row")
            menu_item.connect("activate",self.DataView_Delete_Row , delrow)
            menu_item.show()
            imenu.append(menu_item)

            menu_item = gtk.MenuItem("Save to File")
            menu_item.connect("activate",self.DataViewSave , obj)
            menu_item.show()
            imenu.append(menu_item)

            imenu.show()
            imenu.popup(None,None, None,event.button, event.time)

    def DataView_Delete_Row(self, widget, delrow):

        model, iterr = delrow
        if iterr:
            model.remove(iterr)

    def DataViewSave(self, widget, obj):

        file_dialog = gtk.FileChooserDialog('Save Data View...', None, gtk.FILE_CHOOSER_ACTION_SAVE, ('gtk-cancel', gtk.RESPONSE_CANCEL,
                                                                                                      'gtk-save',gtk.RESPONSE_OK))
        file_dialog.set_do_overwrite_confirmation(True)
        ifil = self.targetip + "_" + self.set_module_name + ".txt"
        file_dialog.set_current_name(ifil)
        ifolder = path=os.path.join(os.getcwd(),"Your_Documents")
        file_dialog.set_current_folder(ifolder)
        file_dialog.set_select_multiple(False)
        file_dialog.set_local_only(True)
        if gtk.RESPONSE_OK == file_dialog.run():
            file_name = file_dialog.get_filename()
            FILE = open(file_name,"w")
            model = obj.get_model()
            n_columns = model.get_n_columns()
            iter = model.get_iter(0)
            while iter:
                if n_columns==1:
                   FILE.write(model.get_value(iter,0)+"\r\n")
                else:# more that one column
                    line = ""
                    for i in range(n_columns):
                        line += model.get_value(iter,i)
                        if i < n_columns - 1: # dont add , at end line
                            line += ","
                    FILE.write(line+"\r\n")
                iter = model.iter_next(iter)
            FILE.flush()
            FILE.close()
        file_dialog.destroy()
        
    ##Rich mod to SRF code
    def build_meta_data_dictionary(self):
        """
        Mash together the PROPERTY and DOCUMENTATION dictionaries from all exploits and set a variable
        Only done the first time called, otherwise return the dictionary already made
        Dictinary is keyed on module object, with 
        """
        ##Has the dictionary already been built?
        if not self.search_dict:
            self.search_dict={}
            for name in canvasengine.registeredModuleList():
                
                exploitmod = canvasengine.getModule(name)
                self.search_dict[exploitmod]={}
    
                if hasattr(exploitmod, "PROPERTY"):
                    self.search_dict[exploitmod].update(exploitmod.PROPERTY)
                if hasattr(exploitmod, "DOCUMENTATION"):
                    self.search_dict[exploitmod].update(exploitmod.DOCUMENTATION)
                if hasattr(exploitmod, "__name__"):
                    self.search_dict[exploitmod].update({"MODULE NAME":exploitmod.__name__})
                ##Remove empty enires as will save us loop iterations later when comparing
                if not self.search_dict[exploitmod]:
                    del self.search_dict[exploitmod]
                            
                ##alphbetise the order of the modules for prettyness
                self.ordered_exploit_list=self.search_dict.keys()
                self.ordered_exploit_list.sort()
                
                #print self.search_dict[exploitmod]["ALL"]

    def search_modules(self, obj):

        search_combo_val = ""
        search_text = ""

        search_combo = self.wTree.get_widget("combobox_search")
        model = search_combo.get_model()
        index = search_combo.get_active()
        if index:
            search_combo_val = model[index][0]

        search_text = self.wTree.get_widget("entry_search").get_text()

        # check for empty vals
        if search_text == "" or search_combo_val == "":
            return

        model = gtk.ListStore(gobject.TYPE_STRING, gobject.TYPE_STRING)
        self.searchtreeview.set_model(model)
        model.clear()

        counter = 0

        if search_combo_val == "OS": # OS & ARCH are the same...
            search_combo_val = "ARCH"

        if not self.search_dict:
            self.build_meta_data_dictionary()
            
        ##Rich mod
        ##TODO standard str wildcard suppoort 
        for exploitmod in self.ordered_exploit_list:
                
            property=self.search_dict[exploitmod]
            
            if not property:
                ##Exploit module has no meta data keys
                continue

            if property.has_key(search_combo_val):
                

                if (self.wTree.get_widget("radiobutton_search_raw").get_active()): # raw search

                    if isinstance(property[search_combo_val],list):
                        for v in property[search_combo_val]:
                            if isinstance(v,list):
                                for v1 in v:
                                    #if search_text.lower() == v1.lower():
                                    if search_text.lower() in v1.lower():
                                        myiter=model.insert(counter)
                                        model.set_value(myiter,0,exploitmod.__name__)
                                        model.set_value(myiter,1,exploitmod.NAME)
                                        counter += 1
                                        continue                                
                            else:
                                if isinstance(v,str):
                                    #if v.lower() == search_text.lower():
                                    if v.lower() in search_text.lower():
                                        myiter=model.insert(counter)
                                        model.set_value(myiter,0,exploitmod.__name__)
                                        model.set_value(myiter,1,exploitmod.NAME)
                                        counter += 1
                                        continue
                    else:
                        #if type(property[search_combo_val]) == type("") and property[search_combo_val].lower() == search_text.lower():
                        if type(property[search_combo_val]) == type("") and search_text.lower() in property[search_combo_val].lower():
                            myiter=model.insert(counter)
                            model.set_value(myiter,0,exploitmod.__name__)
                            model.set_value(myiter,1,exploitmod.NAME)
                            counter += 1
                            continue
                    
                else: # regex search

                    if isinstance(property[search_combo_val],list):
                        for v in property[search_combo_val]:
                            if isinstance(v,list):
                                for v1 in v:
                                    r = re.compile(search_text,re.IGNORECASE)
                                    m = r.search(v1)
                                    if m:
                                        myiter=model.insert(counter)
                                        model.set_value(myiter,0,exploitmod.__name__)
                                        model.set_value(myiter,1,exploitmod.NAME)
                                        counter += 1
                                        continue                                
                            else:
                                if isinstance(v,str):
                                    r = re.compile(search_text,re.IGNORECASE)
                                    m = r.search(v)
                                    if m:
                                        myiter=model.insert(counter)
                                        model.set_value(myiter,0,exploitmod.__name__)
                                        model.set_value(myiter,1,exploitmod.NAME)
                                        counter += 1
                                        continue
                    else:
                        r = re.compile(search_text,re.IGNORECASE)
                        m = r.search(property[search_combo_val])
                        if m:
                            myiter=model.insert(counter)
                            model.set_value(myiter,0,exploitmod.__name__)
                            model.set_value(myiter,1,exploitmod.NAME)
                            counter += 1
                            continue
                        
        myiter=model.insert(counter)
        model.set_value(myiter,0,"-- %d results for that query --"%(counter))
                
        return

    # ripped / modify from module_treeview
    def searchtree_press(self,obj,event):
        if event.type==gtk.gdk._2BUTTON_PRESS:
            model,iter=obj.get_selection().get_selected()
            if iter==None:
                return

            value = model.get_value(iter,0)
            nodetext=self.node_resolv(model.get_value(iter,0))

            if value in self.moduletreeCallbacks.keys():                
                self.moduletreeCallbacks[value]()

            if not self.handlers.has_key(nodetext):
                self.handlers[nodetext] = canvasengine.getModule(nodetext, True)

            if self.handlers.has_key(nodetext):
                #exploit modules which are in their own directories
                m = self.handlers[nodetext]
                gladefile = os.path.join(os.path.dirname(m.__file__), m.GTK2_DIALOG)                    
                self.display_exploit_dialog(nodetext,gladefile=gladefile)

                self.set_module_name = nodetext
        return

    # ripped / modify from columns_changed
    def search_columns_changed(self, treeview):
        """
        This goes through each of the documentation fields in a module
        and loads it into the documentation view
        """
        model,iter = self.selection1.get_selected()
        if iter == None:
            devlog('gtk', "weird - nothing was selected, yet we got a single click")
            return
        nodetext = self.node_resolv(model.get_value(iter,0))
        try:
            module=self.handlers[nodetext]

            # XXX: this returns a tuple! (showdoc, csvdoc)
            showdoc = canvasengine.html_docs_from_module(module)[0]

            #devlog("gui","Inserting text with markup: %s"%showdoc)
            self.documentationwindow.set_text("")
            #this does an almost HTML-like insertion
            showdoc = str(showdoc).replace("\"","\'") # for consistency
            # replace existing newlines, because <br>'s should be set in html_docs_from_module
            showdoc = str(showdoc).replace("\\n", "")
            insert_text_with_markup(self.documentationwindow,"<docs>" + showdoc + "</docs>")
        except KeyError:
            #unknown node...we ignore it because it's one of our headers
            pass
        except:
            import traceback
            traceback.print_exc(file=sys.stderr)
            self.documentationwindow.set_text("")

    def commandline_entry_key_press(self, obj, event):
        """
        We bound this event to handle up and down arrow keys to implement
        history
        
        Returns True to break inheritance if it was an arrow key, otherwise
        returns False to continue processing of keystroke 
        """
        if gtk.gdk.keyval_name(event.keyval) not in ["Up","Down"]:
            return False #we don't handle this
        if gtk.gdk.keyval_name(event.keyval)=="Up":
            #print "Up Arrow Pressed %d"%self.current_cl_history
            if self.current_cl_history>=len(self.commandline_history):
                #we are trying to go up past the last item in the history
                return True #we handled it, nothing to do
            
            if self.current_cl_history==0:
                #save this off 
                self.commandline_editing=self.commandline_entry.get_text() 

            self.current_cl_history+=1
            #zeroth item is the current commandline
            new_commandline=self.commandline_history[self.current_cl_history-1]
        elif gtk.gdk.keyval_name(event.keyval)=="Down":
            #print "down arrow pressed: %d"%self.current_cl_history
            if self.current_cl_history==0:
                #already at the bottom
                return True 
            #otherwise, choose a lower value
            self.current_cl_history-=1
            if self.current_cl_history==0:
                #we have reached the bottom, time to use the saved commandline
                new_commandline=self.commandline_editing
            else:
                new_commandline=self.commandline_history[self.current_cl_history-1]
                
        #here we set the text with our new commandline
        self.commandline_entry.set_text(new_commandline)
        #move cursor to end
        self.commandline_entry.set_position(-1)
        
        return True 
        
    def commandline_entry_activate(self, obj):
        self.commandline=self.commandline_entry.get_text()
        self.commandline_entry.set_text("")
        self.current_cl_history=0
        self.commandline_editing=""
        # do something with self.commandline
        #print "Using commandline: %s" % self.commandline
        #prepend our new commandline
        self.commandline_history.insert(0, self.commandline)
        t=Thread(target=self.mycanvasengine.run_commandline, args=(self.commandline,))
        t.setDaemon(True)
        t.start()
        self.commandline = ''
        return 

    # hack to support different names for the same node
    def node_resolv(self, nodename):
        if self.handlers.has_key(nodename):
            return nodename
        elif self.handlers_multinames.has_key(nodename):
            return self.handlers_multinames[nodename]
        else:
            devlog('gtk', "can not find unknown node %s" % nodename)
            return "unknown node"

    def columns_changed(self, treeview):
        """
        This goes through each of the documentation fields in a module
        and loads it into the documentation view
        """
        model,iter = self.selection.get_selected()
        if iter == None:
            devlog('gtk', "weird - nothing was selected, yet we got a single click")
            return
        nodetext = self.node_resolv(model.get_value(iter,0))
        try:
            module=self.handlers[nodetext]

            # XXX: this returns a tuple! (showdoc, csvdoc)
            showdoc = canvasengine.html_docs_from_module(module)[0]

            #devlog("gui","Inserting text with markup: %s"%showdoc)
            self.documentationwindow.set_text("")
            #this does an almost HTML-like insertion
            showdoc = str(showdoc).replace("\"","\'") # for consistency
            # replace existing newlines, because <br>'s should be set in html_docs_from_module
            showdoc = str(showdoc).replace("\\n", "")
            insert_text_with_markup(self.documentationwindow,"<docs>" + showdoc + "</docs>")
        except KeyError:
            #unknown node...we ignore it because it's one of our headers
            pass
        except:
            import traceback
            traceback.print_exc(file=sys.stderr)
            self.documentationwindow.set_text("")

    # THIS HANDLES THE STATUS WINDOW .. NOT ANY ACTUAL CANVAS LISTENERS!

    # 1. listener_treeview is collected from window1 (base new gui)
    # 2. on_listener_treeview_button_press connected to listener_press

    def listener_press(self, obj, event):
        # on double click .. show the loggedInformation (if any) for the module

        # double click pulls up the log for that specific module
        if event.type == gtk.gdk._2BUTTON_PRESS:

            # LISTENER TREE VIEW REPRESENTS THE STATUS WINDOW!
            model,iter  = self.listenertreeview.get_selection().get_selected()
            if iter == None:
                return

            # module lives at the 0th column :>
            module  = model.get_value(iter, 0)
            name    = ''
            if hasattr(module, 'loggedInformation'):
                text    = '\n'.join(module.loggedInformation)
                if hasattr(module, 'name'):
                    name    = module.__module__    
            else:
                text    = ''
            
            # get the window .. via the glade hop through
            wTree           = gtk_glade_hook.XML(get_glade_file(), 'module_log_window')
            window_view     = wTree.get_widget('module_log_window')
            text_window     = wTree.get_widget('module_log_text')
            # set a text buffer for the text
            tb              = gtk.TextBuffer()
            text_window.set_buffer(tb)
            iter            = tb.get_end_iter()
            mark            = tb.create_mark("end", tb.get_end_iter(), False)

            tb.insert(iter, text)
            text_window.scroll_to_mark(mark, 0.05, True, 0.0, 1.0)
            window_view.set_title('Module log %s' % name)
            window_view.show()

    def moduletree_press(self,obj,event):
        """
        You no longer have to edit this every time you add a new module to the gui
        """
        devlog("gtk::gui","treeview for modules clicked")
        if event.type==gtk.gdk._2BUTTON_PRESS:
            devlog("gui", "Double Click in moduletree_press()")
            model,iter=self.moduletree.get_selection().get_selected()
            if iter==None:
                devlog('gtk', "weird - nothing was selected, yet we got a double-click")
                return

            value = model.get_value(iter,0)
            nodetext=self.node_resolv(model.get_value(iter,0))                    

            #sel=self.moduletree.get_selection_info(event.x,event.y)
            #self.moduletree.select_row(sel[0],sel[1])
            #node=self.moduletree.selection[0]
            #nodetext=self.moduletree.get_node_info(node)[0]
            #print "Clicked on "+nodetext

            # FIXME: probably incomplete list here
            # maybe better to check if node is branch or leaf
            devlog('gtk', "nodetext: %s"%nodetext)
            if value in self.moduletreeCallbacks.keys():                
                self.moduletreeCallbacks[value]()
            elif nodetext in ["Unix","Windows","Exploits","Recon","DoS","Helium","Listener Shells","unknown node"]:
                pass


            elif nodetext=="Listener-Shell":
                self.do_listener_shell(self.mycanvasengine.passednodes[0])

            else:
                if not self.handlers.has_key(nodetext):
                    self.handlers[nodetext] = canvasengine.getModule(nodetext, True)

                if self.handlers.has_key(nodetext):
                    #exploit modules which are in their own directories
                    m = self.handlers[nodetext]
                    gladefile = os.path.join(os.path.dirname(m.__file__), m.GTK2_DIALOG)                    
                    self.display_exploit_dialog(nodetext,gladefile=gladefile)

                #################################################
                ##### Gui broken?!?
                #####
                else:
                    print 'canvasgui', "Node %s not handled yet" % nodetext
                    devlog('canvasgui', "Node %s not handled yet" % nodetext)

                self.set_module_name = nodetext

        devlog("gtk::gui","End of moduletree press")
        return

    def launch_filesystem_browser(self, node):
        """
        Launches a window that browses the remote file system
        """
        self.mycanvasengine.log("Launching Filesystem Browser")

        wTreeTmp    = gtk_glade_hook.XML(get_glade_file() ,"filesystembrowser")
        wid         = wTreeTmp.get_widget("filesystembrowser")
        browser     = browser_window(node, self, self.mycanvasengine, wTreeTmp)

        return

    def do_listener_shell(self, node):
        """
        Creates a Listener-Shell window, attaches the events
        This shell is a CANVASNode - by default, the current run_on node,
        but if this is being called by the engine after a successful exploit
        than it's whatever new Node was created by that exploit or callback
        """

        self.mycanvasengine.log("Doing a Listener-Shell")

        #first connect the signal handlers
        wTreeTmp=gtk_glade_hook.XML(get_glade_file() ,"listenershell")
        #print "wTreeTmp=%s"%wTreeTmp

        # set the host info for that listener shell
        hostinfo    = wTreeTmp.get_widget('listenershell')
        hostid      = ''

        if node.nodetype.upper() in ['LINUXNODE', 'WIN32NODE', 'SOLARISNODE', 'BSDNODE', 'OSXNODE']:
            try:
                hostid  = "%s" % node.get_interesting_interface()
            except:
                import traceback
                traceback.print_exc(file=sys.stdout)
                pass

        hostinfo.set_title('Listener Shell - ' + hostid)

        wid=wTreeTmp.get_widget("listenershell")
        downloadest=wTreeTmp.get_widget("list_entry")
        uploadsrc=wTreeTmp.get_widget("list_entry")
        #print "wid=%s"%wid
        dic= {"on_piped_clicked": (self.listenerdialog_runcommand,wTreeTmp,node),
              "on_pwd_clicked": (self.listenerdialog_pwd, wTreeTmp,node),
              "on_cd_clicked": (self.listenerdialog_cd, wTreeTmp,node),
              "on_download_clicked":(self.listenerdialog_download, wTreeTmp,node),
              "on_upload_clicked":(self.listenerdialog_upload, wTreeTmp,node),
              "on_dir_clicked":(self.listenerdialog_dir, wTreeTmp,node),
              "on_unlink_clicked":(self.listenerdialog_unlink, wTreeTmp,node),
              "on_spawn_clicked":(self.listenerdialog_spawn, wTreeTmp,node),
              "on_destdir_browse_clicked": (self.browsebutton, downloadest, "localfolder"),
              "on_uploadsrc_browse_clicked": (self.browsebutton, uploadsrc, "local"),
              "on_cancel_clicked": wid.destroy,
              "gtk_widget_destroy": wid.destroy}
        wTreeTmp.signal_autoconnect (dic)
        #print "After signal connect"
        tb=gtk.TextBuffer(None)
        #print "Got text buffer"
        wid=wTreeTmp.get_widget("text10")
        #print "text10"
        wid.set_buffer(tb)
        #print "wid set buffer"
        #ok, set buffer now
        return

    def killall_listeners(self, obj):
        list=self.listenertreeview.get_model()
        for a in list:
            if a.iter==None:
                continue
            listenerid=int(self.node_resolv(list.get_value(a.iter, 0)))
            lst=self.mycanvasengine.getListenerByID(listenerid)
            if lst==None:
                continue
            lst.closeme()
            self.mycanvasengine.removeListener(lst)
            self.input_remove(lst.getGtkID())
        return 

    def kill_listener(self,obj):
        """
        Forcefully closes a listener or listener
        """
        self.mycanvasengine.log("Killing a Listener")

        lst=self.getSelectedListener()
        if lst==None:
            self.mycanvasengine.log("No listener selected() for killing")
            return
        lst.closeme()
        self.mycanvasengine.removeListener(lst)
        self.input_remove(lst.getGtkID())

        return

    def halt_bruteforce(self, obj):
        """
        Halt Bruteforcing
        """
        self.mycanvasengine.log("Halting exploit")        
        lst=self.getSelectedExploit()
        if hasattr(lst, "halt") and callable(lst.halt):
            lst.halt()
        else:
            self.mycanvasengine.log("Halting Brute Force is only for exploits")        
        return 

    def new_listener_dialogue(self,obj):
        #print "Starting a new listener"

        wTree2 = gtk_glade_hook.XML(get_glade_file() ,"newlistener_dialog")
        dialog = wTree2.get_widget("newlistener_dialog")

        options=canvasengine.getAllListenerOptions()
        option_menu=wTree2.get_widget("optionmenu1")

        menu = gtk.Menu()                # create a menu
        for str in options:                 # fill our menu with the options
            menu_item = gtk.MenuItem(str)
            #menu_item.connect("activate",    # attach "str" to widget
            #              on_optionmenu_activate, str) 
            menu_item.show()                 # don't forget this here
            menu.append(menu_item)
        #option_menu = gtk.GtkOptionMenu()   # create the optionmenu
        option_menu.set_menu(menu)          # add the menu into the optionmenu
        response=dialog.run()
        if response==gtk.RESPONSE_OK:
            self.newListener(dialog,wTree2)
        dialog.destroy()
        return

    def do_callzeroexit(self):
        """
        Calls 0 - this will most likely exit the listener
        """
        lst=self.getSelectedListener()
        if lst==None:
            self.mycanvasengine.log("No listener selected()")
            return
        listenertype=lst.getType()

        if listenertype!="Active":
            self.mycanvasengine.log("Selection is not an Active listener!")
            return

        self.removeListener(lst.getID())
        self.mycanvasengine.removeListener(lst)
        self.input_remove(lst.getGtkID())
        lst.callzero()
        print "Called zero (gui)"
        return

    def do_autorecon(self):
        """
        Calls 0 - this will most likely exit the listener
        """
        lst=self.getSelectedListener()
        if lst==None:
            self.mycanvasengine.log("No listener selected()")
            return
        listenertype=lst.getType()

        if listenertype!="Active":
            self.mycanvasengine.log("Selection is not an Active listener!")
            return
        lst.autorecon()
        return

    def do_fixheap(self):
        """
        Tries to fix the heap on that listener - needed
        for some heap overflow exploits
        """

        lst=self.getSelectedListener()
        if lst==None:
            self.mycanvasengine.log("No listener selected()")
            return
        listenertype=lst.getType()

        if listenertype!="Active":
            self.mycanvasengine.log("Selection is not an Active listener!")
            return
        lst.fixheap()
        return 

    def do_exitprocess(self):
        """
        calls exit process on the selected listener
        """

        lst=self.getSelectedListener()
        if lst==None:
            self.mycanvasengine.log("No listener selected()")
            return
        listenertype=lst.getType()
        if listenertype!="Active":
            self.mycanvasengine.log("Selection is not an Active listener!")
            return
        listenerid=lst.getID()
        self.mycanvasengine.log("Calling exit process on listener id %d"%listenerid)
        lst.runexitprocess()
        return 

    def play(self,var):
        if canvasengine.CanvasConfig['sound']:
            canvasengine.sound.play(var)

    def browsebutton(self,event,destination,typestr):
        """typestr is local, localfolder or remote (not yet supported)
        """
        #dictionary used for GTK actions
        actiondict={}
        actiondict["localfolder"]=gtk.FILE_CHOOSER_ACTION_SELECT_FOLDER
        #local dialogs are here
        if typestr in ["local","localfolder"]:
            action=actiondict.get(typestr,gtk.FILE_CHOOSER_ACTION_OPEN)
            chooser = gtk.FileChooserDialog(title="Choose local file",action=action,
                                            buttons=(gtk.STOCK_CANCEL,gtk.RESPONSE_CANCEL,gtk.STOCK_OPEN,gtk.RESPONSE_OK))
            ret=chooser.run()
            if ret==gtk.RESPONSE_OK:
                filename=chooser.get_filename()
                print "Filename=%s!"%filename
                chooser.destroy()
                destination.set_text(filename)
            else:
                #assume cancel was clicked
                chooser.destroy()
        else:
            print "Dialog of type %s not understood!"%typestr

        return

    def gtk_ok_response(self, obj, dialog):
        """
        Dialog boxes are different - they have a run() function which
        loops a gtk.mainloop() to look for GTK Response codes being emitted.
        
        For addhost and other things where you want to explicitly handle
        enter or another keystroke, this will send that dialog the GTK Response code.
        """
        dialog.response(gtk.RESPONSE_OK)
        return 
    
    def display_exploit_dialog(self, name, gladefile="canvasgui2.glade", notarget=0):
        import threading 
        #print "display_exploit_dialog Currentthread: %s"%threading.currentThread()
        #print "Event Peek: %s"%gtk.gdk.event_peek()
        threadcheckMain() #should always run in main thread

        dname="%s_dialog"%name

        #print self.mycanvasengine.target_host
        try:
            target_ip = self.mycanvasengine.target_hosts[0].interface     
        except AttributeError:
            target_ip="127.0.0.1"
        try:
            #print "Dialog Name=%s"%dname
            #print "Gladefile=%s"%gladefile
            if self.dialogs.has_key(dname):
                #print "Cached dialog"
                exploitdialog=self.dialogs[dname]
                wTree2= self.wTree2Dict[dname]
            else:
                #print "Uncached dialog"
                if self.handlers.has_key(name):
                    _tname = "exploit_dialog"
                else:
                    _tname = dname

                wTree2 = gtk_glade_hook.XML(gladefile, _tname)
                exploitdialog = wTree2.get_widget(_tname)
                if exploitdialog == None:
                    print "DID NOT FIND DIALOG - FATAL ERROR: %s" % dname
                    # FIXME: fatal error -> raise SystemExit/AssertionError ?
                self.dialogs[dname]=exploitdialog
                self.wTree2Dict[dname]=wTree2
            exploitdialog.hide()
            
            #realize it to prevent deadlock when updating it!
            exploitdialog.realize()
            exploitdialog.show()
            
            # if available, set target/local IP in exploit/tool dialog
            # new gui has engine.target_host set
            if target_ip:
                for widget_name in ["entry1", "target_ip", "target_entry"]:
                    target_ip_widget = wTree2.get_widget(widget_name)
                    if target_ip_widget and type(target_ip_widget) == gtk.Entry:
                        target_ip_widget.set_text(target_ip)
            if hasattr(self, 'localip') and self.localip:
                for widget_name in ["entry2", "callback_entry", "local_ip"]:
                    local_ip_widget = wTree2.get_widget(widget_name)
                    if local_ip_widget and type(local_ip_widget) == gtk.Entry:
                        local_ip_widget.set_text(self.localip)

            #browse button code
            #TODO: remote browse windows
            for b in ["local","remote"]:
                #for each kind of possible browse window
                for c in ["source","dest","filename","uploadsrc"]:
                    buttonname="%s_browsebutton_%s"%(b,c)
                    button=wTree2.get_widget(buttonname)
                    if button:
                        #print "Button found %s!"%buttonname
                        for destination_name in ["%sentry"%c,c,"sourceentry"]:
                            #search among possible destination names based on our "c" variable
                            destination=wTree2.get_widget(destination_name) #sourceentry or destentry
                            if destination:
                                #print "Destination Name: %s"%destination_name
                                break
                        #try both signalnames
                        signalname="on_%s_%s_browsebutton_clicked"%(b,c)
                        signalname2="on_%s_browsebutton_%s_clicked"%(b,c)
                        #print "Signalname: %s"%signalname
                        
                            
                        connectdict={signalname: (self.browsebutton,destination,b) }
                        connectdict[signalname2]= (self.browsebutton,destination,b) 

                        wTree2.signal_autoconnect(connectdict)
            #end browse button code

            #now add the on_enter_clicked thing for addhost/etc
            mod=self.mycanvasengine.getModuleExploit( name )
            signalname3="on_enter_clicked"
            connectdict={}
            connectdict[signalname3]= (self.gtk_ok_response,exploitdialog)                    
            wTree2.signal_autoconnect(connectdict)
            
            # Now determine if there is a callback in the module
            # that dynamically sets text fields in the GUI
            
            try:
                if mod.gui_update:
                    elements = mod.gui_hook_function()

                    for element in elements:
                        target_widget = wTree2.get_widget( element[0] )

                        if target_widget and type( target_widget ) == gtk.Entry:
                            target_widget.set_text( element[1] )
            except AttributeError:
                pass
                        

            # hot update of gtk dialog from exploit
            if hasattr(self, 'handlers') and self.handlers.has_key(name) and hasattr(self.handlers[name], 'dialog_update'):
                devlog("gui", "Adding handler: %s"%name)
                self.handlers[name].dialog_update(gtk, wTree2)

            # align exploit

            exploitdialog.set_position(gtk.WIN_POS_CENTER_ALWAYS)            
            exploitdialog.show_all()
            # LEAVE THIS SLEEP IN FOR NOW, TESTING FOR BUG!!!!!!!
            #Sleep taken out...if random freezes occure, then put it back in!
            time.sleep(0.3)
            # LEAVE THIS SLEEP IN FOR NOW, TESTING FOR BUG!!!!!!!
            devlog("gui", "Before exploitdialog. set_transient_for()")
            exploitdialog.set_transient_for(self.window)
            devlog("gui", "Running exploitdialog")
            #print "Event Peek: %s"%gtk.gdk.event_peek()
            done=False 
            """
            There's a tricky bug that you see people having where a dialog
            will pop in and then immediately dissapear when they run any
            exploit. This is something wrong with GTK that we don't understand
            yet, and the only known solution is to sleep() before you call exploitdialog.run()

            We sleep() a small amount for every event we see in the event queue.
            I'm sensing a problem with this code that is really annoying - dialogs
            are not setting netmask (or other properties) 
            """
            #while not done:
                #event=gtk.gdk.event_get()
                #if not event:
                    #done=True 
                #del event 
                #time.sleep(0.001)
            #print "Event Peek: %s"%gtk.gdk.event_peek()
            response=exploitdialog.run()
            devlog("gui","After exploitdialog.run()")
            devlog("gui","Serving exploit dialog")
            devlog("gui","Hiding dialog")
            exploitdialog.hide()
            if response == gtk.RESPONSE_OK:
                try:
                    self.runAnExploit(exploitdialog,name,wTree2,target_ip)
                except:
                    self.mycanvasengine.log("WARNING: Unhandled Exception caught in exploit...")
                    import traceback
                    print '-'*60
                    traceback.print_exc(file=sys.stdout)
                    print '-'*60
        except:
            import traceback
            print '-'*60
            traceback.print_exc(file=sys.stdout)
            raise

        #print "Done here123"
        return

    def runAnExploit(self,widget,name,wTree2,host):
        """
        This routine calls the runAnExploit_gtk2 routine, which eventually ends
        up in canvasengine.py::runExploit().

        This will be called by the main thread, so it can't block.
        """

        if self.handlers.has_key(name):
            # we rely on create new listener for new gui
            # localip for callback is now engine.callback_interface.ip
            # set os to "", we don't use defaultos anyways
            bugtracker(self.handlers[name].runAnExploit_gtk2, \
                       widget, wTree2, self.mycanvasengine, self.handlers[name])
            return
        else:
            self.mycanvasengine.log("Didn't recognize that exploit: %s !"%name)

        return

    def setListenerInfo(self,listener):
        """
        Should only be called from main thread

        This is what updates an exploit's progress bar
        and text.
        """
        devlog("gui::exploittree", "Setting exploit info: %s"%listener.name)
        model=self.listenerlistmodel
        #myiter=listener.gtkIter.copy()
        #don't need to reset this...
        #model.set_value(myiter,0,listener)
        start=model.get_iter_root()
        if not start:
            devlog("gui::exploittree", "Model is empty!")
            return 
        #is this function using huge amounts of CPU?
        myiter=newgui.findobj_sibling(model, listener, start)
        if not myiter:
            devlog("gui","Could not find object %s in our tree!"%listener.name)
            return 
        p=Progress()
        image=p.set(self.window, listener.getProgress() )
        #print listener.getProgress(), listener.name, listener.getInfo(), "\n\n\n"
        model.set_value(myiter,1, image)
        model.set_value(myiter,2,listener.getAction())
        model.set_value(myiter,3,listener.getStartTime())
        model.set_value(myiter,4,listener.getEndTime())        
        model.set_value(myiter,2,listener.getInfo())
        model.row_changed(model.get_path(myiter),myiter)

        return

    def registerNewExploit(self,exploit):
        """
        Called by engine
        listener is a listener type
        """
        devlog("gui::exploittree", "Registering new listener in listener window! %s"%exploit.name)
        model=self.listenerlistmodel
        tree= self.listenertreeview
        #add this gui as the exploit's main gui!
        exploit.gui=self

        path, column = tree.get_cursor()

        if not hasattr(exploit, "parent"):
            #this should never happen: all hostlisteners have parents!
            exploit.parent=None 

        if exploit.parent==None:
            myiter=model.insert_after(None,None)
        else:
            #this is a child - if we have children
            #but there is nothing in our tree already
            #then we have some sort of error and return None
            #this happens for the initial addhosts() 
            start=model.get_iter_root() 
            #get_iter_first only returns the first object
            #whereas we really want to return the top of the tree
            #start=None 
            #print "start=%s"%start
            parentiter=None
            if start:
                #we do have at least one object in our tree
                parentiter=newgui.findobj_sibling(model,exploit.parent,start)
            if parentiter:
                devlog('gui::exploittree', "Found parent of exploit")
            else:
                devlog('gui::exploittree', "No parent exploit found {Not adding}")
                return 
            myiter=model.insert_after(parentiter,None,row=None)
                #print "before 0"

        p=Progress()
        image=p.set(self.window, exploit.getProgress())            
        model.set_value(myiter,0,exploit) #invisible!        
        model.set_value(myiter,1, image)

        if not hasattr(exploit, "name"):
            exploit.name=str(type(exploit))
        exploit.setAction("%s RUNNING"%exploit.name)
        model.set_value(myiter, 2, exploit.getAction())
        model.set_value(myiter, 3, exploit.getStartTime())
        model.set_value(myiter, 4, str(""))

        model.set_value(myiter, 5 ,exploit.getInfo())        
        new_path = model.get_path(myiter)

        #tree.scroll_to_cell(new_path, column, True, 0.5, 0.5)
        #print "set value"
        #send a reference to the GUI values to the listener
        exploit.setGTKModel(self, model, myiter.copy())
        devlog("gui::exploittree", "returning from adding a new exploit to our tree")
        return 

    def removeListener(self,id):
        """
        removes a row from the listener list
        """
        c=self.listenerlistmodel
        foundrow=-1
        iter=c.get_iter_first()

        while iter!=None:
            if c.get_value(iter,0)==str(id):
                foundrow=1
                c.remove(iter)
                break
            iter = c.iter_next(iter)

        if foundrow==-1:
            print "Didn't find the row with id %d"%id
        else:
            print "Listener %d removed from gui"%id

        return

    def newListener(self,widget,tree):
        """
        This method is called when OK is clicked in the new listener dialogue
        """
        option_menu=tree.get_widget("optionmenu1")
        port=int(tree.get_widget("spinbutton1").get_value())
        fromcreatethread = int(tree.get_widget("fromcreatethread").get_active())
        self.mycanvasengine.log("From createthread set to: %s" % bool(fromcreatethread))
        self.mycanvasengine.log("New Listener Port selected is %d"%port)
        listenertype=option_menu.get_children()[0].get()
        self.mycanvasengine.log("New Listener Selected listenertype is %s"%listenertype)
        #this needs to be done in a new thread or we can block while doing this, killing our gui
        newthread=Thread(target=self.mycanvasengine.start_listener, args=(None,listenertype,port,fromcreatethread))
        newthread.start()

        return

    def target_entry_changed(self, obj):
        self.targetip = self.wTree.get_widget("target_entry").get_text()
        if self.mycanvasengine != None:
            self.mycanvasengine.log("New target IP=%s"% self.targetip)
        return

    def callback_entry_changed(self,obj):
        self.localip=self.wTree.get_widget("callback_entry").get_text()
        if self.mycanvasengine!=None:
            self.mycanvasengine.log("New local IP=%s"%self.localip)
        return

    ########
    def listener_log(self,wTree2,message):
        self.mycanvasengine.openlogfile()
        self.mycanvasengine.writetologfile(message)

        devlog('gtk::gui::listener_log', "wTree2=%s, message=%s" % (wTree2, [message]))
        if not wTree2:
            import traceback
            devlog('all', "listener_log() call with wTree2=None! anti-deadlock activated!")
            traceback.print_stack(file=sys.stdout)
            return

        wid=wTree2.get_widget("text10")
        if wid==None:
            print "Serious error, can't find text widget!"
            # FIXME: nothing else then returning?
            return

        buffer = wid.get_buffer()
        iter = buffer.get_end_iter()

        message = iso8859toascii(message)

        try:
            wid.get_buffer().insert(iter, message, len(message))
        except:
            wid.get_buffer().insert(iter, message)

        buffer = wid.get_buffer()
        mark = buffer.create_mark("end", buffer.get_end_iter(), False)

        wid.scroll_to_mark(mark,0.05,True,0.0,1.0)

        return

    #################################################################
    #LISTENER SHELL DIALOG CALLBACKS
    #these are special because the output has to go into another window
    def listenerdialog_pwd(self,wid,wTree2,shell):
        #self.mycanvasengine.log( "Doing pwd on listener id %d"%id)
        self.mycanvasengine.pwd(shell,wTree2)
        #self.listener_log(wTree2,"Current working directory is: [%s]\n"%shell.result)
        return

    def listenerdialog_runcommand(self,wid,wTree2,id):
        #self.mycanvasengine.log("Doing command on listener id %d"%id)
        command=wTree2.get_widget("list_entry").get_text()
        result=self.mycanvasengine.runcommand(id,wTree2,command)
        return 

    def listenerdialog_cd(self,wid,wTree2,id):
        #self.mycanvasengine.log("Doing cd command on listener id %d"%id)
        dir=wTree2.get_widget("list_entry").get_text()
        result=self.mycanvasengine.runcd(id,wTree2,dir)
        return

    def listenerdialog_download(self,wid,wTree2,id):
        #self.mycanvasengine.log("Doing command on listener id %d"%id)
        source=wTree2.get_widget("list_entry").get_text()
        dir= "" # wTree2.get_widget("entry8").get_text()
        result=self.mycanvasengine.rundownload(id,wTree2,source,dir)
        return

    def listenerdialog_upload(self,wid,wTree2,id):
        #self.mycanvasengine.log("Doing upload command on listener id %d"%id)
        source=wTree2.get_widget("list_entry").get_text()
        result=self.mycanvasengine.runupload(id,wTree2,source)
        return

    def listenerdialog_dir(self,wid,wTree2,id):
        #self.mycanvasengine.log("Doing dir command on listener id %d"%id)
        source=wTree2.get_widget("list_entry").get_text()
        result=self.mycanvasengine.rundir(id,wTree2,source)
        return

    def listenerdialog_unlink(self,wid,wTree2,id):
        #self.mycanvasengine.log("Doing unlink command on listener id %d"%id)
        source=wTree2.get_widget("list_entry").get_text()
        result=self.mycanvasengine.rununlink(id,wTree2,source)
        return

    def listenerdialog_spawn(self,wid,wTree2,id):
        #self.mycanvasengine.log("Doing spawn command on listener id %d"%id)
        source=wTree2.get_widget("list_entry").get_text()
        result=self.mycanvasengine.runspawn(id,wTree2,source)
        return

    ## Exploit Pack Info Window stuff
    def setupExploitPackWindow(self):
        self.exploitPackWTree = gtk_glade_hook.XML(get_glade_file(), "windowExploitPack")
        w = self.exploitPackWTree.get_widget("windowExploitPack")

        signals = {"on_button1_clicked": self.hideExploitPackWindow }
        self.exploitPackWTree.signal_autoconnect(signals)

        vb = self.exploitPackWTree.get_widget("vboxMain")
        # Treestore model longName, version, path, is-a-demo
        ts = gtk.TreeStore(str, str, str, str)
        for ep in canvasengine.exploitPacks.itervalues():
            ts.append(None, [ep.longName, "%s (%s)" % (ep.version, ep.isDemo() and "Demo" or "Full"), ep.path, ep.name] )
        tv = gtk.TreeView(ts)

        tvc = gtk.TreeViewColumn("Name")
        tv.append_column(tvc)
        cell = gtk.CellRendererText()
        tvc.pack_start(cell, True)       
        tvc.add_attribute(cell, 'text', 0)

        tvc = gtk.TreeViewColumn("Version")
        tv.append_column(tvc)
        cell = gtk.CellRendererText()
        tvc.pack_start(cell, False)
        tvc.add_attribute(cell, 'text', 1)

        tvc = gtk.TreeViewColumn("Path")
        tv.append_column(tvc)
        cell = gtk.CellRendererText()
        tvc.pack_start(cell, False)
        tvc.add_attribute(cell, 'text', 2)

        tv.get_selection().connect("changed", self.handleExploitPackTreeSelectionChanged)
        tv.get_selection().select_path("0")

        tv.show()

        vb.pack_start(tv, False, True)

    def handleExploitPackTreeSelectionChanged(self, tvs):
        model, iter = tvs.get_selected()
        epname = model.get_value(iter, 3)
        ep = canvasengine.exploitPacks[epname]
        self.setupExploitPackNotebook(ep)

    def setupExploitPackNotebook(self, ep):
        infoFields = [("Name", "name"),
                      ("Long Name", "longName"),
                      ("Version", lambda x: "%s (%s)" % (x.version, x.isDemo() and "Demo" or "Full")),                      
                      ("Path", "path"),
                      ("Author", "author"),
                      ("URL", "contactUrl"),
                      ("Email", "contactEmail"),
                      ("Phone", "contactPhone")]

        vbInfo = gtk.VBox()        
        tbInfo = gtk.Table(rows=len(infoFields), columns=2, homogeneous=False)

        i = 0
        for l,v in infoFields :
            x = gtk.Label()
            x.set_markup("<b>%s:</b>" % l)        
            x.set_alignment(1.0,0.5)
            y = gtk.Label(callable(v) and v(ep) or getattr(ep, v))
            y.set_alignment(0.0,0.5)            
            x.show()
            y.show()
            tbInfo.attach(x, 0, 1 , i, i+1, gtk.FILL)
            tbInfo.attach(y, 1, 2, i, i+1, gtk.FILL|gtk.EXPAND)
            i+=1
        tbInfo.set_col_spacings(5)
        vbInfo.pack_start(tbInfo, False, True)        
        tbInfo.show()
        vbInfo.show()

        # Read README and LICENSE
        vbReadme = gtk.VBox()
        vbLicense = gtk.VBox()

        for widget,fn in [(vbReadme, ep.readme), (vbLicense, ep.license)]:

            sw = gtk.ScrolledWindow()
            sw.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
            tv = gtk.TextView()
            tb = tv.get_buffer()
            sw.add(tv)
            sw.show()
            tv.show()
            fo = open(fn, "r")
            try:
                data = unicode(fo.read())
            except UnicodeDecodeError,i:
                data = "Error reading %s, file is not valid UTF-8. (%s)" % (fn, i)
            fo.close()           
            tb.set_text(data)
            widget.pack_start(sw, True, True)
            widget.show()


        nb = gtk.Notebook()
        nb.set_name("nb")
        nb.append_page(vbInfo, gtk.Label("Info"))
        nb.append_page(vbReadme, gtk.Label("Readme"))
        nb.append_page(vbLicense, gtk.Label("License"))

        nb.show()

        vb = self.exploitPackWTree.get_widget("vboxMain")
        if hasattr(self, "exploitPackWindowNB"):
            vb.remove(self.exploitPackWindowNB)
        vb.pack_end(nb)
        self.exploitPackWindowNB = nb

    def showExploitPackWindow(self):
        w = self.exploitPackWTree.get_widget("windowExploitPack")
        w.show()

    def hideExploitPackWindow(self, x):

        w = self.exploitPackWTree.get_widget("windowExploitPack")
        w.hide()
        if not os.path.exists(canvasengine.EXPLOITPACK_LICENSE_FLAG):
            try:
                fo = open(canvasengine.EXPLOITPACK_LICENSE_FLAG, "w")
                fo.write("yup")
                fo.close()
            except IOError, i:
                self.log("Error creating %s: %s" % (canvasengine.EXPLOITPACK_LICENSE_FLAG, i))            

class Progress:
    xpm_data = [
        "34 12 7 1",
        "  c None",
        ". c #000000",
        "1 c #bcbcbc",
        "2 c #bcbcbc",
        "3 c #bcbcbc",
        "4 c #bcbcbc",
        "5 c #bcbcbc",
        " ....   ....   ....   ....   .... ",
        ".1111. .2222. .3333. .4444. .5555.",
        ".1111. .2222. .3333. .4444. .5555.",
        ".1111. .2222. .3333. .4444. .5555.",
        ".1111. .2222. .3333. .4444. .5555.",
        ".1111. .2222. .3333. .4444. .5555.",
        ".1111. .2222. .3333. .4444. .5555.",
        ".1111. .2222. .3333. .4444. .5555.",
        ".1111. .2222. .3333. .4444. .5555.",
        ".1111. .2222. .3333. .4444. .5555.",
        ".1111. .2222. .3333. .4444. .5555.",
        " ....   ....   ....   ....   .... "
    ]
    def __init__(self):
        self.onbar= "#5448ec"
        self.offbar="#bcbcbc"
        self.badbar="#ff0000"

    def setOn(self, color):
        self.onbar=color

    def setOff(self, color):
        self.offbar=color

    def setBad(self,color):
        self.badbar=color

    def set(self, window, progress): # progress is a percentage
        on=self.onbar
        if progress==0xba5:
            for a in range(0, 5):
                import random
                # Back to the 60's! Flower Power, LSD is on the air
                self.xpm_data[a+3]="%d c #%06x" % (a+1, random.randrange(0, 0xffffff))
            return gtk.gdk.pixbuf_new_from_xpm_data(self.xpm_data)
        elif progress > 100:
            progress=100
        elif progress < 0:
            progress=100
            on=self.badbar

        amount=int(progress/20)
        for a in range(0, amount):
            self.xpm_data[a+3]="%d c %s" % (a+1, on)
        for a in range(amount, 5):
            self.xpm_data[a+3]="%d c %s" % (a+1, self.offbar)
        #pixmap, mask= gtk.gdk.pixmap_create_from_xpm_d(window.window,\
        #                                            None,
        #                                            self.xpm_data)
        #image=gtk.Image()
        image=gtk.gdk.pixbuf_new_from_xpm_data(self.xpm_data)
        #image=gtk.gdk.Pixbuf.render_pixmap_and_mask(pixmap, mask)
        #image.set_from_pixmap(pixmap, mask)
        return image


def canvasguimain(init_threads=True):
    _gui_init_ts = time.time()
    mycanvasgui=canvasgui()
    devlog('all', "initialized GUI time: %ss" % (time.time() - _gui_init_ts))

    #hmmm
    if init_threads:
        try:
            gtk.gdk.threads_init()
        except:
            print "No threading was enabled when you compiled pyGTK!"
            sys.exit(1)
    gtk.gdk.threads_enter()
    try:
        gtk.main()
    except:
        gtk.mainloop ()

    gtk.gdk.threads_leave()


                                                                                                     