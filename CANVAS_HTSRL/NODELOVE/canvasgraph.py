#!/usr/bin/env python

## CANVAS Node Graphing v0.1-beta
##
## South Beach, Miami, 2007

## Standard GTK loading
import sys
if '.' not in sys.path:
    sys.path.append('.')
    
import os
import time

try:
    import pygtk
    pygtk.require("2.0")
except:
    pass

try:
    import gtk
    import gtk.gdk
    import gtk.glade
except:
    sys.exit(1)
    
import gobject
import cairo

# exploitutils.py dependency for target mapping ...
from exploitutils import check_reserved

## __dict__ will have a nice name:handler dict for the class ;)
class SignalHandlers:
    """ Provides the signal handler dict for our interface """
    
    def on_exit_clicked(event):
        gtk.main_quit()
    
    def on_GraphWindow_destroy(event):
        gtk.main_quit()
        
    def destroy(event):
        gtk.main_quit()
        
class NodePopupHandlers:
    """ provides Knowledge and Interfaces handlers for our nodes """
    
    def on_Knowledge_clicked(menu, item):
        print "Handling knowledge click"
        print repr(menu)
        print repr(item)
        
    def on_Interfaces_clicked(menu, item):
        print "Handling interfaces click"
        print repr(menu)
        print repr(item)
    
## Signal handlers for node events (clicky clicky on the nodes)
class NodeHandlers:
    """ Provides event handlers unrelated to drawing """
    
    def test_event(widget, event):
        print "[XXX] got 'event' .. dumping widget and event ..."
        print repr(widget)
        print repr(event)
        return False

class NodeLayout:
    """ Provides a base shell layout we can use to draw shiznit """
    
    def __init__(self):
        import array
        self.array = array # we only use the array function
        
    def has_node(self, nodes, node):
        """ checks if node n is in nodelist nodes """
        for n in nodes:
            if n['title'] == node['title']:
                return True
        return False
    
    def set_layout(self, nodes, edges=[], center_x=0, center_y=0, type='shell'):
        """ sets the positioning coordinates in a list of CANVASGraph nodes """
        
        if type == 'grid':
            vpos = self.layered_canvas_layout(nodes)
            for node in nodes:
                try:
                    node['x'] = vpos[node['title']][0] * 200 # width 125, space 25
                    node['y'] = vpos[node['title']][1] * 150 # height 75, space 25
                except:
                    import traceback
                    traceback.print_exc(file=sys.stderr)
                    raise Exception, 'no known position for node: %s (are you trying to use non-CANVAS nodes?)'% node['title']             
        else:
            raise Exception, 'unknown layout type for set_layout'

        return nodes
    
    # ONLY FOR CANVAS, ASSUMES NODE CONTAINER HAS A CANVAS NODE
    def layered_canvas_layout(self, nodes):
        """ simplified layered rooted tree graph """
        
        # a vertex v that has a depth of layer i, has a y(v) of -i
        # e.g. root of tree v has layer depth 0, so y coord of 0
        # child of root of tree v has layer depth so y coord of -1
        # 
        # deduce the n of layers from the node.parent depth

        # work out the layer position for each node
        layer = {}
        vpos = {}
        for node in nodes:
            if node['container']:
                CANVASNode = node['container']
                y = 0 # start at parent layer
                while CANVASNode.parent != None:
                    CANVASNode = CANVASNode.parent.parent
                    print "Adding layer for node: %s"% node['title']
                    y += 1 # -i .. but whatev
                # set the layer list
                if y in layer.keys():
                    layer[y].append(node['title'])
                else:
                    layer[y] = [node['title']]
                    
        # work out the x vpos coordinates for each node, y is layer
        
        for node in nodes:
            if node['container']:
                for y in layer.keys():
                    if node['title'] in layer[y]:
                        x = layer[y].index(node['title'])
                        # x and y are now both known :>
                        vpos[node['title']] = self.array.array('i', [x, y])
        
        #print repr(vpos)
        return vpos
            
## Show nodes on our glade canvas ..
class NodeCanvas(gtk.DrawingArea):
    """ Everything to do with drawing nodes in a CANVAS node graph """

    # RGB palette
    PALETTE = {}
    PALETTE['black'] = (000, 000, 000)
    PALETTE['white'] = (255, 255, 255)
    PALETTE['red'] = (255, 000, 000)
    PALETTE['green'] = (000, 255, 000)
    
    def __init__(self):
        super(NodeCanvas, self).__init__()
    
        # unmask GDK events we want .. in our case we need clicky clicky support
        self.add_events(gtk.gdk.BUTTON_PRESS_MASK)

        # connect event callbacks ..
        self.connect('expose-event', self.on_expose_event)
        self.handlerid = self.connect('button-press-event', self.on_button_press_event)
        
        # list of displayed nodes (dicts)
        self.nodes = []
        # list of edges between nodes (tuples)
        self.edges = []
        # we want a grid of rows and columns for node display
        # dimensions are 100x50 for a node .. leave 25 x space and 50 y space between nodes
        self.overlapProtection = False
        self.center = [0, 0]

        return
    
    def redraw(self):
        """ redraw drawing area """
        self.queue_draw()
        return
    
    def on_button_press_event(self, widget, event):
        # use the event.area to determine if a node was clickered

        x = event.x
        y = event.y
        
        #print "XXX: button press (x: %d, y: %d)"% (event.x, event.y)
        
        for node in self.nodes:
            if x in range(node['x'], node['width'] + node['x']) \
               and y in range(node['y'], node['height'] + node['y']):
                self.handleNodeClick(node, event.button, event.time)
                
        return
        
    def on_expose_event(self, widget, event):
        """ The display event """
        
        #print self.window.get_size()
        
        # 1. get a cairo context
        ctx = self.window.cairo_create()
        
        # 2. limit cairo to the actual event area
        ctx.rectangle(event.area.x, event.area.y, event.area.width, event.area.height)
        ctx.clip()
        #ctx.rectangle(0, 0, *self.window.get_size())
        
        # 3. draw nodes and edges
        self.drawVertices(ctx)
        self.drawEdges(ctx)
        
        return False
    
    # XXX: testing function
    def menuHandlerTest(self, widget, event):
        print "XXX: menu handler called !"
        return
    
    def handleNodeClick(self, node, button, time):
        """ Handle clicks on nodes """

        # eventually we'll link the actual CANVAS callbacks into this
        
        title = 'NODE[%s]'% node['title']
        # 1 is left, 2 is middle, 3 is right
        if  button == 1:
            print "Left click ... " + title
        elif button == 2:
            print "Middle click ... " + title
        elif button == 3:
            print "Right click ... " + title
            # pop up an option menu ... eventually replace
            # with actual CANVAS muckery for a Node
            menu = gtk.Menu()
            items = ['Knowledge', 'Interfaces']
            for item in items:
                mLine = gtk.MenuItem(item)
                # connect to our popup handling class ...
                mLine.connect('activate', NodePopupHandlers.__dict__['on_%s_clicked'%item], item)
                mLine.show()
                menu.append(mLine)
            menu.show()
            menu.popup(None, None, None, button, time)
            
        return
    
    def addEdge(self, src, dst):
        """ Add an edge tuple to the global edges list """
        
        self.edges.append((src, dst))
        return self.edges
    
    def drawEdges(self, ctx):
        """ Walk the edge list and draw them """
        
        for edge in self.edges:
            self.drawEdge(ctx, edge[0], edge[1])
        return
    
    def drawEdge(self, ctx, src, dst):
        """ draw a connecting line between two nodes based on title """
        nodeA = None
        nodeB = None
        
        for node in self.nodes:
            if node['title'] == src:
                nodeA = node
            elif node['title'] == dst:
                nodeB = node
        
        if None in [nodeA, nodeB]:
            raise Exception, 'did not find both src/dst for drawEdge'
        
        # connect the middle bottom of src to the middle top of dst
        r, g, b = self.PALETTE['red']
        ctx.set_source_rgb(r, g, b)
        
        # move pointer to middle bottom of src
        src_x = nodeA['x'] + nodeA['width']/2
        src_y = nodeA['y'] + nodeA['height']
        ctx.move_to(src_x, src_y)
        
        # !!! remember the pointer is now relative to src_x and src_y
        
        # draw the line from the middle bottom of src to the middle top of dst
        # eventually we want to move through a grid so we can control layout properly
        dst_x = (nodeB['x'] + nodeB['width']/2) - src_x
        dst_y = (nodeB['y']) - src_y
        ctx.rel_line_to(dst_x, dst_y)
        
        # reset the pointer
        ctx.move_to(self.center[0], self.center[1])
        
        # draw the shiznit
        ctx.stroke()
        
        return

    # set default node dimensions here in width and height
    def addVertex(self, title, label, x, y, width=125, height=75, container=None):
        """ Adds a node to the node display list """
        
        # make sure there is no node overlap (toggable)
        if self.overlapProtection == True:
            for node in self.nodes:
                if x in range(node['x'], node['width']) or y in range(node['y'], node['height']):
                    print "Alert: node overlap detected !!!"
                    raise Exception, 'node overlap error'
                
        # every vertex gets a 'container' that is None .. which can be used to store any additonal
        # data we want to associate with the vertex that is specific to the application it's used in
        # e.g. in CANVAS 'container' will point to a classic nodetree structure :>
        self.nodes.append({ 'title' : title, 'label' : label, 'x' : x, 'y' : y,\
                            'width' : width, 'height' : height, 'container' : container })
        # trigger a redraw here ...
        return self.nodes
    
    def drawVertex(self, ctx, title, label, x, y, width, height, outline='white'):
        """ Draw a single node on the canvas """
        
        r, g, b = self.PALETTE[outline]
        ctx.set_source_rgb(r, g, b)
        ctx.rectangle(x, y, width, height)
        ctx.stroke()
        
        # Add text to the node
        fontsize = 12
        r, g, b = self.PALETTE['red']
        ctx.set_source_rgb(r, g, b)
        
        # Select the font
        ctx.select_font_face('Sans', cairo.FONT_SLANT_NORMAL, cairo.FONT_WEIGHT_NORMAL)
        ctx.set_font_size(fontsize)

        # Place the pointer inside the box (fontsize*n where n is line number)
        # y controls the lines, x the indent ..
        ctx.move_to(x+fontsize/2, y+fontsize*2)
        ctx.show_text('ID: %s'% title)
        r, g, b = self.PALETTE['white']
        ctx.set_source_rgb(r, g, b)
        
        label = label.split('\n')
        n = 3
        for line in label:
            #print "XXX: grap label debug: " + repr(line)
            if line != '':
                ctx.move_to(x+fontsize/2, y+fontsize * n)
                ctx.show_text('%s'%line)
                n += 1
        
        ctx.set_line_width(2.0)
        
        # reset to center of canvas
        ctx.move_to(self.center[0], self.center[0])

        # Display the text
        ctx.stroke()
        
        return
        
    def drawVertices(self, ctx):
        """ Draw all nodes on the canvas """
        
        # set background
        r, g, b = self.PALETTE['black']
        ctx.set_source_rgb(r, g, b)
        ctx.rectangle(0, 0, *self.window.get_size()) # tuple * to (w, h)
        ctx.fill()
        
        # walk the node display list
        for node in self.nodes:
            color = 'white'
            # XXX: keep at white until i figure out display bug ..
            #selected = False
            if node['container']: # node container available
                if hasattr(node['container'], 'amselected') == True and node['container'].amselected:
                    color = 'red' # selected nodes
            #        selected = True
                    
            self.drawVertex(ctx, node['title'], node['label'],\
                          node['x'], node['y'], node['width'], node['height'], outline=color)
            
        return
            
            
    def delVertex(self, title):
        """ remove a node from node list and edges """
        
        print "Removing node: %s"% title
        for node in self.nodes:
            if node['title'] == title:
                self.nodes.remove(node)
        for edge in self.edges:
            if title in list(edge):
                self.edges.remove(edge)
        # redraw the screen ...
        self.redraw()
        return

## CANVAS Graphing Display Testing class
class CanvasGraphTest:
    """ Test Graphing CANVAS Nodes onto a cairo canvas """

    def __init__(self, width, height):
        # Grab widget tree from the GLADE XML
        self.wTree = gtk.glade.XML('graph_base.glade')
        
        # Connect the signal handlers
        self.wTree.signal_autoconnect(SignalHandlers.__dict__)
        
        # Init main window from GLADE
        self.window = self.wTree.get_widget('GraphWindow')
        
        # Init the canvas handler
        self.canvas = self.wTree.get_widget('CanvasFrame')
        self.canvas.set_size_request(width, height)
        
        # Add our cairo canvas widget to the target frame
        self.graph = NodeCanvas()
        self.canvas.add(self.graph)
        
        # Show the window + frame
        self.window.show_all()
        
    def run(self):
        gtk.main()

class MapCanvas(gtk.DrawingArea):
    """ Everything to do with drawing nodes in a CANVAS node target map """

    # RGB palette
    PALETTE = {}
    PALETTE['black'] = (000, 000, 000)
    PALETTE['white'] = (255, 255, 255)
    PALETTE['red'] = (255, 000, 000)
    PALETTE['green'] = (000, 255, 000)
    
    def __init__(self, map):
        self.check_reserved = check_reserved
        super(MapCanvas, self).__init__()
        
        self.local_width = 0 # width of the local network part of the map
    
        self.GeoIP = None
        # UNIX
        if 'WIN32' not in sys.platform.upper():
            try:
                import GeoIP
                # you need a current
                try:
                    db_path = 'NODELOVE' + os.sep + 'GeoLiteCity.dat'
                    #db_path = 'GeoLiteCity.dat'
                    self.GeoIP = GeoIP.open(db_path, GeoIP.GEOIP_STANDARD)
                except SystemError, err:
                    print "[X] GeoIP / GeoIP Lite City database is not available .."
                    # fall back to regular GeoIP .. no long/lat info
                    self.GeoIP = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
            except ImportError, err:
                pass
        # WIN32
        else:
            # use the com object for Win32 CANVAS Platforms
            try:
                import win32com.client
                try:
                    # for version >= 1.2 of the Win32 COM Object
                    db_path = '.' + os.sep + 'NODELOVE'
                    self.GeoIP = win32com.client.Dispatch("GeoIPCOMEx.GeoIPEx")
                    self.GeoIP.set_db_path(db_path)
                except:
                    print "[X] GeoIP COM Object for Win32 not available ... see NODELOVE/README.TXT for INSTALL Instructions"
            except ImportError, err:
                print "[X] Win32 extensions for Python not installed ..."
                
        if self.GeoIP == None:
            print "[X] See CANVAS/NODELOVE/README.TXT on how to enable full Mapping support .."
        
        # init the map surface object
        self.map = map
        
        # unmask GDK events we want .. in our case we need clicky clicky support
        self.add_events(gtk.gdk.BUTTON_PRESS_MASK)

        # connect event callbacks ..
        self.connect('expose-event', self.on_expose_event)
        self.handlerid = self.connect('button-press-event', self.on_button_press_event)
        
        # list of displayed nodes (dicts)
        self.nodes = []
        # list of edges between nodes (tuples)
        self.edges = []
        # we want a grid of rows and columns for node display
        # dimensions are 100x50 for a node .. leave 25 x space and 50 y space between nodes
        self.overlapProtection = False
        self.center = [0, 0]
        
        # dict of host dicts
        self.hosts = {}
        return
    
    def add_host(self, ip):
        """ add a new host to the hosts array by ip .."""
        if self.GeoIP==None:
            #no GeoIP Available, so just bail
            return 
        print "[!] Trying to add %s to target map .."% ip
        if self.check_reserved(ip) == True:
            print "[!] Skipping Reserved/Local IPs for now .."
            
        # skip IPv6 ips for now too
        elif ':' in ip:
            print "[!] Skipping IPv6 IP for IPv4 database .."
        
        elif ip not in self.hosts.keys():
            x = 0
            y = 0
            # if geoip available
            if self.GeoIP != None:
                x, y = self.get_geoip(ip)
                
            host = { 'x' : x, 'y' : y, 'ip' : ip, 'click_handler' : None, 'target' : False, 'target_line' : None, 'children' : {} }
            # if no overlap, add as unique ip
            if self.detect_overlap_add(host) == False:
                self.hosts[ip] = host
            
        else:
            print "[!] host key %s already exists"% ip
            
        return
    
    def detect_overlap_add(self, c_host):
        """ detects if an added host overlaps with an existing host point """
        c_x = c_host['x']
        c_y = c_host['y']
        for key in self.hosts.keys():
            p_host = self.hosts[key]
            # width and height == 5
            p_x = p_host['x']
            p_y = p_host['y']
            # we can decide that neighbouring ip's should be grouped too
            # for now we just do same-city IP's
            if c_x == p_x and c_y == p_y:
                print "[X] Same city IP detected .. adding to additional hosts dict for parent IP"
                self.hosts[key]['children'][c_host['ip']] = c_host
                return True
        return False
        
    def del_host(self, ip):
        """ delete a host by ip """
        
        self.hosts.__delitem__(ip)
        return
    
    def degrees_to_coord(self, lo, la):
        """ transforms longitude/latitude to map coordinates using simple projection logic """
        
        # 2048x1024 world maps .. simple translation .. will cause distortion near poles
        
        # ratio multipliers for map size ..
        m_x = 5.6888888888888891 # approx
        m_y = 5.6888888888888891 # approx

        # -180 -> 0 <- 180 .. x .. 90 -> 0 <- -90 .. y ..
        
        x = (180 + lo) * m_x # works for -- and +
        y = (90  - la) * m_y # works for -- and +

        # we dont really care about float precision .. 
        # we're doing rough visualisation
        
        x = int(x)
        y = int(y)
        
        x += self.local_width
        
        print "[X] translated degrees to projection map coordinates: %d,%d"% (x, y)
        return (x, y)
    
    def get_geoip(self, addr):
        """ get geoip long/lat/etc. records for an ip address """
        gir = {}
        lo = 0 #longitude
        la = 0 #latitude

        # XXX: make better fallback coord layout logic
        coord = (0, 0)
        
        if self.GeoIP != None:
            lo = 0
            la = 0
            
            try: # they like to throw random SystemError
                # geoip is available
                print "[!] querying GeoIP database for %s"% addr
                
                # UNIX and WIN32 GeoIP API differ !
                if 'WIN32' in sys.platform.upper():
                    if self.GeoIP.find_by_addr(addr) == True:
                        lo = self.GeoIP.longitude
                        la = self.GeoIP.latitude
                    else:
                        print "[X] Could not load GeoIP Database for COM object"
                # UNIX
                else:
                    gir = self.GeoIP.record_by_addr(addr)
                    print "[!] dumping GeoIP information for %s"% addr
                    print repr(gir)
                    if 'longitude' in gir and 'latitude' in gir:
                        lo = gir['longitude']
                        la = gir['latitude']
                        
                print "[!] converting degrees to coordinate"
                coord = self.degrees_to_coord(lo, la)
            except:
                print "[X] unable to query GeoIP database type (country/city mismatch?)"
                # disable GeoIP so we don't keep throwing these errors
                self.GeoIP = None
                
        return coord
    
    def redraw(self):
        """ redraw drawing area """
        self.queue_draw()
        return
    
    # this gets reconnected/replaced in newgui.py with the actual object gui handler's version
    def on_button_press_event(self, widget, event):
        print "PLACEHOLDER: on_button_press_event"
        return
     
    def drawHosts(self, ctx):
        """ test drawing host markers """

        if self.GeoIP == None:
            nogeoip = "The CANVAS World Map requires the\nthird party GeoIP libraries.\nPlease read the NODELOVE/README.TXT\nfile for installation details."
            maxw = 0
            totalh = 0
            # Ummm, surely this is what pango is for?
            lines = nogeoip.split("\n")
            for n in lines:
                x_b, y_b, w, h, x_a, y_a = ctx.text_extents(n)
                maxw = max(w, maxw)
                totalh += h
                
            x = 20
            y = 20
            linegap = h * 0.3
            lineheight = h
            w = maxw
            h = totalh + (linegap * len(lines))
            border = 10
            r,g,b = self.PALETTE["red"]
            ctx.set_source_rgb(r,g,b)
            ctx.rectangle(x, y, w + (2*border), h + (2*border))
            ctx.stroke()
            
            r, g, b = self.PALETTE['white']
            ctx.set_source_rgb(r, g, b)
            for i,n in enumerate(lines):
                ctx.move_to(x + border, y + border + ((i +1 )* lineheight) + (i * linegap))
                ctx.show_text(n)
                ctx.stroke()
            
        else:
            
    
            # immunityinc.com miami beach coordinates
            w = 5
            h = 5
            
            for host_key in self.hosts.keys():
                host = self.hosts[host_key]
                
                # fill in coordinates here ..
                if not host['x'] and not host['y']:
                    host['x'], host['y'] = self.get_geoip(host['ip'])
                    self.hosts[host_key] = host
                    
                x = host['x']
                y = host['y']
                
                # multiple hosts available is green
                if len(host['children']):
                    print "[!] Multiple hosts available .. switching palette to green .."
                    r, g, b = self.PALETTE['green']
                else:
                    r, g, b = self.PALETTE['white']
                    
                # targeting superseeds multiple hosts
                if host['target'] == True:
                    r, g, b = self.PALETTE['red']
                    
                ctx.set_source_rgb(r, g, b)
                ctx.rectangle(x, y, w, h)
                ctx.fill()
            
                ctx.move_to(x+(w*2), y+h)
            
                # tags are white text
                r, g, b = self.PALETTE['white']
                    
                ctx.set_source_rgb(r, g, b)
                ctx.show_text(host['ip'])
                ctx.stroke()
        
        return ctx
        
    def on_expose_event(self, widget, event):
        """ The display event """
        
        # 1. get a cairo context and show the map on it
        ctx = self.window.cairo_create()
        # do the map PNG muck
        ctx.rectangle(0, 0, self.map.get_width(), self.map.get_height())
        ctx.set_source_surface(self.map, 0, 0)
        ctx.fill()
        
        self.drawHosts(ctx)       
        return False
    
    def pop_up_menu(self, item_handlers, button, time):
        """ pop up menu .. item_handlers is a {} of 'item' : handler() """

        # pop up an option menu ... eventually replace
        # with actual CANVAS muckery for a Node
        menu = gtk.Menu()
        for item in item_handlers:
            mLine = gtk.MenuItem(item)
            # connect to our popup handling class ...
            mLine.connect('activate', item_handlers[item], item)
            mLine.show()
            menu.append(mLine)
            
        menu.show()
        menu.popup(None, None, None, button, time)
        return
    
## CANVAS Graphing Display Testing class
class MapCanvasTest:
    """ Test Graphing CANVAS Nodes onto a cairo canvas """

    def __init__(self):
        # Grab widget tree from the GLADE XML
        self.wTree = gtk.glade.XML('graph_base.glade')
        
        # Connect the signal handlers
        self.wTree.signal_autoconnect(SignalHandlers.__dict__)
        
        # Init main window from GLADE
        self.window = self.wTree.get_widget('GraphWindow')
        
        # Init the canvas handler
        self.canvas = self.wTree.get_widget('CanvasFrame')
        
        map = cairo.ImageSurface.create_from_png('base_map.png')
        self.canvas.set_size_request(map.get_width(), map.get_height())
        
        # Add our cairo canvas widget to the target frame
        self.graph = MapCanvas(map)
        self.canvas.add(self.graph)
        
        # Show the window + frame
        self.window.show_all()
        
    def run(self):
        gtk.main()

### main - for testing
if __name__ == "__main__":
    print "## CANVAS GRAPH TESTING v0.1"
    
    test = MapCanvasTest() # width, height
    #test.graph.addVertex('1', 'test', 0, 0)
    #test.graph.addVertex('2', 'test', 0, 0)
    #test.graph.addVertex('3', 'test', 0, 0)
    #test.graph.addEdge('1', '2')
    #test.graph.addEdge('1', '3')
    
    # test the layout algo (fills in the x and y we want for each node)
    #test.graph.nodes = NodeLayout().set_layout(test.graph.nodes, edges=test.graph.edges, type='grid')

    # display
    test.run()
