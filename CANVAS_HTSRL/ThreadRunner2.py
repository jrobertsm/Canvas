##ThreadRunner2 - Not all sequels suck......
##New threading logic for CANVAS exploits

import Queue, time, random, thread, traceback, copy
from threading import Thread
##Easy alias for locking
lock=thread.allocate_lock()

from exploitutils import *

AUTHOR="rich"
NOTES="""
Version 1 - 25/11/08
"""
class ThreadTracker(Thread):
    """
    Keep track of where all our child threads are in their run and make it accessible to 
    ThreadRunner2 in a thread safe way
    """
    def __init__(self, track_q, kill_signal="!DIE!"):
        """
        Set up our state
        """
        ##Do the thread dance
        Thread.__init__(self)
        ##The queue down which the child threads will update us on their progress
        self.q=track_q
        ##Table to track IP and child thread mappings
        self.thread_table={}
        ##Q down which to chuck the results from the modules executed in the child threads
        ## this will be consumed by a method in the main canvasexploit instance (or sub class of it like massattack2)
        self.result_q=Queue.Queue(0)
        ##Magic word to make us exit our tracking loop
        self.kill_signal=kill_signal
        
    def run(self):
        """
        Main data process loop
        """
        while 1:
            t_update=self.q.get()
            
            ##Have we been instructed to exit ?
            if t_update == self.kill_signal:
                self.q.task_done()
                break
            
            self.process_update(t_update)
            
            ##Signal we have processed the data
            self.q.task_done()
            
    def process_update(self, data):
        """
        Parse and use update data from child threads
        """    
        opt, thread_obj = data
            
        if opt == "register":
            ##New thread kicked off add to the thread table for accounting purposes
            lock.acquire()
            self.thread_table[thread_obj.target.interface]=[thread_obj,"Spawning Thread"]
            lock.release()        
        elif opt in ["killed", "error", "exception", "failure", "success", "dead"]:
            ##Thread finished, this should be called from the cleanup method in ThreadWrapper
            lock.acquire()
            ##Put the result into the q which is consumed by the canvasexploit which called us
            self.result_q.put((thread_obj, opt, thread_obj.result ))
            del self.thread_table[thread_obj.target.interface]
            lock.release()
        elif opt == "attack_module_update":
            lock.acquire()
            self.thread_table[thread_obj.target.interface][1]=thread_obj.status_data
            lock.release()
            
        else:
            ##All other opcodes are just passed through as they are just status codes
            ## so we don't care, it is for process_thread_status() in the caller to work out
            self.result_q.put((thread_obj, opt, thread_obj.status_data))
        
    
    def get_thread_info(self, ip_list=None):
        """
        Show current state of:
        ALL threads (default)
        or of selected threads by passing list of ip's
        """
        ret={}
        if not ip_list:
            lock.acquire()
            #for ip in self.thread_table.keys():
                #ret[ip]=self.thread_table[ip]
            ret=copy.copy(self.thread_table)
            lock.release()
        else:

            for ip in ip_list:
                lock.acquire()
                try:
                    ret[ip]=copy.copy(self.thread_table[ip])
                except KeyError, err:
                    devlog("ThreadRunner2", "IP NOT FOUND IN THREAD TABLE: %s"%(err) )
                    print "IP NOT FOUND IN THREAD TABLE: %s"%(err)
                lock.release()
        
        return ret
    
    def get_current_attack_module(self, ip):
        """
        Return a string of the module currently in use by the thread attacking specified ip
        """
        msg=self.get_thread_info(ip_list=[ip])
        return msg[ip][1]
    
    def get_threadcount(self):
        """
        Return current number of running threads
        """
        lock.acquire()
        tc=len(self.thread_table)
        lock.release()
        
        return tc
            
            


class ThreadWrapper(Thread):
    """
    Spawn a new exploit module in its own thread
    
    Can READ from the canvasexploit instance via self.canvas_obj
    but should NOT write/communicate back to the canvasexpoit module except by
    using the ThreadWatcher queues.
    """
    def __init__(self, target, module, canvas_obj, track_q, checkforlife):
        """
        Set up our state
        """
        ##Do the thread dance
        Thread.__init__(self)
        self.setDaemon(1)
        
        ##The queue down which the child threads will update us on their progress
        self.q=track_q
        
        ##Quick link back to the canvas exploit instance that spawned us
        self.canvas_obj=canvas_obj
        self.log=self.canvas_obj.log
        
        ##Pre-test before running canvas module whether host is responsive or not?
        self.checkforlife=checkforlife
        
        ##Target may be a string of an IP addy if it is anything something has gone WRONG  
        try:
            node=self.canvas_obj.argsDict["passednodes"][0]        
        except:
            self.log("ERROR: No node in ThreadRunner2?")
            self.cleanup(result="ERROR: No node in ThreadRunner2?")
            
        try:
            #print "doing str to hostKnowledge object"
            self.target=node.get_known_host(target)
            if not self.target:
                #print "No existing hostKnowledge for %s, creating new object"%(target)
                self.target=node.new_host(target)
            else:
                ##We got an already known host so no need to check for life is specified we should
                self.checkforlife=False
            #print "got hostKnowledge object: %s"%(self.target)
        except:
            ##TODO **************************************** cleanup properly
            traceback.print_exc(file=sys.stdout) ##XXX
            print "ERRROOORRRRR could not get hostKnowledge object - something seriously wrong"
            os._exit(0)
        
        ##Register us in the thread table so we can be accounted for , NOTE: keyed on hostKnowledge objects now not IP strings
        self.q.put(["register",self])
        ##And wait until we are sure we have been registered :)
        self.q.join()

        ##Canvas module that will be run for this target
        self.module=module
        
    def log(self, msg):
        """
        Little wrapper so the correct IP gets used for the messages
        """
        self.canvas_obj.log(msg, host=self.target.interface)
        
    def run(self):
        """
        Start the exploit module
        """  
        self.log("Running on %s"%self.target.interface)
        self.canvas_obj.setInfo("Running on %s"%self.target.interface)

        if self.target.interface in self.canvas_obj.localips:
            self.log("Not running on localip %s"%(self.target.interface))
            self.status_update("newhost", self.target)
            self.cleanup("error", [self.target, "Not running on localip %s"%(self.target.interface)])
        
        ##XXX
        if not hasattr(self.canvas_obj, 'state') \
           or not hasattr(self.canvas_obj, 'HALT'):
            devlog("ThreadRunner2", "XXX: check CANVAS object (theexploit instance) attributes")
            
        if self.canvas_obj.state == self.canvas_obj.HALT:
            self.log("ThreadRunner2 thread was told to halt")            
            self.cleanup("killed",[ self.target, "ThreadRunner2 thread was told to halt"] )
        
        ##Pre module attack life check
        self.do_life_test()
        self.status_update("newhost", self.target)
            
        ##Do a Traceroute
        self.do_traceroute()
        
        ##Do OS detect / portscan (in autohack via flags ??) does the link() call gives us this automatically??
        
        ##OK, finally run the module 
        self.log( "Getting module %s"%(self.module) )
        app=self.get_module_and_link(self.module)
        app.target=self.target
        app.log=self.log
        app.report=self.canvas_obj.report
        app.set_current_attack_module=self.set_current_attack_module #overload canvasexploit method with a thread safe one
        app.argsDict["netmask"]="32" #hardcode to one ip
        if self.module == "autohack" or self.module=="autoassess":
            app.exploit_modules=self.canvas_obj.exploit_modules
            app.portscantype="fast"
               
        #app.ignore_unidentified_hosts=self.canvas_obj.ignore_unid_hosts
        self.set_current_attack_module(self.module)
        try:
            ret=app.run()
        except:
            self.log("Exception caught in autohack run")
            self.cleanup("exception", "Exception caused in %s during threaded run: %s"%(self.module, traceback.print_exc()) )
            
        ##Attacks modules can return 1,0, None or a node - if its a node throw it up to our calling canvas object
        if ret not in [1,0,None]:
            self.canvas_obj.results+=[ret]            
            
        self.result=app.result
        self.status_update("extras",ret)  #Needed ???
        if not self.result:
            devlog("ThreadRunner2", "Exploit failed : %s"%(self.target.interface) )
            self.cleanup("failure", self.target)
        else:    
            devlog("ThreadRunner2", "Exploit succeeded %s - %s"%(self.target.interface, self.result))
            self.cleanup("success", self.result)
    
    def get_module_and_link(self, module):
        """
        Load and link a new canvas exploit module
        """        
        app=self.canvas_obj.engine.getModuleExploit(module)
        app.link(self.canvas_obj)
        return app
            
    def do_life_test(self):
        """
        Is the target alive?
        """ 
        self.log( "Doing life test")
        if self.checkforlife and not self.canvas_obj.checkAlive(self.target.interface):
            ##Dead
            self.cleanup("dead", [self.target, "Target %s not alive"%(self.target.interface)] )
            
    def do_traceroute(self):
        """
        Get traceroute info for reporting
        """
        if getattr( self.canvas_obj, "traceroute", False):
            try:
                app=self.get_module_and_link("traceroute")
                app.target=target
                self.set_current_attack_module("traceroute")
                ret=app.run()
                if ret:
                    app.setProgress(100)
                else:
                    app.setProgress(-1)
                mytrace=app.result

            except:
                #TODO --------------------------------------------------------------
                #import traceback
                #traceback.print_exc(file=sys.__stdout__)
                self.log("No traceroute")
                return

            tracelist = target.get_knowledge("TraceList", None)
            if tracelist:
                #self.report.note(target, "%s"%str(tracelist))
                self.status_update("note",[self.target, "%s"%str(tracelist)])
        else:
            self.log("Traceroute set to off, continuing")
    
    def set_current_attack_module(self, new_module_str):
        """
        Attack modules called in the thread may in turn call multiple other attack modules, this
        exposes the attack currently being conducted against our target.
        
        To expose this to everything else we update the table the threadtracker keeps
        
        NOTE: It is the attack module which calls the other modules responsibility to update us.
        """
        self.log("Current module UPDATE: %s -> %s"%(self.target.interface, new_module_str))
        self.status_update("attack_module_update",new_module_str)
        
    def get_current_attack_module(self):
        """
        Return the module we are currently using against the target
        """
        self.log("ERROR - we should never be called - The threadtracker should be queried for current thread activities")
            
    def suicide(self):
        """
        Make ourselves exit early as the module we invoked has encountered 
        problems and never returned
        """
        ##Inform the watcher we have finished early (or late in actual fact!)
        #we should really have a cleanup() method in theexploit modules that tears down as much stuff as we can
        self.result=[self.target, "thread forcibly finished early. No result"]
        self.q.put(["killed", self])
        ##And exit ourselves
        thread.exit()
        
    def status_update(self, status, data):
        """
        Throw a status update down the q to the canvasexploit instance so as progress
        can be displayed/rolled into a report or whatever the caller sees fit to do with
        our notifications
        """
        self.status_data=data
        self.q.put([status, self])
        #join ?
    
    def cleanup(self, status, result):
        """
        Update our status as well as tidying up everything
        and exiting cleanly, all thread safely and that
        """
        self.result=result
        ##Inform the watcher we have finished - send the result??
        self.q.put([status, self])
        ##wait until the watcher has done its thing
        #self.q.join()
        ##And exit ourselves
        devlog("ThreadRunner2", "scannin thread %s joined and exiting"%self)
        thread.exit()
    
class ThreadRunner2(Thread):    
    """
    Thread Generator Class
    """
    
    def __init__(self, canvas_obj, ip_list, module, life_check, wait_time=3600):
        """
        Set up our state
        """
        ##Do the thread dance
        Thread.__init__(self)
        
        ##Canvas exploit instamce of our caller
        self.canvas_obj=canvas_obj
        ##Easy alias for logging
        self.log=canvas_obj.log
        ##Canvas exploit module to run across ip range
        self.module=module
        self.ip_list=ip_list
        
        ##Do we attempt to see if target is alive before continuing with a scan?
        self.life_check=life_check
        
        ##After all our threads have spawned how long shall we wait before
        ## we decide the remaining threads have gone rogue and need to be killed? (default 1 hour)
        self.thread_wait_time=wait_time
        
        ##A queue for child threads and the thread_tracker to communicate
        ##  we also use this q to tell the thread tracker to exit when all our threads have returned
        self.track_q=Queue.Queue(0)
        ##Spawn a thread tracker who will keep our thread table up to date
        self.thread_tracker_kill_signal="!DIE!"
        self.thread_tracker=ThreadTracker(self.track_q,self.thread_tracker_kill_signal)
        
        ##Expose the result queue to be easily grabbed by canvasexploit (our caller)
        self.result_q=self.thread_tracker.result_q
        self.end_of_results_marker="!EndOfResults!"
        
                
    def run(self):
        """
        Main thread spawning loop
        """
        msg="Scanning ip range:"
        for i in self.ip_list:
            msg+="%s, "%i
        self.log(msg)
        
        self.thread_tracker.start()
        
        ##Spawn an instance of the module (normally autohack) in its own thread for each ip
        for ip in self.ip_list:  
            ##First check has the 'STOP!' button been hit ?
            if self.canvas_obj.state == self.canvas_obj.HALT:
                print "STOP! halt scan detected. Bailing out....."
                devlog("ThreadRunner2", "STOP! halt scan detected. Bailing out.....")
                break
            
            ##If not spawn if we are within out thread limits
            while 1:
                if self.thread_tracker.get_threadcount() < self.canvas_obj.maxthreads:
                    child_t=ThreadWrapper(ip, self.module, self.canvas_obj, self.track_q, self.life_check)
                    self.log("***Starting scan thread for ip %s"%(ip))
                    bugtracker(child_t.start)
                    break
                else:
                    ##we have hit our thread limit so lets sleep a little zzzzzzzzz
                    self.threadwait()
                
        self.log("All scanning threads spawned")

        start_timer=time.time()
                
        ##All threads spawn now we just wait for them to all finish...
        while self.thread_tracker.get_threadcount() != 0:
            ##Test to see if we have waited for too long for all threads to return
            if (time.time() - start_timer) > self.thread_wait_time or self.canvas_obj.state == self.canvas_obj.HALT:
                self.log( "Thread wait time of %d expired - killing remaining threads"%(self.thread_wait_time))
                self.kill_rogue_threads()
                break
            
            self.log("==== %d Child threads still running.\n Thread status table:%s"%(self.thread_tracker.get_threadcount(), self.thread_tracker.get_thread_info()))
            time.sleep(30)
        
        ##Tell the thread_tracker thread to finish up nicely
        self.log("All child scanning threads complete. Shutting down tracker & spawner threads.....")
        self.thread_tracker.q.put(self.thread_tracker_kill_signal)
        self.thread_tracker.q.join()
        devlog("ThreadRunner2", "Thread tracker closed")
        
        ##All results will now be in the results q so add in the final 'its all over' to the end of the q
        ## so the result processor in canvasexploit can know its all over
        self.result_q.put([self,self.end_of_results_marker, ""])
                
    def threadwait(self):
        """
        This function waits until our threadcount is small enough for us to continue
        """
        while (self.canvas_obj.maxthreads<=self.thread_tracker.get_threadcount()) and (not time.sleep(0.1) and self.canvas_obj.maxthreads<=self.thread_tracker.get_threadcount()) :
            sleeptime=float(random.randint(1,50))/25.0
            devlog("threadrunner", "Enter sleeping %f seconds"%sleeptime)
            time.sleep(sleeptime)
        return
    
    def kill_rogue_threads(self):
             
        self.log("%d threads never returned"%(self.thread_tracker.get_threadcount()))
        for t in self.thread_tracker.get_thread_info().values():
            self.log("Killing thread: %s"%(t))
            try:
                t[0].suicide()
            except SystemExit, err:
                pass

            
            