#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

#Part of CANVAS For licensing information, please refer to your
#Immunity CANVAS licensing documentation

"""
Runs the CANVAS
"""

import os, sys

#here we change location to where our install path is, ideally
our_dir=os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]),'.')) 
os.chdir(our_dir)

#Psyco is turned off now, since it causes random segfaults in
#PyEval_Restricted for some reason?
if True:# and os.environ.has_key('WINGDB_ACTIVE'):
  pass
else: 
  try:
    import psyco
    psyco.full() 
    print "Psyco acceleration enabled"
  except:
    pass 

from canvasengine import canvasmain

canvasmain()

