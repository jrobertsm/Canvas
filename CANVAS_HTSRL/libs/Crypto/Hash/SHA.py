#! /usr/bin/env python

# Just use the SHA module from the Python standard library

__revision__ = "$Id: SHA.py,v 1.2 2006/07/29 02:52:49 phil Exp $"

from sha import *
import sha
if hasattr(sha, 'digestsize'):
    digest_size = digestsize
    del digestsize
del sha
