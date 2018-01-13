#! /bin/sh

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

PYTHON=python

if [ -z "$DISPLAY" ] ; then
    DISPLAY=:0.0
    export DISPLAY
fi

if [ -f /etc/debian-release ] ; then
    # XXX check if we are with a bugged kernel before to apply that fix
    export LD_ASSUME_KERNEL=2.4.1
fi

if [ -f /etc/gentoo-release ] ; then
    PYTHONPATH=/usr/lib/python2.4/site-packages
    export PYTHONPATH
fi

if [ -f /etc/release ] ; then # Solaris, hehe
    PATH=$PATH:/usr/sfw/bin
    export PATH # uh
fi

if [ ! -z "$SHELL" ] ; then
    BUSYBOX="$(which busybox)"
    if [ ! -z "$BUSYBOX" ] && [ -x "$BUSYBOX" ] && [ "$SHELL" -ef "$BUSYBOX" ] ; then
        if [ "$(uname -sm)" = "Linux armv5tejl" ] ; then
            PYTHON=/var/lib/install/usr/bin/python2.4
            LD_LIBRARY_PATH=/var/lib/install/usr/lib:$LD_LIBRARY_PATH
            export LD_LIBRARY_PATH
        fi
    fi
fi

$PYTHON runcanvas.py $*
