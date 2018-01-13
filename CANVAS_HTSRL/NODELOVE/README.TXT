Install
=======

For full mapping support, download and uncompress the GeoIP City database 
into the CANVAS/NODELOVE/ directory. You will also need the GeoIP 
C library and the GeoIP Python bindings installed. Most Linux distributions
come with packaged versions of GeoIP for both the C library and the
Python Bindings.

Note that Linux/UNIX users will need to name their database 
'GeoLiteCity.dat' and Win32 users will need to name their database 
'GeoIPCity.dat'.

If you already have GeoIP and GeoIP Python, then you can just place the 
uncompressed (GeoLiteCity.dat) City Database in CANVAS/NODELOVE. CANVAS
expects the database to be named 'GeoLiteCity.dat'.

Notes for Linux users
=====================

wget -c http://www.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
gunzip GeoLiteCity.dat.gz
#ubuntu
apt-get install python-geoip

Notes for Win32 users
=====================

Win32 based CANVAS users need the GeoIP com object installed to be able
to use the mapping functionality. You can download this from:

Note: please make sure you download the latest (as of writing 1.2) 
COM version capable of City database support.

http://www.maxmind.com/app/com

To install the COM object, copy GeoIpComEx.dll to the SYSTEM32 folder.
Then from an Administrator CMD prompt, cd into SYSTEM32 and register
the COM with: 'regsvr32 GeoIpComEx.dll'

To be able to use the com object from Python, additionaly you will 
need the win32 extensions for Python installed from:

https://sourceforge.net/projects/pywin32/

Database Naming
===============

You want to name your database file 'GeoIPCity.dat' for Win32 Mapping
support and place it in the CANVAS\NODELOVE\ directory. UNIX/Linux
users should use 'GeoLiteCity.dat' as their db name.

Downloads
=========

Current GeoLite CITY Database:

http://www.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz

GeoIP (libs and python bindings):

http://www.maxmind.com/app/python

Map Credit
==========

http://visibleearth.nasa.gov/view_rec.php?id=2433

Full Map Credit
===============

NASA Goddard Space Flight Center Image by Reto Stöckli (land 
surface, shallow water, clouds). Enhancements by Robert Simmon (ocean 
color, compositing, 3D globes, animation). Data and technical support: 
MODIS Land Group; MODIS Science Data Support Team; MODIS Atmosphere 
Group; MODIS Ocean Group Additional data: USGS EROS Data Center 
(topography); USGS Terrestrial Remote Sensing Flagstaff Field Center 
(Antarctica); Defense Meteorological Satellite Program (city lights).

http://visibleearth.nasa.gov/useterms.php

Map PNG Size
============

Our simple projection algo takes 2048 * 1024 sized maps. Using a 
standard longitude/latitude degree to coordinate projection algorithm.

