rem This is a little CANVAS loader. It tries both Python 2.4 and 2.5.
rem Copyright Immunity, Inc.

rem if running python22...
rem YOU CANNOT USE -OO because that strips doc strings, and
rem we need docstrings to do our MOSDEF compile!

rem This weird command cd's to the current directory of the batch script
pushd %~dp0

@IF exist c:\Python24\python.exe GOTO p24
rem else python 2.5:
PATH=c:\GTK\bin;c:\Python25\DLLs;C:\python25\;c:\Program Files\Common Files\GTK\2.0\lib;%PATH%
python.exe -W ignore runcanvas.py
@exit



:p24
rem else python 2.4:
PATH=c:\GTK\bin;c:\Python24\DLLs;c:\Program Files\Common Files\GTK\2.0\lib;c:\Python24\; %PATH%
rem c:\python24\python.exe -W ignore runcanvas.py
rem in case:
python.exe -W ignore runcanvas.py
@exit

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     
