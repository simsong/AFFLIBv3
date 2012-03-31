#!/usr/bin/python
# This file is a work of a US government employee and as such is in the Public domain.
# Simson L. Garfinkel, March 12, 2012


import os,sys
d = "/tmp/"

def cmd(s):
    print s
    if(os.system(s)):
        print "** TEST FAILED"
        sys.exit(1)

def runtest(ext,maxsize):
    iso  = d + "image.iso"
    iso2 = d + "image2.iso"
    i1  = d + "image1." + ext
    i2  = d + "image2." + ext
    cmd("rm -rf %s %s %s %s" % (iso,iso2,i1,i2))
    cmd("./makeimage %s 100000",(iso))
    cmd("../aimage/aimage   %s -q -E %s %s" % (maxsize,iso,i1))
    cmd("../tools/affconvert %s -o %s %s" % (maxsize,i2,iso))
    cmd("../tools/affinfo -mS %s" % (i1))
    cmd("../tools/affinfo -mS %s" % (i2))
    cmd("../tools/affcompare %s %s" % (iso,i1))
    cmd("../tools/affcompare %s %s" % (iso,i2))
    cmd("../tools/affconvert -r -o %s %s" % (iso,i1))
    cmd("../tools/affcat %s > %s" % (i2,iso2))
    cmd("cmp %s %s" % (iso,iso2))
    cmd("rm -rf %s %s %s %s" % (iso,iso2,i1,i2))

    
if(__name__=='__main__'):
    runtest("aff","")
    runtest("aff","-M33554432b")
    runtest("afd","")
    runtest("afd","-M33554432b")
    runtest("afm","")
    runtest("afm","-M33554432b")
    
