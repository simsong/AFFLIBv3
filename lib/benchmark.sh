#!/bin/bash
#
# perform some performance testing
# This file is a work of a US government employee and as such is in the Public domain.
# Simson L. Garfinkel, March 12, 2012
# 
echo Building aftest with profiling
(cd .. ; make distclean; ./configure CFLAGS="-p -pg" CPPFLAGS="-p -pg" CXXFLAGS="-p -pg" ; make)
cp aftest aftest.prof
./aftest.prof -1
gprof -c aftest.prof gmon.out > aftest.gmon.txt

echo Re-Building aftest without profiling
(cd .. ; make distclean; ./configure ; make)

echo Running time tests 

echo try it with auditing
sudo dtruss ./aftest -1 2>aftest.dtruss
echo number of lseeks: `grep lseek aftest.dtruss  | wc -l`
echo number of reads: `grep read_nocancel aftest.dtruss  | wc -l`
echo number of writes: `grep write_nocancel aftest.dtruss  | wc -l`

