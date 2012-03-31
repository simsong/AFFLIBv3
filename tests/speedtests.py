#
# python speed test jig.
# Note: this currently doesn't work.
#

# This file is a work of a US government employee and as such is in the Public domain.
# Simson L. Garfinkel, March 12, 2012

opt_megabytes = 4096
min_range = 7
max_range = 20

#max_range = 14

import time,re,os


#def do_command(cmd):
#    """ Run a command and return the clock time """
#    print cmd
#    start = time.time()
#    os.system(cmd)
#    end = time.time()
#    return end-start

def dd_test(infile="/dev/zero",outfile="/dev/null",bs=16384):
    transfer = 1024*1024*opt_megabytes
    count = transfer / bs
    res = re.compile("(\d+) bytes/sec")
    cmd = "dd if=%s of=%s bs=%d count=%d 2>&1" % (infile,outfile,bs,count)
    print cmd
    for line in os.popen(cmd,"r"):
        print "*",line
        m = res.search(line)
        if(m):
            print "yum",m.group(1)
            return int(m.group(1))
    return False

def grep(fn,what):
    import re
    m = re.compile(what)
    for line in open(fn,"r"):
        if(m.search(line)): return line.strip()
    return False

def dd_speed_tests():
    cpu = grep("/var/run/dmesg.boot","CPU")
    mem = grep("/var/run/dmesg.boot","real memory")

    print "\n\nRunning write tests..."
    block_sizes = []
    for i in range(min_range,max_range):
        block_sizes.append(2**i)

    write_speeds = {}
    for bs in block_sizes:
        write_speeds[bs] = dd_test(outfile="speed.tmp",bs=bs) / 1000000.0

    print "\n\nRunning read tests..."
    read_speeds = {}
    for bs in block_sizes:
        read_speeds[bs] = dd_test(infile="speed.tmp",bs=bs)   / 1000000.0
    
    print "\n\n"
    print cpu
    print mem
    print "Transfer Size: ",opt_megabytes,"MB"

    def print_sorted(title,dict):
        print title
	print "bs=nn\t\tMBytes/sec"
        keys = dict.keys()
        keys.sort()
        for k in keys:
            print "%d\t\t%.2f" % (k,dict[k])

    print_sorted("Write Results\ndd if=/dev/zero of=speed.tmp\n",write_speeds)
    print_sorted("Read Results\ndd if=/speed.tmp of=/dev/null",read_speeds)


if(__name__=='__main__'):
    dd_speed_tests()
