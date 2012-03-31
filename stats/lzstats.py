import sys,os;

sys.path.append(os.getenv("HOME") + "/slg/src/python")

from statbag import statbag

drives = {}                             # hash table for the drives
gb = 1000*1000*1000

class dr:
    pass

def process_afcompare(fn):
    import re
    global null_drives,total_nochg,total_null,total_lzma,total_drives,drives_larger_1g
    m = re.compile("\d\d\d\d[.]aff")
    for line in open(fn,"r"):
        r = m.search(line)
        drive = r.group(0)
        d = dr()
        fields = line.split(" ")
        while "" in fields: fields.remove("")
        d.nochg = int(fields[4])
        d.nul = int(fields[6])
        d.lzma = int(fields[8])
        d.old_bytes = int(fields[10])
        d.new_bytes = int(fields[12])
        drives[drive] = d

def process_afreport(fn):
    import re
    m = re.compile("\d\d\d\d[.]aff")
    for line in open(fn,"r"):
        r = m.search(line)
        try:
            drive = r.group(0)
            if drive not in drives: continue
            d = drives[drive]
            line = line.replace("\t"," ")
            fields = line.split(" ")
            while "" in fields: fields.remove("")
            d.imagesize  = int(fields[1])
            d.compressed = int(fields[2])
            d.uncompressed = int(fields[3])
            print d.iamgesize,d.compressed,d.uncompressed
        except AttributeError:
            pass


if(__name__=="__main__"):
    import glob
    for fn in glob.glob("*afcompare*"):
        process_afcompare(fn)
    for fn in glob.glob("*-report*"):
        process_afreport(fn)

    null_drives =0 

    big = {}

    for (fn,d) in drives.iteritems():
        if(d.nochg==0 and d.nul>=0 and d.lzma==0):
            null_drives += 1
            continue
        if(d.uncompressed<gb):
            continue

        big[fn] = d

    print "Total drives:",len(drives)
    print "Drives that were completely blank:",null_drives
    remaining = len(drives) - null_drives
    print "Drives containing some data:",remaining
    print "Drives larger than 1GB uncompressed:",len(big)
    print
    print "For the drives larger than 1GB uncompressed:"
    print "(All sizes in megabytes)"
    print "%8s %8s %8s %8s %s" % ("DriveID","Uncomp","EnCase","AFFLIB 1.7","Savings")

    def myfunc(A,B):
        a = big[A]
        b = big[B]
        if a.uncompressed < b.uncompressed: return -1
        if a.uncompressed > b.uncompressed: return 1
        return 0

    fns = big.keys()
    fns.sort(myfunc)
    avg_savings = statbag();
    for fn in fns:
        d = big[fn]
        savings = 100.0 - (100.0 * d.new_bytes/d.old_bytes)
        if(d.old_bytes/1000000 < 10): continue
        print "%8s %8d %8d %8d    %5.2f%%" % (
            fn,d.uncompressed/1000000,d.old_bytes/1000000,d.new_bytes/1000000,savings)
        avg_savings.addx(savings)
    print "\nAverage savings: %5.2f%%" % avg_savings.average()
