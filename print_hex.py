import sys

if sys.argv.__len__() != 2:
    print("Usage : %s <binary>"%sys.argv[0])
    exit(1)
    
with open(sys.argv[1],"rb") as f:
    for b in f.read():
        print("\\x%02x" % b,end='')