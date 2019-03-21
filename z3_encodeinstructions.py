#!/usr/bin/env python

from z3 import *
import argparse
import struct

def solve(target, num_vars=3, previous=0):
    X = [BitVec('X'+str(i), 32) for i in range(0, num_vars)]
    Z = BitVec("Z", 32)
    

    s = Solver()
    s.add( Z == previous )
    s.add(Or(    sum(X)+Z==target, (sum(X)+Z)&0xFFFFFFFF==target))
    for param in X:
        t_param = (param & 0xFF000000) >> 24
        s.add(t_param >0x20, t_param < 0x80, t_param!=0x0A, t_param!=0x0D)
        t_param = (param & 0x00FF0000) >> 16
        s.add(t_param >0x20, t_param < 0x80, t_param!=0x0A, t_param!=0x0D)
        t_param = (param & 0x0000FF00) >> 8
        s.add(t_param >0x20, t_param < 0x80, t_param!=0x0A, t_param!=0x0D)
        t_param = (param & 0x000000FF)
        s.add(t_param >0x20, t_param < 0x80, t_param!=0x0A, t_param!=0x0D)


    valid = s.check()
    #print(valid)
    if "unsat" in str(valid):
        return False, []
    s.model()
    r = []
    for i in s.model():
        if("X" not in str(i)): continue
        r.append(s.model()[i].as_long())
        print("sub eax, {0}".format(hex(s.model()[i].as_long())))
    print("push eax")
    return True, r

parser = argparse.ArgumentParser()
parser.add_argument("-s", "--shellcode", required=True, help="Shellcode to encode using the SUB method")
args = parser.parse_args()

shellcode = args.shellcode.replace("\\", "").replace("x", "")
shellcode = str(shellcode) + int(((len(shellcode)/2)%4))*"90"
shellcode = [struct.pack("<I", int(shellcode[i:i+8], 16)) for i in range(0, len(shellcode), 8)]

#print(shellcode)
print(";Assembly to clear out EAX")
print("and eax, 0x554e4d4a")
print("and eax, 0x2a313235")
print(";Assembly to get code onto the stack")
previous = 0
for x in shellcode:
    count = 1
    valid = False
    while not valid:
        valid, res = solve(int(struct.unpack("<I", x)[0]), count, previous)
        count += 1
    previous = int(struct.unpack("<I", x)[0])
#print('###########')
#sumCheck = 0
#for b in res[-3:]:
#    sumCheck += b
#    print("sub eax, {0}".format(hex(b)))
#print('###########')

#print('Check sum = {}'.format(hex(sumCheck)))

