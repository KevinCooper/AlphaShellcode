#!/usr/bin/env python

from z3 import *
import argparse

def solve(offset, num_vars=3):
    X = [BitVec('X'+str(i), 32) for i in range(0, num_vars)]

    s = Solver()
    s.add(Or(    sum(X)==offset, sum(X)&0xFFFFFFFF==offset))
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
    print(valid)
    if "unsat" in str(valid):
        return False, []
    s.model()
    r = []
    for i in s.model():
        r.append(s.model()[i].as_long())

    return True, r

parser = argparse.ArgumentParser()
parser.add_argument("-o", "--offset", type=lambda x: (int(x,16)), help="Bytes to add or subtract (default is add)")
parser.add_argument("-c", "--esp", type=lambda x: (int(x,16)), help="Address of ESP")
parser.add_argument("-t", "--target", type=lambda x: (int(x,16)), help="Shellcode start address")
args = parser.parse_args()
print(args)
if not args.offset and not (args.esp is not None and args.target):
    parser.print_help()
    parser.exit()
offset = args.offset

if not offset:
    offset = args.target - args.esp

valid = False
count = 1
while not valid:
    print("Solving for -{0} with {1} ops".format(hex(offset), count))
    valid, res = solve(-1*offset, count)
    count += 1

print('###########')
sumCheck = 0
for b in res[-3:]:
    sumCheck += b
    print("sub eax, {0}".format(hex(b)))
print('###########')
for b in res[-3:]:
    print("\"\\x2D\" + pack(\"<I\", {0})".format(hex(b)))

print('Check sum = {}'.format(hex(sumCheck)))

