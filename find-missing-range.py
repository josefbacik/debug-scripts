from __future__ import print_function
import re
import sys

class Range:
    def __init__(self, off, length, times, reserve):
        self._off = off
        self._len = length
        self._times = times
        self._reserve = reserve

    def contains(self, off):
        return self._off <= off and (self._off + self._len) > off

    def __repr__(self):
        return "off={} len={} times={} reserve={}".format(self._off, self._len,
                                                          self._times,
                                                          self._reserve)

def collapse_list(l):
    newlist = []
    while len(l):
        remaining = []
        cur = l[0]
        for i in range(1, len(l)):
            n = l[i]
            if (cur._off + cur._len) == n._off and n._times == cur._times:
                cur._len += n._len
            else:
                remaining.append(n)
        newlist.append(cur)
        l = sorted(remaining, key=lambda x: x._off)
    newlist.sort(key=lambda x: x._off)
    return newlist

def carve(r, n, excess):
    if r._off < n._off:
        x = Range(r._off, n._off - r._off, r._times, r._reserve)
        excess.append(x)
        r._off = n._off
        r._len -= x._len
    if r._off + r._len > n._off + n._len:
        x = Range(n._off + n._len, (r._off + r._len) - (n._off + n._len),
                  r._times, r._reserve)
        excess.append(x)
        r._len -= x._len

def find(r, l):
    for x in l:
        if x.contains(r._off) or r.contains(x._off):
            return x
    return None

def add_entry(r, l):
    n = find(r, l)
    if n is None:
        l.append(r)
        return
    while r._off != n._off or r._len != n._len:
        tmp = []
        if r._off == n._off:
            if r._len > n._len:
                carve(r, n, tmp)
            else:
                carve(n, r, tmp)
        elif r.contains(n._off):
            carve(r, n, tmp)
        elif n.contains(r._off):
            carve(n, r, tmp)
        else:
            print("FUCK")
            sys.exit(1)
        for x in tmp:
            add_entry(x, l)
    if r._off != n._off or r._len != n._len:
        print("We fucked up")
        sys.exit(1)
    n._times += r._times

getre = re.compile("Get off=(\d+) bytes=(\d+) times=(\d+)")
putre = re.compile("Put off=(\d+) bytes=(\d+) times=(\d+)")

getlist = []
putlist = []

totalput = 0
totalget = 0
f = open("out.txt")
for line in iter(f):
    reserve = True
    m = getre.match(line)
    if m is None:
        m = putre.match(line)
        if m is None:
            continue
        reserve = False
    r = Range(int(m.group(1)), int(m.group(2)), int(m.group(3)), reserve)
    if reserve:
        totalget += (r._len * r._times)
        add_entry(r, getlist)
    else:
        totalput += (r._len * r._times)
        add_entry(r, putlist)

getlist.sort(key=lambda x: x._off)
putlist.sort(key=lambda x: x._off)
getlist = collapse_list(getlist)
putlist = collapse_list(putlist)

offset = 0
print("getlist")
for i in getlist:
    if i._off != offset:
       for n in range(offset, i._off, 4096):
           print('.', end='')
    for n in range(i._off, i._off + i._len, 4096):
        print("{}".format(i._times), end='')
    offset = i._off + i._len
offset = 0
print("\nputlist")
for i in putlist:
    if i._off != offset:
       for n in range(offset, i._off, 4096):
           print('.', end='')
    for n in range(i._off, i._off + i._len, 4096):
        print("{}".format(i._times), end='')
    offset = i._off + i._len

print("\ntotat get {} totalput {}".format(totalget, totalput))
print("Starting phase one, len {}, getlist len {}".format(len(putlist),
                                                          len(getlist)))

loops=1
while True:
    nextput = []
    nextget = []
    for r in putlist:
        n = find(r, getlist)
        if loops > 1:
            print("doing r {} n {}".format(r, n))
        if n is None:
            print("breaking!?!?")
            break
        while r._off != n._off or r._len != n._len:
            if r._off == n._off:
                if r._len > n._len:
                    print("this is what's happening? {} {}".format(r, n))
                    carve(r, n, nextput)
                else:
                    print("adding some shit to nextget")
                    carve(n, r, nextget)
            elif r.contains(n._off):
                print("r {} contains {}".format(r._off, n._off))
                carve(r, n, nextput)
            elif n.contains(r._off):
                print("adding some shit to nextget")
                carve(n, r, nextget)
            else:
                print("FUCK")
                sys.exit(1)
        if r._off != n._off or r._len != n._len:
            print("We fucked up r={} n={}".format(r, n))
            sys.exit(1)
        getlist.remove(n)
        if r._times != n._times:
            print("this is the fucked up one {} {}".format(r, n))
        if r._times <= n._times:
            n._times -= r._times
            if n._times != 0:
                print("ALSKJDF:DAJFadding some shit to nextget")
                nextget.append(n)
        else:
            r._times -= n._times
            nextput.append(r)
    nextget.extend(getlist)
    print("nextget len {}".format(len(nextget)))
    nextget.sort(key=lambda x: x._off)
    print("nextget len {}".format(len(nextget)))
    getlist = collapse_list(nextget)
    print("getlist len {}".format(len(getlist)))
    print("putlist len {}".format(len(putlist)))
    loops += 1
    if len(putlist) == len(nextput):
        print("we're done loops {}".format(loops))
        print(getlist)
        print(putlist)
        break
    putlist = sorted(nextput, key=lambda x: x._off)

for x in getlist:
    print("off={} len={} times={} remaining".format(x._off, x._len, x._times))
