#!/usr/bin/python
#
# (C) 2018 Riad S. Wahby <rsw@cs.stanford.edu>
#
# use CFFI to link from Python to pylaurent (test)

try:
    import random
    import sys
    import os
    import os.path as OP
except:
    assert False
else:
    sys.path.insert(0, OP.abspath(OP.join(sys.path[0], os.pardir)))
import pylaurent

p = 2**61 - 1
rand = random.SystemRandom()

def get_rnd(l=None):
    if l is None:
        return rand.randint(1, p - 1)
    return [ rand.randint(1, p - 1) for _ in range(0, l) ]

def run_one_test(m, n):
    zVec = [0] * n
    rx = [zVec] * (4 * m + 2)
    sx = [zVec] * (4 * m + 2)
    yP = get_rnd(n)
    for i in range(0, m):
        rx[m + i] = get_rnd(n)
        rx[2*m + i + 1] = get_rnd(n)
        rx[3*m + i + 1] = get_rnd(n)
        rx[4*m + 1] = get_rnd(n)
        sx[i] = get_rnd(n)
        sx[m + i] = get_rnd(n)
        sx[2*m + i + 1] = get_rnd(n)

    ret = pylaurent.compute(yP, rx, sx)
    assert len(ret) == 8*m + 3, "%d %s" % (len(ret), str(ret))
    assert all([ t == 0 for t in ret[:m] ])
    return ret[m:]

def run_tests(num):
    pylaurent.init(p)
    for _ in range(0, num):
        run_one_test(random.randint(2, 6), random.randint(2, 6))
        sys.stderr.write('.')
        sys.stderr.flush()
    print(" (done)")

if __name__ == "__main__":
    run_tests(10)
