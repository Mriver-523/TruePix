#!/usr/bin/python
#
# (C) 2018 Riad S. Wahby <rsw@cs.stanford.edu>
#
# test pymiracl

# hack: tests live in the module
try:
    import sys
    import os.path
except:
    assert False
else:
    sys.path.insert(0, os.path.abspath(os.path.join(sys.path[0], os.pardir)))

import pymiracl

def run_one_test(curvename, keepstrs):
    pm = pymiracl.MiraclEC(curvename, 3, False, keepstrs)

    q = pm.q
    g = pm.g
    if keepstrs:
        inf = ('0', '0')
        inval = ('1', '1')
    else:
        inf = (0, 0)
        inval = (1, 1)

    # exp_mul
    assert pm.exp_mul(g, 3, inf) == pm.pow_g(3)
    assert pm.exp_mul(inf, 3, g) == g
    assert inf == pm.exp_mul(inf, 3, inf)
    assert pm.exp_mul(g, 3, g) == pm.pow_g(4)
    try:
        pm.exp_mul(inval, 3, g)
    except:
        pass
    else:
        assert False
    try:
        pm.exp_mul(g, 3, inval)
    except:
        pass
    else:
        assert False

    # exp
    assert pm.exp(inf, 3) == inf
    assert pm.exp(g, 3) == pm.pow_g(3)

    # maul
    assert pm.maul(inf, 3) == pm.pow_g(q - 3)
    assert pm.maul(g, 3) == pm.pow_g(q - 2)

    # div
    assert pm.div(inf, g) == pm.pow_g(q - 1)
    assert pm.div(g, inf) == g
    assert pm.div(inf, inf) == inf
    assert pm.div(g, g) == inf

    # mul
    assert pm.mul(inf, g) == g
    assert pm.mul(g, inf) == g
    assert pm.mul(inf, inf) == inf
    assert pm.mul(g, g) == pm.pow_g(2)

    # multiexp
    xlst = [1, 2, 3, 4, 5, 6]
    glst = [inf, inf, inf, inf, inf, inf]
    for i in range(0, len(glst)):
        assert pm.multiexp(glst, xlst) == pm.pow_g(sum(xlst[:i]))
        glst[i] = g
    assert pm.multiexp(glst, xlst) == pm.pow_g(sum(xlst))

def run_tests(_=None):
    for curve in ('m159', 'm191', 'm221', 'm255'):
        for keep in (True, False):
            run_one_test(curve, keep)
            sys.stdout.write('.')
            sys.stdout.flush()
    print(" (curve inf/inval test passed)")

if __name__ == "__main__":
    run_tests()
