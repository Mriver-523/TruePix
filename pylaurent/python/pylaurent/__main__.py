#!/usr/bin/python
#
# (C) 2018 Riad S. Wahby <rsw@cs.stanford.edu>
#
# test runner for pylaurent

try:
    import sys
    import os
    import os.path as OP
except:
    assert False
else:
    sys.path.insert(0, OP.abspath(OP.join(sys.path[0], os.pardir)))

import pylaurent.pyl_test as pyltest

DEFAULT_NUM_TESTS = 8
if len(sys.argv) > 1:
    try:
        num_tests = int(sys.argv[1])
    except:
        num_tests = DEFAULT_NUM_TESTS
else:
    num_tests = DEFAULT_NUM_TESTS

for t in [pyltest]:
    t.run_tests(num_tests)
