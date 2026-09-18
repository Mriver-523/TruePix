#!/usr/bin/python
#
# (C) 2018 Riad S. Wahby <rsw@cs.stanford.edu>
#
# pymiracl runner

# hack: these tests live in a subdir
try:
    import sys
    import os.path
except:
    assert False
else:
    sys.path.insert(0, os.path.abspath(os.path.join(sys.path[0], os.pardir)))

import pymiracl.test_curve as curve

DEFAULT_NUM_TESTS = 8
if len(sys.argv) > 1:
    try:
        num_tests = int(sys.argv[1])
    except:
        num_tests = DEFAULT_NUM_TESTS
else:
    num_tests = DEFAULT_NUM_TESTS

for thing in [curve]:
    thing.run_tests(num_tests)
