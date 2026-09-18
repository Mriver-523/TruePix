#!/usr/bin/python
#
# libTruePixtests runner

# hack: these tests live in a subdir
try:
    import sys
    import os.path
except:
    assert False
else:
    sys.path.insert(1, os.path.abspath(os.path.join(sys.path[0], os.pardir)))

import libTruePixtests.commit as commit
import libTruePixtests.compute_v as compute_v
import libTruePixtests.compute_beta as compute_beta
import libTruePixtests.iomlext as iomlext
import libTruePixtests.layer as layer
import libTruePixtests.circuit as circuit
import libTruePixtests.verifier as verifier
import libTruePixtests.nonint as nonint
import libTruePixtests.nizk as nizk
import libTruePixtests.nizkvecwit as nizkvecwit
import libTruePixtests.logwit as logwit

DEFAULT_NUM_TESTS = 5

if len(sys.argv) > 1:
    try:
        num_tests = int(sys.argv[1])
    except:
        num_tests = DEFAULT_NUM_TESTS
else:
    num_tests = DEFAULT_NUM_TESTS

for thing in [commit, logwit, compute_v, compute_beta, iomlext, layer, circuit, verifier, nonint, nizk, nizkvecwit]:
    thing.run_tests(num_tests)
