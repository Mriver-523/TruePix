// Python interface to PWS parser
// (C) 2017 Riad S. Wahby <rsw@cs.nyu.edu>

#include <gmp.h>
#include <iostream>
#include <string.h>
#include <string>
#include <sstream>
#include <vector>

#include "pws_circuit_parser.hh"

using namespace std;

string outstr;
stringstream outstream;
const char *err_string;

static const char *write_circuitdesc(PWSCircuitParser &parser);
extern "C" {
    const char *pypws_get_error(void);
    const char *pypws_parse(bool optimize, char *filename, char *prime_str);
    void pypws_clear(void);
}

void pypws_clear(void) {
    outstr.clear();
    outstream.clear();
    outstream.str(string());
}

const char *pypws_get_error(void) {
    return err_string;
}

const char *pypws_parse(bool optimize, char *filename, char *prime_str) {
    mpz_t prime;
    mpz_init_set_str(prime, prime_str, 10);
    PWSCircuitParser parser(prime);
    try {
        if (optimize) {
            parser.optimize(filename);
        } else {
            parser.parse(filename);
        }
    } catch (...) {
        err_string = "Error opening/parsing PWS file.";
        return NULL;
    }

    mpz_clear(prime);
    if (parser.circuitDesc.size() == 0) {
        err_string = "PWS has circuit with size 0.";
        return NULL;
    } else {
        return write_circuitdesc(parser);
    }
}

static const char *write_circuitdesc(PWSCircuitParser &parser) {
    pypws_clear();
    outstream << '['; // start outer list

    // build input layer: ints for constants, None for variables
    outstream << '['; // start list for inputs
    unsigned inlayer_size = parser.circuitDesc[0].size();
    for (unsigned i = 0, j = 0, k = 0; k < inlayer_size; i++, k++) {
        j = k;

        if (i >= parser.inConstants.size()) {
            k = inlayer_size;
        } else {
            k = get<1>(parser.inConstants[i]);
        }

        for (; j < k; j++) {
            outstream << "None,";
        }

        if (k < inlayer_size) {
            outstream << get<0>(parser.inConstants[i]) << ','; // constants
        }
    }
    outstream << "],"; // end of list for inputs

    // go through each layer and build tuples for each gate
    for (unsigned layNum = 1; layNum < parser.circuitDesc.size(); layNum++) {
        outstream << '['; // start list for this layer
        LayerDescription &layer = parser.circuitDesc[layNum];
        unsigned lay_size = layer.size();
        for (unsigned gNum = 0; gNum < lay_size; gNum++) {
            GateDescription &gate = layer[gNum];
            outstream << "('" << gate.strOpType() << "'," << gate.in1 << ',' << gate.in2 << ',';
            if (gate.op == GateDescription::MUX) {
                outstream << parser.muxGates[gate.pos.layer].at(gate.pos.name);
            } else {
                outstream << "None";
            }
            outstream << "),";
        }
        outstream << "],";
    }

    outstream << ']';
    outstr = move(outstream.str());
    return outstr.c_str();
}
