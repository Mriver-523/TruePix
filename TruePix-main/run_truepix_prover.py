#!/usr/bin/python
#
# Copyright 2017 Riad S. Wahby and the Hyrax authors
# Copyright 2025-2026 the TruePix authors
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
#
# Modified to support VOLE commitments

import bz2
import gc
import getopt
import resource
import sys
import time
import traceback
import subprocess
import glob
import os
from timeit import default_timer as timer  

try:
    import pypws
except ImportError:
    print("ERROR: could not import pypws; you should run `make`. Giving up now.")
    sys.exit(1)

import libTruePix.circuitnizkvec_vole
import libTruePix.circuitnizkvec_vole_ZK  
import libTruePix.VOLECommit
import libTruePix.VOLECommit_zk
from libTruePix.defs import Defs
from libTruePix.fiatshamir import FiatShamir
import libTruePix.parse_pws
import libTruePix.randutil as randutil
import libTruePix.util as util
from ecdsa import SigningKey, VerifyingKey
import pickle
from ecdsa.util import sigdecode_der

class VerifierInfo(object):
    nCopyBits = 11
    nCopies = 1350  #


    ndBits = None
    ndGen = None

    rvStart = None
    rvEnd = None

    pwsFile = None
    rdlFile = None

    inputFile = None
    # 1 = let Orion sample its own input; set to 0 when -i pins a snapshot.
    # This used to default to None and was passed to the Orion binaries as the
    # literal string "None", where sscanf left the flag uninitialised.
    userandom = 1
    usezk = None

    pProofFile = None
    vProofFile = None

    proofType = None  
    witnessDiv = 2

    logFile = None
    VOLEPName = None
    VOLEVName = None

    vole_security_repetitions = 1

    showPerf = False
    pStartTime = 0
    pEndTime = 0
    vStartTime = 0
    vEndTime = 0
    
    # Added detailed timing fields
    timing_data = {
        'total_prove': 0,
        'total_verify': 0,
        'phase_times': {},  
        'sub_times': {},    
    }

    class Log(object):
        logLines = []

        @classmethod
        def get_lines(cls):
            for line in cls.logLines:
                yield line
                yield '\n'

        @classmethod
        def log(cls, lStr, do_print):
            cls.logLines.append(lStr)
            if do_print:
                print(lStr)

def get_usage():
    uStr =  "Usage: %s -p <pwsFile> [options]\n\n" % sys.argv[0]
    uStr += " option        description                                 default\n"
    uStr += " --            --                                          --\n"

    uStr += " -p pwsFile    PWS describing the computation to run.      (None)\n\n"
    uStr += " -c nCopyBits  log2(#copies) to verify in parallel         (%d)\n" % VerifierInfo.nCopyBits
    uStr += "    NOTE: \"-c =<nCopies>\" treats arg as #copies instead of log2\n\n"

    uStr += " -i inputsFile file containing inputs for each copy        (None)\n"
    uStr += "               (otherwise, inputs are generated at random\n\n"

    uStr += " -n b          Set nondet input range per sub-AC.          (None)\n"
    uStr += "               The final 2^(-b) fraction of input indices\n"
    uStr += "               are part of the witness (e.g., x=1 means the\n"
    uStr += "               last 1/2 of input is the witness, x=2 means 1/4, etc.\n\n"

    uStr += " -R x,y        (inclusive) rvalue range per sub-AC         (None,None)\n\n"

    uStr += " -g genscript  set filename of nondet generator script, a  (None)\n"
    uStr += "               .py file that defines a function like so:\n"
    uStr += "  def nondet_gen(inputs, muxsels):\n"
    uStr += "      new_inputs = []\n"
    uStr += "      for (copy_num, copy_ins) in enumerate(inputs):\n"
    uStr += "          new_copy_ins = []\n"
    uStr += "          # do something with this copy's inputs\n"
    uStr += "          new_inputs.append(new_copy_ins)\n"
    uStr += "      return new_inputs\n\n"

    uStr += " -o prooffile  write proof to prooffile                    (None)\n"
    uStr += "               (cannot be used at the same time as -v)\n\n"

    uStr += " -v prooffile  verify proof from prooffile                 (None)\n"
    uStr += "               (cannot be used at the same time as -o)\n\n"

    uStr += " NOTE: If neither -o nor -v is supplied, generates and verifies proof.\n\n"
    uStr += " -z            Verify using image editing results without enabling the zero knowledge option when -z 1\n\n"  
    uStr += "               Verify using proof results without enabling the zero knowledge option -z 2\n\n"  
    uStr += "               Verify using image editing results without enabling the zero knowledge option -z 3\n\n"  
    uStr += "               Verify using proof results without enabling the zero knowledge option -z 4\n\n" 
    uStr += " -T            show performance info when done             (False)\n\n"

    return uStr

def get_inputs(verifier_info, input_layer):
    nCopies = verifier_info.nCopies if verifier_info.rdlFile is None else 1

    if verifier_info.inputFile is None:
        inputs = randutil.rand_inputs(0, nCopies, input_layer)
    else:
        inputs = util.get_inputs(verifier_info.inputFile, input_layer, nCopies)

    if len(inputs) != nCopies:
        print("ERROR: input file has too few lines (got %d, expected %d)" % (len(inputs), nCopies))
        sys.exit(1)

    return inputs
    
def print_section_header(title):
    print("\n" + "=" * 50)
    print(f"=== {title.center(44)} ===")
    print("=" * 50)

def print_subsection_header(title):
    print("\n" + "-" * 50)
    print(f"--- {title.center(44)} ---")
    print("-" * 50)

def print_metric(name, value, unit=""):
    print(f"{name:<30}: {value:>15} {unit}")

def parse_ec_y1_metrics(stdout):
    """Sum Protocol-3 EC(y1) inner-proof timings from Orion stdout.

    ZK opens two polynomials (masked + mask), so each line may appear twice.
    """
    wall, prover, verifier = [], [], []
    for line in stdout.splitlines():
        if "EC(y1) code-switching time" in line:
            wall.append(float(line.split()[-1]))
        elif "EC(y1) prover time" in line:
            prover.append(float(line.split()[-1]))
        elif "EC(y1) verifier time" in line:
            verifier.append(float(line.split()[-1]))
    return (
        sum(wall) if wall else None,
        sum(prover) if prover else None,
        sum(verifier) if verifier else None,
    )

def sweep_stale_vole_files():
    """
    Drop VOLE files left behind by runs that died before their own cleanup.

    The files are named after the producing PID and are tens of megabytes each,
    so a few interrupted runs are enough to accumulate hundreds of megabytes.
    """
    removed = 0
    for pattern in ("vole_prover_*.json", "vole_verifier_*.json",
                    "vole_ext_prover_*.json", "vole_ext_verifier_*.json"):
        for path in glob.glob(pattern):
            try:
                pid = int(os.path.basename(path).rsplit("_", 1)[1].split(".")[0])
            except (IndexError, ValueError):
                continue
            if pid == os.getpid():
                continue
            try:
                # A live process still owns this file.
                os.kill(pid, 0)
                continue
            except ProcessLookupError:
                pass
            except PermissionError:
                continue
            try:
                os.remove(path)
                removed += 1
            except OSError:
                pass
    if removed:
        print(f"Removed {removed} stale VOLE file(s) from earlier runs")


def get_vole_filenames(input_filename):
    """Generate ExtVOLE filenames based on input filename"""

    sweep_stale_vole_files()

    pid = os.getpid()
    prover_file = f"vole_ext_prover_{pid}.json"
    verifier_file = f"vole_ext_verifier_{pid}.json"
    return prover_file, verifier_file

def run_truepix(verifier_info):
    print_metric("Max Memory Usage", f"{resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024:.2f}", "MB")
    # set curve and prime
    #Defs.curve = verifier_info.curve
    #util.set_prime(libTruePix.commit.MiraclEC.get_order(Defs.curve))

    Defs.configure(
        vole_security_repetitions=getattr(verifier_info, "vole_security_repetitions", 1)
    )
    print_metric("Circuit prime", str(Defs.prime))

    # pylint doesn't seed to understand how classmethods are inherited from metclasses
    p_from_pws = verifier_info.proofType.ProverClass.from_pws # pylint: disable=no-member
    pFile = pypws.parse_pws(verifier_info.pwsFile, str(Defs.prime))

    # Generate ExtVOLE relations for preprocessing
    from libTruePix.ExtVOLEGen import ExtVOLEGenerator
    vole_gen = ExtVOLEGenerator(
        base_prime=Defs.BASE_PRIME_61,
        security_repetitions=Defs.vole_security_repetitions,
    )
    vole_gen.generate_deltas()
    num_instances = 100000
    vole_gen.generate_vole_instances(num_instances)
    verifier_info.VOLEPName, verifier_info.VOLEVName = get_vole_filenames(
        verifier_info.inputFile
    )
    vole_gen.save_to_files(verifier_info.VOLEPName, verifier_info.VOLEVName)
    # Drop ExtVOLE buffers before Circuit Prove so gen HWM does not stack
    # with proof-time allocations (ru_maxrss is monotonic).
    if hasattr(vole_gen, "clear"):
        vole_gen.clear()
    del vole_gen
    gc.collect()
    
    print(f"Generated {num_instances} VOLE instances and saved to:")
    print(f"  Prover file: {verifier_info.VOLEPName}")
    print(f"  Verifier file: {verifier_info.VOLEVName}")

    # handle RDL
    if verifier_info.rdlFile is not None:
        rFile = pypws.parse_pws_unopt(verifier_info.rdlFile, str(Defs.prime))
        (r_input_layer, rdl_map) = libTruePix.parse_pws.parse_rdl(rFile, verifier_info.nCopies, pFile[0])

    # either generate or read in proof
    if verifier_info.vProofFile is None:
        (input_layer, prv) = p_from_pws(pFile, verifier_info.nCopies)
        prv.build_prover()

        # set up RDL
        if verifier_info.rdlFile is not None:
            inputs = get_inputs(verifier_info, r_input_layer)
            prv.set_rdl(rdl_map, len(r_input_layer))
        else:
            inputs = get_inputs(verifier_info, input_layer)

        # handle nondeterminism options
        if verifier_info.ndBits is not None:
            prv.set_nondet_range(verifier_info.ndBits)
        if verifier_info.ndGen is not None:
            prv.set_nondet_gen(verifier_info.ndGen)
        if verifier_info.rvStart is not None and verifier_info.rvEnd is not None:
            prv.set_rval_range(verifier_info.rvStart, verifier_info.rvEnd)
        if verifier_info.witnessDiv is not None:
            prv.set_wdiv(verifier_info.witnessDiv)

        # Add detailed timing
        verifier_info.pStartTime = time.time()
        start_prove = timer()
        
        # If detailed timing is supported, use timed execution method
        if hasattr(prv, 'run_with_timing'):
            proof, timing_info = prv.run_with_timing(inputs)
            verifier_info.timing_data.update(timing_info)
        else:
            proof = prv.run(inputs)
            
        end_prove = timer()
        verifier_info.pEndTime = time.time()
        verifier_info.timing_data['total_prove'] = end_prove - start_prove
    else:
        with open(verifier_info.vProofFile, 'rb') as fh:
            proof = bz2.decompress(fh.read())            
        

    # either verify or write out proof
    if verifier_info.pProofFile is None:
        (_, ver) = v_from_pws(pFile, verifier_info.nCopies)

        # set up RDL
        if verifier_info.rdlFile is not None:
            ver.set_rdl(rdl_map, len(r_input_layer))

        verifier_info.vStartTime = time.time()
        try:
            ver.run(proof)
        except Exception as e: # pylint: disable=broad-except
            verifier_info.Log.log("Verification failed: %s" % e, True)
            verifier_info.Log.log(traceback.format_exc(), True)
        else:
            verifier_info.Log.log("Verification succeeded.", True)
        verifier_info.vEndTime = time.time()
    else:
        with open(verifier_info.pProofFile, 'wb') as fh:
            fh.write(bz2.compress(proof))
        
        
    # Add structured output
    #verifier_info.Log.log("Hyrax Proof size: %d elems, %d bytes" % FiatShamir.proof_size(proof), True)
    nInBits = util.clog2(len(input_layer))
    if verifier_info.rdlFile is not None:
        nInBits = util.clog2(len(r_input_layer))
    nCopies = verifier_info.nCopies
    nLayers = len(ver.in0vv) + 1 if verifier_info.rdlFile is not None else 0
    verifier_info.Log.log("nInBits: %d, nCopies: %d, nLayers: %d" % (nInBits, nCopies, nLayers), verifier_info.showPerf)
    if Defs.track_fArith:
        verifier_info.Log.log(str(Defs.fArith()), verifier_info.showPerf)
    
    # Calculate and print Hyrax time
    hyrax_prove_time = verifier_info.pEndTime - verifier_info.pStartTime
    proof_size = FiatShamir.proof_size(proof)
    print_metric("Circuit Proof Size", f"{int(proof_size[1]):,}", "bytes")  # Adjust index based on actual situation
    print_metric("Circuit Prove Time", f"{verifier_info.timing_data['total_prove']:.6f}", "seconds")
    print_metric("Max Memory Usage", f"{resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024:.2f}", "MB")
    # VOLE correlations consumed during circuit prove (prover's (u,v) view).
    try:
        from libTruePix.fp2_link import format_vole_usage_metrics
        for name, value, unit in format_vole_usage_metrics(getattr(prv, "com", None), "Prover"):
            print_metric(name, value, unit)
    except Exception:
        pass
     # 2. Input equivalence proof (this part is replaced by orion)

    orion_ec_wall = None
    orion_ec_prover = None
    orion_ec_verifier = None

    # The prove phase used to run with the legacy Y/Cb/Cr packing, a fresh
    # random mask and a random opening point, so it neither committed to
    # nor opened the polynomial the rest of the protocol talks about.
    from libTruePix.fp2_link import (
        infer_gkr_input_layout,
        orion_binary,
        orion_env,
        parse_orion_prove_time,
        write_point_file,
    )

    if prv.final_input_point is None:
        raise Exception("prover did not record the GKR input point")
    point_file, _ = write_point_file("gkr_point_prover.json", prv.final_input_point)

    copy_size, const_idx, const_val = infer_gkr_input_layout(
        verifier_info.pwsFile,
        verifier_info.inputFile or "input.txt",
    )
    env = orion_env(copy_size, const_idx, const_val)
    env["TRUEPIX_GKR_POINT_FILE"] = os.path.abspath(point_file)

    cmd = [
        "taskset", "-c", "1",
        orion_binary("prove", VerifierInfo.usezk == 1),
        str(VerifierInfo.nCopies),
        "0",  # shared input.txt is mandatory
    ]
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise Exception(
            "Orion prove phase failed (commitment root mismatch or failed "
            "tensor-IOP check)"
        )

    orion_proof_size = None
    orion_prove_time = parse_orion_prove_time(result.stdout)
    orion_ec_wall = None
    orion_ec_prover = None
    orion_ec_verifier = None
    for line in result.stdout.split('\n'):
        if "Proof size for tensor IOP" in line:
            # ZK opens two polynomials; non-ZK opens one.
            factor = 2 if VerifierInfo.usezk == 1 else 1
            orion_proof_size = int(line.split()[-2]) * factor
    orion_ec_wall, orion_ec_prover, orion_ec_verifier = parse_ec_y1_metrics(result.stdout)

    print_metric("Input Proof Size", f"{orion_proof_size if orion_proof_size is not None else 0:,}", "bytes")
    print_metric("Input Prove Time", f"{(orion_prove_time or 0.0):.6f}", "seconds")
    print_metric("EC(y1) Code-Switch Time", f"{(orion_ec_wall or 0.0):.6f}", "seconds")
    print_metric("EC(y1) Prover Time", f"{(orion_ec_prover or 0.0):.6f}", "seconds")
    print_metric("EC(y1) Verifier Time", f"{(orion_ec_verifier or 0.0):.6f}", "seconds")
    
    
    # Overall statistics
    print_section_header("Editing and Prove Performance")
    total_Prove_time = hyrax_prove_time+(orion_prove_time or 0.0)
    
    print_metric("TOTAL Prove Time", f"{total_Prove_time:.6f}", "seconds")
    print_metric("Max Memory Usage", f"{resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024:.2f}", "MB")


def print_timing_info(verifier_info):
    """Print detailed timing information"""
    if not verifier_info.showPerf:
        return
    
    print("\n=== Detailed Timing Information ===")
    print(f"Total prove time: {verifier_info.timing_data['total_prove']:.6f} seconds")
    print(f"Total verify time: {verifier_info.timing_data['total_verify']:.6f} seconds")
    
    if verifier_info.timing_data.get('phase_times'):
        print("\nPhase Times:")
        for phase, time_taken in verifier_info.timing_data['phase_times'].items():
            print(f"  {phase}: {time_taken:.6f} seconds")
    
    if verifier_info.timing_data.get('sub_times'):
        print("\nSub-step Times:")
        for step, time_taken in verifier_info.timing_data['sub_times'].items():
            print(f"  {step}: {time_taken:.6f} seconds")
    
    print("=================================\n")

def main():
    uStr = get_usage()
    oStr = "c:i:p:n:g:o:v:C:Pz:TZr:R:L:w:D"  # Added D option for detailed timing

    try:
        (opts, args) = getopt.getopt(
            sys.argv[1:],
            oStr,
            ["vole-reps="],
        )
    except getopt.GetoptError as err:
        print(uStr)
        print(str(err))
        sys.exit(1)

    if args:
        print(uStr)
        print("ERROR: extraneous arguments.")
        sys.exit(1)

    for (opt, arg) in opts:
        if opt == "-c":
            if arg[0] == "=":
                nC = int(arg[1:])
                nCB = util.clog2(nC)
            else:
                nCB = int(arg)
                nC = 1 << nCB
            VerifierInfo.nCopyBits = nCB
            VerifierInfo.nCopies = nC
        elif opt == "-i":
            VerifierInfo.inputFile = arg
            VerifierInfo.userandom = 0
        elif opt == "--vole-reps":
            VerifierInfo.vole_security_repetitions = int(arg)
        elif opt == "-p":
            VerifierInfo.pwsFile = arg
        elif opt == "-r":
            VerifierInfo.rdlFile = arg
        elif opt == "-n":
            VerifierInfo.ndBits = int(arg)
        elif opt == "-R":
            (VerifierInfo.rvStart, VerifierInfo.rvEnd) = [ int(x) for x in arg.split(',') ]
        elif opt == "-g":
            arg_ns = {}
            try:
                exec(compile(open(arg, "rb").read(), arg, 'exec'), arg_ns)
                VerifierInfo.ndGen = staticmethod(arg_ns['nondet_gen'])
            except IOError:
                print(uStr)
                print("ERROR: Could not open file %s" % arg)
                sys.exit(1)
            except NameError:
                print(uStr)
                print("ERROR: Could not find nondet_gen function in file %s" % arg)
                sys.exit(1)
        elif opt == "-v":
            VerifierInfo.vProofFile = arg
        elif opt == "-o":
            VerifierInfo.pProofFile = arg
        elif opt == "-z":
            arg = int(arg)
            if arg == 1:
                VerifierInfo.proofType = libTruePix.circuitnizkvec_vole_ZK
                VerifierInfo.usezk = 1
            elif arg == 2:
                VerifierInfo.proofType = libTruePix.circuitnizkvec_vole
                VerifierInfo.usezk = 0
            else:
                assert False, "got '-z %s', expected 1 (ZK) or 2 (non-ZK)" % arg
            VerifierInfo.witnessDiv = None
        elif opt == "-T":
            VerifierInfo.showPerf = True
        elif opt == "-L":
            VerifierInfo.logFile = arg
        elif opt == "-w":
            if arg == '1':
                VerifierInfo.witnessDiv = None
            else:
                VerifierInfo.witnessDiv = float(arg)
        else:
            assert False, "logic error: got unexpected option %s from getopt" % opt

    if VerifierInfo.pwsFile is None:
        print(uStr)
        print("ERROR: missing required argument, -p <pwsFile>.")
        sys.exit(1)

    if VerifierInfo.nCopyBits < 1:
        print(uStr)
        print("ERROR: nCopyBits must be at least 1.")
        sys.exit(1)

    if VerifierInfo.vProofFile is not None and VerifierInfo.pProofFile is not None:
        print(uStr)
        print("ERROR: only one of -o and -v can be supplied.")
        sys.exit(1)

    # -z 1 = GKR product-mask + Orion ZK; -z 2 = plain GKR + Orion non-ZK.
    zk_ok = VerifierInfo.proofType is libTruePix.circuitnizkvec_vole_ZK and VerifierInfo.usezk == 1
    nonzk_ok = VerifierInfo.proofType is libTruePix.circuitnizkvec_vole and VerifierInfo.usezk == 0
    if not (zk_ok or nonzk_ok):
        print(uStr)
        print("ERROR: expected '-z 1' (GKR+Orion ZK) or '-z 2' "
              "(GKR+Orion non-ZK); got proofType=%s usezk=%s"
              % (getattr(VerifierInfo.proofType, "__name__", VerifierInfo.proofType),
                 VerifierInfo.usezk))
        sys.exit(1)
    # Shared input.txt is mandatory; never ask Orion to sample independently.
    VerifierInfo.userandom = 0
    if VerifierInfo.inputFile is None:
        VerifierInfo.inputFile = "input.txt"

    run_truepix(VerifierInfo)

    # The ExtVOLE files (vole_ext_*) were not covered by this glob, so every
    # run left ~90MB behind. The verifier's own file must survive until the
    # verifier has read it, so only the prover's copy is removed here.
    for pattern in ("vole_prover_*.json", "vole_ext_prover_*.json"):
        for file_path in glob.glob(pattern):
            try:
                os.remove(file_path)
                print(f"Deleted VOLE prover file: {file_path}")
            except OSError as e:
                print(f"Error deleting {file_path}: {e}")

if __name__ == "__main__":
    main()
