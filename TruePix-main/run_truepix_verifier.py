#!/usr/bin/python
#
# Copyright 2017 Riad S. Wahby and the Hyrax authors
# Copyright 2025-2026 the TruePix authors
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
#
# Modified to support VOLE commitments
# Added detailed timing measurements

import bz2
import getopt
import resource
import sys
import time
import traceback
import subprocess
import glob
import os
from timeit import default_timer as timer  # Added high-precision timer

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
from libTruePix import attest
import pickle

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

    vole_security_repetitions = 1
    orion_result_file = "orion_open_result.json"
    gkr_point_file = "gkr_point.json"

    showPerf = False
    pStartTime = 0
    pEndTime = 0
    vStartTime = 0
    vEndTime = 0
    
    # Added detailed timing fields
    timing_data = {
        'total_prove': 0,
        'total_verify': 0,
        'phase_times': {},  # Time records for each phase
        'sub_times': {},    # Time records for sub-steps
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

def run_truepix(verifier_info):
    print_metric("Max Memory Usage", f"{resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024:.2f}", "MB")

    # Every failure below is recorded here and turned into a non-zero exit
    # status at the end. Previously a rejected proof was only logged, so the
    # harness reported success no matter what the verifier concluded.
    verification_failed = False

    Defs.configure(
        vole_security_repetitions=getattr(verifier_info, "vole_security_repetitions", 1)
    )
    print_metric("Circuit prime", str(Defs.prime))

    # pylint doesn't seed to understand how classmethods are inherited from metclasses
    p_from_pws = verifier_info.proofType.ProverClass.from_pws # pylint: disable=no-member
    v_from_pws = verifier_info.proofType.VerifierClass.from_pws # pylint: disable=no-member
    pFile = pypws.parse_pws(verifier_info.pwsFile, str(Defs.prime))

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
    else:
        with open(verifier_info.vProofFile, 'rb') as fh:
            proof = bz2.decompress(fh.read()) 
    

    # either verify or write out proof
    if verifier_info.pProofFile is None:
        (_, ver) = v_from_pws(pFile, verifier_info.nCopies)

        # set up RDL
        if verifier_info.rdlFile is not None:
            ver.set_rdl(rdl_map, len(r_input_layer))

        start_verify = timer()
        
        try:
            from libTruePix.fp2_link import (
                write_point_file,
                run_orion_open_with_point,
                infer_gkr_input_layout,
                check_manifest_layout,
                read_commit_manifest,
            )

            pending = ver.run(proof)
            write_point_file(verifier_info.gkr_point_file, pending.input_point)

            copy_size, const_idx, const_val = infer_gkr_input_layout(
                verifier_info.pwsFile,
                verifier_info.inputFile or "input.txt",
            )
            # ver.run() already checked that the commitment in the proof is
            # the one in the manifest; also require the manifest to describe
            # the packing this circuit actually uses.
            check_manifest_layout(
                read_commit_manifest(),
                verifier_info.nCopies,
                copy_size,
                const_idx,
                const_val,
            )

            t_orion0 = timer()
            orion_res = run_orion_open_with_point(
                verifier_info.nCopies,
                0 if verifier_info.inputFile else 1,
                verifier_info.gkr_point_file,
                verifier_info.orion_result_file,
                use_zk=(VerifierInfo.usezk == 1),
                copy_size=copy_size,
                const_idx=const_idx,
                const_val=const_val,
            )
            orion_wall = timer() - t_orion0
            # The opening carries the commitment-root check and the two
            # tensor-IOP verifications; a rejected opening must not be used
            # to satisfy the GKR input claim.
            if not orion_res.ok:
                raise Exception(
                    "Orion rejected the opening (commitment root mismatch or "
                    "failed tensor-IOP check):\n%s" % orion_res.raw_stdout[-4000:]
                )
            if orion_res.value is None:
                raise Exception(
                    "Orion did not return an Fp2 opening value. "
                    "Ensure linearPC_multi_open[_zk] reads TRUEPIX_GKR_POINT_FILE "
                    "and writes TRUEPIX_ORION_RESULT_FILE."
                )
            ver.finish_input(orion_res.value)
            # Sum of all Orion "Verification time" lines (ZK: mask + masked).
            orion_open_time = orion_res.verification_time
            if orion_open_time is None:
                raise Exception(
                    "Orion did not report Verification time in stdout. "
                    "Ensure linearPC_multi_open[_zk] reports Verification time."
                )
            # Exclude Orion open wall time from Circuit Verify Time.
            verifier_info.timing_data["_orion_wall"] = orion_wall
        except Exception as e: # pylint: disable=broad-except
            verifier_info.Log.log("Verification failed: %s" % e, True)
            verifier_info.Log.log(traceback.format_exc(), True)
            orion_open_time = None
            verification_failed = True
        else:
            verifier_info.Log.log("Verification succeeded.", True)
        
        end_verify = timer()
        verifier_info.timing_data['total_verify'] = end_verify - start_verify
        # Orion open runs inside the same timer window; subtract it so
        # "Circuit Verify Time" is GKR-only.
        orion_wall = verifier_info.timing_data.pop("_orion_wall", 0.0)
        if orion_wall:
            verifier_info.timing_data['total_verify'] = max(
                0.0, verifier_info.timing_data['total_verify'] - orion_wall
            )
    else:
        with open(verifier_info.pProofFile, 'wb') as fh:
            fh.write(bz2.compress(proof))
        orion_open_time = None
        
    print_metric("Circuit Verify Time", f"{verifier_info.timing_data['total_verify']:.6f}", "seconds")
    hyrax_verify_time = verifier_info.timing_data['total_verify']
    # VOLE correlations consumed during circuit verify (verifier's p view).
    try:
        from libTruePix.fp2_link import format_vole_usage_metrics
        for name, value, unit in format_vole_usage_metrics(getattr(ver, "com", None), "Verifier"):
            print_metric(name, value, unit)
    except Exception:
        pass
    
    # Orion open already performed above for input binding.
    if orion_open_time is None:
        orion_open_time = 0.0
    
    if orion_open_time is None:
        orion_open_time = 0.0
    print_metric("Input Verify Time", f"{orion_open_time:.6f}", "seconds")

    # 5. Verify the signer's attestation over the Orion commitment.
    # This used to reference vk/signature/message, none of which existed, so
    # the NameError was swallowed by a bare except and the result was never
    # even printed.
    sig_ok, ecdsa_verify_time, sig_detail = attest.verify(VerifierInfo.usezk)

    # Print ECDSA metrics
    print_metric("Signature Verify Result", "Success" if sig_ok else "Failed")
    print_metric("Signature Verify Time", f"{ecdsa_verify_time:.6f}", "seconds")
    if not sig_ok:
        verifier_info.Log.log("Signature verification failed: %s" % sig_detail, True)
        verification_failed = True
    
    # Overall statistics
    print_section_header("Overall Verify Performance")
    total_Verify_time = (hyrax_verify_time + 
                 orion_open_time + 
                 ecdsa_verify_time)
    
    print_metric("TOTAL Verify Time", f"{total_Verify_time:.6f}", "seconds")
    print_metric("Max Memory Usage", f"{resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024:.2f}", "MB")

    return not verification_failed


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
    VerifierInfo.userandom = 0
    if VerifierInfo.inputFile is None:
        VerifierInfo.inputFile = "input.txt"

    ok = run_truepix(VerifierInfo)

    # The ExtVOLE files (vole_ext_*) were not covered by this glob, so every
    # run left ~90MB behind.
    for pattern in ("vole_verifier_*.json", "vole_ext_verifier_*.json"):
        for file_path in glob.glob(pattern):
            try:
                os.remove(file_path)
                print(f"Deleted VOLE verifier file: {file_path}")
            except OSError as e:
                print(f"Error deleting {file_path}: {e}")

    if not ok:
        print("ERROR: verification failed; see the log above for details.")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
