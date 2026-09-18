#!/usr/bin/python3
#
# VOLE (Vector Oblivious Linear Evaluation) Commitment Scheme Implementation
# Commitment library built on VOLE protocol, analogous to Pedersen commitment functionality

import json
from libTruePix.gateprover_vole import GateFunctionsVC
from libTruePix.circuitverifier import VerifierIOMLExt
from itertools import chain
import libTruePix.util as util
from libTruePix.defs import Defs
from typing import List, Tuple

class VOLECommit(object):
    """
    Main VOLE commitment class, combining sender and receiver functionality
    Implements interface similar to Pedersen commitment, but based on VOLE protocol principles
    
    Core variable descriptions:
    - q: Finite field size (prime)
    - delta: Receiver's private delta value
    - u: Sender's fixed u value (scalar)
    - v: Sender's list of v values (one per commitment)
    - p: Receiver's list of p values (precomputed verification values)
    - messages: List of committed messages
    - r: List of commitment random numbers
    - uv_primes: List of received commitment values (u_m, v_m)
    """

    def __init__(self, field_size=None, delta=None, rec=None, fs=None):
        """
        Initialize VOLE commitment object
        
        Parameters:
        :param field_size: Finite field size (prime)
        :param delta: Receiver's private delta value (randomly generated if None)
        :param rec: Recorder object
        :param fs: Fiat-Shamir random oracle object
        
        Initialization flow:
        1. Set finite field size
        2. Generate or receive delta value
        3. Initialize other variables
        """
        self.q = int(field_size) if field_size is not None else Defs.prime
        #self.delta = delta if delta is not None else util.rand_scalar(self.q)  # For testing, using a fixed value here
        self.delta = 153638010302539506362387700603596961853689011785599237290  # This is a test value; in production use a proper random value
        self.rec = rec
        self.fs = fs
        self.u = []  # Sender's fixed u value (scalar)
        self.v = []  # Sender's list of v values (one per commitment)
        self.numVOLE = 0  # Number of VOLE relationships currently used
        self.p = []  # Receiver's list of p values (precomputed verification values)
        self.messages = []  # List of committed messages
        self.r = []  # List of commitment random numbers
        self.uv_primes = []  # List of received commitment values (u_m, v_m)
        self.VOLEindex = 0  # Number of stored VOLE relationships

    def used_vole_stats(self):
        """
        Return (count, bytes) for VOLE correlations consumed so far.

        Prover stores (u, v) per relation; verifier stores p. Element size is
        the canonical byte length of the active field modulus.
        """
        count = int(self.numVOLE)
        elem_bytes = max(1, (int(self.q).bit_length() + 7) // 8)
        if self.u:
            return count, count * 2 * elem_bytes
        return count, count * 1 * elem_bytes

    def reset(self):
        """Completely reset commitment state"""
        self.u = util.rand_scalar(self.q)
        self.v = []
        self.p = []
        self.messages = []
        self.r = []
        self.uv_primes = []
        if self.fs:
            self.fs.reset()
        
    def _record_op(self, op_type, count=1):
        """Record operation to recorder"""
        if self.rec is not None:
            getattr(self.rec, f"did_{op_type}")(count)
    
    def set_field(self):
        """Set the finite field for current operation"""
        util.set_prime(self.q)
    
    def _rand_scalar(self):
        """Generate random number, prioritizing Fiat-Shamir"""
        return self.fs.rand_scalar() if self.fs else util.rand_scalar(self.q)

    def load_from_file_prover(self, filename: str):
        """
        Load VOLE relationships (u, v) from file
        
        Parameters:
            filename: Path to file containing (u, v)
            
        Returns:
            Length of u and v lists
        """
        with open(filename, 'r') as f:
            data = json.load(f)
            
            self.u = data['u']
            self.v = data['v']
            
        self.VOLEindex = len(self.u)
    
    def get_vole_instance(self, index: int) -> Tuple[int, int]:
        """
        Get VOLE instance (u, v) at specified index
        
        Parameters:
            index: Index of instance to retrieve
            
        Returns:
            (u, v) tuple
        """
        if self.VOLEindex <= 0:
            raise IndexError("VOLE instance index out of range")
        return (self.u[index], self.v[index])
    
    def get_all_instances(self) -> List[Tuple[int, int]]:
        """
        Get all VOLE instances (u, v)
        
        Returns:
            List of [(u1, v1), (u2, v2), ...]
        """
        return list(zip(self.u, self.v))

    def load_from_file_verifier(self, filename: str):
        """
        Load VOLE relationships (p, delta) from file
        
        Parameters:
            filename: Path to file containing (p, delta)
            
        Returns:
            Length of p list
        """
        with open(filename, 'r') as f:
            data = json.load(f)
            
            self.p = data['p']
            self.delta = data['delta']
            
        self.VOLEindex = len(self.p)
    
    def get_p_value(self, index: int) -> int:
        """
        Get p value at specified index
        
        Parameters:
            index: Index of p value to retrieve
            
        Returns:
            p value
        """
        if self.VOLEindex <= 0:
            raise IndexError("P value index out of range")
        return self.p[index]
    
    def commit(self, m):
        """
        Generate VOLE commitment for message m
        
        Parameters:
        :param m: Message value to commit
        
        Returns:
        :return: Commitment value (u_m, v_m) tuple, where:
                 u_m = u*r + m mod q
                 v_m = v*r mod q
        
        Flow:
        1. Generate random numbers r and v
        2. Compute u_m and v_m
        3. Compute receiver's verification value p
        4. Store related values
        """

        (u_r, v_r) = self.get_vole_instance(self.numVOLE)

        # Compute VOLE's IT-MAC
        #u_m = m % self.q  # Essentially we only consider u, v relationship, where u is replaced by m, so only v is considered
        # A blinding factor r is added here, adjust according to actual needs
        v_m = v_r % self.q
        d_m = m - u_r % self.q
        # Adjustments needed here, corresponding to sending the correction value
        #self.p.append()  # This is abstracted as a specific negotiation process

        #self.messages.append(m)

        self._record_op('rng')
        self._record_op('add')
        self._record_op('mul')

        self.numVOLE += 1  # Each commitment increments the index
        self.VOLEindex -= 1  # Each commitment consumes one VOLE relationship
        
        return v_m, d_m  # Output two sets of values, but only the first is used for computation; the second is stored in take and sent to the verifier as part of the interaction
        # Note that what is sent here is no longer p, but the correction value, requiring corresponding adjustment to the verification calculation method
    
    def change_commit(self, d_m):
        """
        Receiver replaces the commitment value, from commitment to random result to commitment to Witness (here for p computation)
        
        Parameters:
        :param u_m: u component of commitment (u*r + m)
        :param v_m: v component of commitment (v*r)
        """

        p_u = self.get_p_value(self.numVOLE)

        p_m = p_u + d_m * self.delta  # Replace result with commitment to m
        
        self.numVOLE += 1  # Each commitment increments the index
        self.VOLEindex -= 1  # Each commitment consumes one VOLE relationship

        return p_m
    
    def pok_init(self):
        """
        Initialize proof of knowledge (PoK)
        Corresponds to Pedersen's pok_init, but using VOLE's linear structure
        :return: (t1, t2) random numbers
        """
        t1 = self._rand_scalar()
        
        self._record_op('rng', 2)
        return t1
    
    def pok_finish(self, m, v_m, c):
        """
        Complete proof of knowledge computation
        Corresponds to Pedersen's pok_finish, but with different verification method
        :param m: Committed message
        :param r: Random number
        :param t1, t2: Initial random numbers
        :param c: Challenge value
        :return: (z1, z2) response values
        :commitment value v_m=v
        :t1+c*v_m ≡ t1+ c*p_m (mod q)
        """
        z1 = (m * c) % self.q  # Zero-knowledge not considered here; if needed, superimpose (u, v) relationship
        z2 = (v_m * c) % self.q
        
        self._record_op('mul', 2)
        return (z1, z2)
    
    def pok_check(self, z1, z2, c, pval):
        """
        Verify proof of knowledge
        VOLE-specific verification method using delta
        :param z1, z2: Response values
        :param c: Challenge value
        :param pval: Verification value
        :return: Whether verification passes
        :Equation: z1*delta+z2=c*p+u_t*delta+v_t
        """
        lhs = (z1 * self.delta + z2) % self.q
        rhs = (pval * c) % self.q
        
        self._record_op('mul', 2)
        self._record_op('add', 1)

        return lhs == rhs
    
    def open(self, m_index=0):
        """
        Open commitment at specified index
        
        Parameters:
        :param m_index: Message index
        
        Returns:
        :return: (m, u_m, v_m) tuple
        
        Flow:
        1. Check index validity
        2. Return stored message and commitment values
        """
        if m_index >= len(self.messages):
            raise IndexError("Message index out of range")
            
        m = self.messages[m_index]
        u_m, v_m = self.uv_primes[m_index]
        return (m, u_m, v_m)
    
    def verify(self, m, p, v_m):
        """
        Verify opened commitment
        
        Parameters:
        :param m: Claimed message
        :param p: Verifier's stored VOLE corresponding value
        :param v_m: v component of commitment
        
        Returns:
        :return: Whether verification passes (bool)
        
        Verification equation:
        delta*u_m + v_m ≡ p + delta*u*r mod q
        """
        if not isinstance(m, int):
            raise TypeError("m must be integer")
    
        lhs = self.delta * m + v_m % self.q
        rhs = p % self.q
    
        if self.rec:
            self.rec.did_mul(1)
            self.rec.did_add(1)
    
        return lhs == rhs
    
    def est_init(self):
        """
        Initialize random parameters for equality test
        
        Returns:
        :return: (t, u_t, v_t) tuple, where:
                 t: Random blinding factor
                 u_t: u*t mod q
                 v_t: v*t mod q
        """
        pass

    def est_eq(self, v_1, v_2, c):
        """
        Response computation for equality test
        
        Parameters:
        :param uv_1: First commitment
        :param uv_2: Second commitment
        :param c: Challenge value
        
        Returns:
        :return: z = t + (r1 - r2)*c mod q
        """
        v_z = (v_1 - v_2) * c % self.q
        # Written this way for now to ensure verification passes

        self._record_op('sub', 2)
        self._record_op('mul', 2)
        self._record_op('add', 2)
        return v_z

    def est_eq_check(self, q_1, q_2, c, v_z):
        """
        Verification for equality test
        
        Parameters:
        :param q_1, q_2: Corresponding stored values for u_v relationship, i.e., verifier's stored values
        :param c: Challenge value
        :param v_z: Response value v_z
        
        Returns:
        :return: Whether verification passes (bool)
        """
        lhs = (q_1 - q_2) * c % self.q
        rhs = v_z
    
        self._record_op('sub')
        return lhs == rhs

    def est_val(self, v_r, c):
        """
        Response computation for value test
        
        Parameters:
        :param v_r: Commitment random number
        :param c: Challenge value
        
        Returns:
        :return: z = r*c mod q
        """
        v_z = (v_r * c) % self.q 

        self._record_op('mul')
        return v_z

    def est_val_check(self, p_x, c, val, v_z):
        """
        Verification for value test
        
        Parameters:
        :param p_x: Verification value
        :param c: Challenge value
        :param v_z: Response value
        
        Returns:
        :return: Whether verification passes (bool)
        """

        # Needs modification; verification part written this way for now, will change after allocation is done
        lhs = v_z
        rhs = (p_x - val * self.delta) * c % self.q
        
        self._record_op('mul')
        self._record_op('sub')

        # For testing
        return lhs == rhs

    def prod_init(self):
        """Initialize product proof"""
        # No initialization needed in VOLE currently
        pass 

    def prod_finish(self, xvals, vval):
        """
        Compute response values for product proof
        
        Parameters:
        :param xvals: (x1, x2, prod) tuple
        :param uv_pval: (uv_1, uv_2, uv_3) tuple
        :param chal: Challenge value
        
        Returns:
        :return: (a_1, a_2) response values
        """
        x1, x2, prod = xvals
        v_1, v_2, v_3 = vval

        a_1 = (v_1 * v_2) % self.q  # a_1 = v1 * v2
        a_2 = (x1 * v_2 + x2 * v_1 - v_3) % self.q  # a_2 = x1*v2 + x2*v1 - v3

        self._record_op('mul', 3)  
        self._record_op('sub', 1)
        self._record_op('add', 1)
        return (a_1, a_2)

    def prod_check(self, pval, aval):
        """
        Verify product proof
        
        Parameters:
        :param uv_index: Commitment index triplet
        :param c: Challenge value
        :param a_1, a_2: Response values
        
        Returns:
        :return: Whether verification passes (bool)
        """
            
        lhs = (pval[0] * pval[1] - pval[2] * self.delta) % self.q
        rhs = (aval[0] + aval[1] * self.delta) % self.q

        self._record_op('mul', 3)
        self._record_op('add', 1)
        self._record_op('sub', 1)
        return lhs == rhs
        
    def prod_check_zk(self, pval, pval_m, aval):
        """
        Verify product proof
        
        Parameters:
        :param uv_index: Commitment index triplet
        :param c: Challenge value
        :param a_1, a_2: Response values
        
        Returns:
        :return: Whether verification passes (bool)
        """
        lhs_1 = (pval[0] * pval[1] - pval[2] * self.delta) % self.q
        lhs_2 = (pval_m[0] * pval_m[1] - pval_m[2] * self.delta) % self.q
        lhs = lhs_1 + lhs_2 % self.q
        rhs = (aval[0] + aval[1] * self.delta) % self.q

        self._record_op('mul', 3)
        self._record_op('add', 1)
        self._record_op('sub', 1)
        return lhs == rhs

    def multvector(self, base_vals, exp_vals): 
        """
        Compute multi-exponentiation in finite field q: 
        tV_cval = sum( base_vals[i]^exp_vals[i] ) mod q
    
        Parameters:
            base_vals (list): List of base values (integers or finite field elements)
            exp_vals (list): List of exponent values (integers)
            q (int): Modulus of the finite field
    
        Returns:
            int: Computation result tV_cval
        """
        if len(base_vals) != len(exp_vals):
            raise ValueError("Lengths of base_vals and exp_vals must be equal")
    
        tV_cval = 0
    
        for base, exp in zip(base_vals, exp_vals):
            # Compute base^exp mod q
            term = base * exp % self.q
            # Accumulate to result
            tV_cval = (tV_cval + term) % self.q
    
        return tV_cval

    # Needs modification because VOLE commitments can be directly treated as normal coefficients

    def tV_eval(self, cvals, mlext_evals, mlx_z2):
        base_vals = []
        exp_vals = []
        for (idx, elm) in enumerate(mlext_evals):
            exp_vals.append((elm * mlx_z2) % self.q)
            base_vals.append(GateFunctionsVC[idx](cvals[0], cvals[1], cvals[2], self.rec))
        tV_cval = self.multvector(base_vals, exp_vals)

        if self.rec:
            nops = len(mlext_evals)
            self.rec.did_mul(nops)
            self.rec.did_add(nops)

        return tV_cval

# Consider modifying the circuitnizkvole part first, then extending the vector content

class VOLEVecCommit(VOLECommit):
    """VOLE vector commitment implementation, analogous to PedVecCommit"""
    
    def __init__(self, field_size=None, rec=None, maxbases=-1, fs=None):
        """
        Initialize VOLE vector commitment
        :param field_size: Finite field size
        :param rec: Recorder object
        :param maxbases: Maximum number of bases (reserved parameter, may not be needed in VOLE)
        :param fs: Fiat-Shamir random oracle object
        """
        self.q = field_size if field_size is not None else Defs.prime
        self.rec = rec
        self.fs = fs
        self.vole = VOLECommit(self.q, rec=rec, fs=fs)  # Using the merged VOLECommit class
        self.reset()
        
    def reset(self):
        """Reset internal state"""
        self.rvals = []
        self.xvals = []
        self.totxvals = 0
        self.delvals = []
        self.rdvals = None
        self.dvals = None
        self.Jvec = None
        self.rcont = None
        self.Cval = None
        
    def set_field(self):
        """Set the finite field for current operation"""
        self.vole.set_field()

    def commit(self, m):
        """Convenience interface for single value commitment"""
        return self.commitvec([m])[0]
        
    def commitvec(self, xvals):
        """Vector commitment
        Args:
            xvals: List of vector values to commit
        Returns:
            list: List of commitment values
        """
        if not xvals:
            raise ValueError("Cannot commit to empty vector")
        if not all(isinstance(x, int) for x in xvals):
            raise TypeError("All vector elements must be integers")
    
        try:
            # Generate VOLE commitment for each element individually
            cvals = [self.vole.commit(x) for x in xvals]
        
            self.xvals.append(xvals)
            self.totxvals += len(xvals)
        
            if self.rec:
                self.rec.did_mul(len(xvals))  # u*m computation
                self.rec.did_add(len(xvals))  # v - u*m computation
                self.rec.did_rng(len(xvals)*2)  # u and v random number generation
            
            return cvals
        except Exception as e:
            self.reset()  # Reset state on error
            raise RuntimeError(f"Vector commitment failed: {str(e)}")
    
    def vecpok_init(self):
        """Initialize vector proof of knowledge"""
        if self.fs is not None:
            self.rdvals = [self.fs.rand_scalar() for _ in range(len(self.xvals))]
            self.dvals = [[self.fs.rand_scalar() for _ in xvi] for xvi in self.xvals]
        else:
            self.rdvals = [util.rand_scalar(self.q) for _ in range(len(self.xvals))]
            self.dvals = [[util.rand_scalar(self.q) for _ in xvi] for xvi in self.xvals]
        
        # VOLE version delta computation
        self.delvals = []
        for (dv, rdv) in zip(self.dvals, self.rdvals):
            delta = sum((d * r) % self.q for (d, r) in zip(dv, [rdv]*len(dv))) % self.q
            self.delvals.append(delta)
        
        if self.rec:
            self.rec.did_rng(len(self.xvals) + self.totxvals)
            self.rec.did_mul(self.totxvals)
            self.rec.did_add(self.totxvals - len(self.xvals))
            
        return self.delvals
    
    def vecpok_cont(self, Jvec):
        """Continue vector proof of knowledge"""
        self.Jvec = Jvec
        self.rcont = util.rand_scalar(self.q)
        
        # Compute C value
        djval = sum((d * j) % self.q for (d, j) in zip(chain.from_iterable(self.dvals), Jvec)) % self.q
        self.Cval = (djval + self.rcont) % self.q  # Simplified linear version
        
        if self.rec:
            self.rec.did_rng()
            self.rec.did_mul(self.totxvals)
            self.rec.did_add(self.totxvals)
            
        return self.Cval
    
    def vecpok_finish(self, j1, rs, Jxyz, rxyz, c):
        """Complete vector proof of knowledge"""
        zvecs = [[(c * x + d) % self.q for (x, d) in zip(xs, ds)] 
                 for (xs, ds) in zip(self.xvals, self.dvals)]
        
        zdels = [(c * rv + rdv) % self.q for (rv, rdv) in zip([rs]*len(self.rdvals), self.rdvals)]
        
        jrval = (j1 * rs) % self.q
        jrval += sum((j * r) % self.q for (j, r) in zip(Jxyz, rxyz))
        jrval %= self.q
        zc = (c * jrval + self.rcont) % self.q
        
        if self.rec:
            nxyz = min(len(Jxyz), len(rxyz))
            self.rec.did_mul(self.totxvals + len(zdels) + nxyz + 2)
            self.rec.did_add(self.totxvals + len(zdels) + nxyz + 1)
            
        return (zvecs, zdels, zc)
    
    def vecpok_check(self, alvals, delvals, zvals, Cval, C0, Jvec, c):
        """Verify vector proof of knowledge"""
        if None in (alvals, delvals, zvals, Cval, C0, Jvec, c):
            raise ValueError("Invalid input: None values detected")

        (zvecs, zdels, zc) = zvals
    
        # Check 1: Verify linear relationship for each element
        passed = True
        for (alval, delval, zvec, zdel) in zip(alvals, delvals, zvecs, zdels):
            lhs = (alval * c + delval) % self.q
            rhs = sum((z * r) % self.q for (z, r) in zip(zvec, [zdel]*len(zvec))) % self.q
            passed = passed and (lhs == rhs)
        
            if self.rec:
                self.rec.did_mul(2)
                self.rec.did_add(len(zvec)+1)
    
        # Check 2: Verify linear relationship for J vector
        jzval = sum((z * j) % self.q for (z, j) in zip(chain.from_iterable(zvecs), Jvec)) % self.q
        rhs2 = (jzval + zc) % self.q
    
        if self.rec:
            self.rec.did_mul(self.totxvals)
            self.rec.did_add(self.totxvals+1)
        
        return passed and (C0 * c + Cval) % self.q == rhs2

    def vecpok_check_lay(self, alvals, delvals, zvals, Cval, C0, xyz, Jvec, j1, Jxyzc, chal):
        """Verify layer vector proof (VOLE version)"""
        if None in (alvals, delvals, zvals, Cval, C0, xyz, Jvec, j1, Jxyzc, chal):
            raise ValueError("Invalid input: None values detected in vecpok_check_lay")

        (X, Y, Z) = xyz
        (Jxc, Jyc, Jzc, Jcc) = Jxyzc  # Correctly unpack 4-element tuple

        # Compute challenge products for j1 and Jxyzc
        j1c = (chal * j1) % self.q
        Jxc = (Jxc * chal) % self.q
        Jyc = (Jyc * chal) % self.q
        Jzc = (Jzc * chal) % self.q
        Jcc = (Jcc * chal) % self.q

        # Compute left side (VOLE version uses simple linear combination)
        lhs2 = (C0 * j1c + X * Jxc + Y * Jyc + Z * Jzc + Cval * Jcc) % self.q

        # Compute right side (same as general check)
        (zvecs, zdels, zc) = zvals
        jzval = sum((z * j) % self.q for (z, j) in zip(chain.from_iterable(zvecs), Jvec)) % self.q
        rhs2 = (jzval + zc) % self.q

        if self.rec:
            self.rec.did_mul(5)  # j1c, Jxc, Jyc, Jzc, Jcc
            self.rec.did_add(4)  # 4 additions
            self.rec.did_mul(self.totxvals)  # jzval computation
            self.rec.did_add(self.totxvals)  # jzval summation

        # Call general check with correct parameter order
        return self.vecpok_check(alvals, delvals, zvals, lhs2, C0, Jvec, chal) and (lhs2 == rhs2)

    def vecpok_check_rdl(self, alvals, delvals, zvals, Cval, C0, xyz, Jvec, j1, Jxyzc, chal):
        """Verify RDL vector proof (VOLE version)"""
        X = xyz[0]
    
        # Compute challenge products for j1 and Jxc
        j1c = (chal * j1) % self.q
        Jxc = (Jxyzc[0] * chal) % self.q
    
        # Compute left side (VOLE version uses simple linear combination)
        lhs2 = (C0 * j1c + X * Jxc + Cval) % self.q
    
        # Compute right side (same as general check)
        (zvecs, zdels, zc) = zvals
        jzval = sum((z * j) % self.q for (z, j) in zip(chain.from_iterable(zvecs), Jvec)) % self.q
        rhs2 = (jzval + zc) % self.q
    
        if self.rec:
            self.rec.did_mul(2)
            self.rec.did_add(1)
            self.rec.did_mul(self.totxvals)
            self.rec.did_add(self.totxvals)
    
        return self.vecpok_check(alvals, delvals, zvals, lhs2, Jvec, chal)

    def create_pok(self, vals):
        """Create proof of knowledge for multiple values"""
        rvals = []
        for val in vals:
            v_prime = self.vole.commit(val)
            t1, t2 = self.pok_init()
            self.fs.put((v_prime, t1))
            chal = self.fs.rand_scalar()
            z1, z2 = self.pok_finish(val, v_prime, t1, t2, chal)
            self.fs.put((z1, z2))
            rvals.append(v_prime)
        return rvals


class VOLEWitnessCommit(object):
    """VOLE witness commitment implementation, analogous to WitnessCommit"""
    
    def __init__(self, com, fs=None, bitdiv=0):

        """
        Initialize VOLE witness commitment
        :param com: VOLE commitment object
        :param fs: Fiat-Shamir random oracle object (new parameter)
        :param bitdiv: Bit division parameter
        """
        self.com = com
        self.q = com.q
        self.bitdiv = bitdiv
        self.fs = fs  # Explicitly store fs parameter
        
        # Witness related data
        self.tvals = None
        self.nbits = None
        self.v1bits = None
        self.v2bits = None
        self.svals = None
        self.v1vals = None
        self.v2vals = None
        self.r0val = None
        self.rhval = None
        self.rcval = None
        self.dvals = None
    
    def witness_commit(self, wvals):
        """Generate witness commitment"""
        self.nbits = util.clog2(len(wvals))
        if self.bitdiv == 0:
            self.v1bits = 0
        else:
            self.v1bits = int(self.nbits / self.bitdiv)
        self.v2bits = self.nbits - self.v1bits
        
        # Build matrix form of witness
        v1len = 2 ** self.v1bits
        v2len = 2 ** self.v2bits
        self.tvals = []
        wlen = len(wvals)
        
        for i in range(v1len):
            row = [wvals[i + v1len * j] if i + v1len * j < wlen else 0 
                   for j in range(v2len)]
            self.tvals.append(row)
        
        self.svals = []
        cvals = []
        
        # VOLE version witness commitment
        for row in self.tvals:
            sval = self._rand_scalar()  # Changed to use internal method
            cval = sum((x * sval) % self.q for x in row) % self.q
            self.svals.append(sval)
            cvals.append(cval)
        
        if self.com.rec:
            self.com.rec.did_rng(len(self.tvals))
            self.com.rec.did_mul(len(self.tvals[0]) * len(self.tvals))
            self.com.rec.did_add(len(self.tvals[0]) * len(self.tvals) - len(self.tvals))
            
        return cvals
    
    def _rand_scalar(self):
        """Internal random number generation method, prioritizing fs"""
        return util.rand_scalar(self.q)
    
    def set_rvals(self, rvals, r0val):
        """Set random values"""
        self.r0val = r0val
        
        if self.nbits is not None:
            assert len(rvals) == self.nbits
        else:
            self.nbits = len(rvals)
            self.v1bits = self.nbits // 2
            self.v2bits = self.nbits - self.v1bits
        
        # VOLE version beta computation
        self.v1vals = [self._rand_scalar() for _ in range(self.v1bits)]
        self.v2vals = [self._rand_scalar() for _ in range(self.v2bits)]

    def eval_init(self):
        """Initialize evaluation"""
        self.rhval = self._rand_scalar()
        self.rcval = self._rand_scalar()
        self.dvals = [self._rand_scalar() for _ in range(2**self.v2bits)]
        
        aval = sum((d * r) % self.q for (d, r) in zip(self.dvals, self.v2vals)) % self.q
        aval = (aval + self.rhval) % self.q
        
        dV2 = sum((dv * v2v) % self.q for (dv, v2v) in zip(self.dvals, self.v2vals)) % self.q
        dV2 = (dV2 * self.r0val) % self.q
        Cval = (dV2 + self.rcval) % self.q
        
        if self.com.rec:
            self.com.rec.did_rng(2 + 2**self.v2bits)
            self.com.rec.did_add(2**self.v2bits)
            self.com.rec.did_mul(2**self.v2bits + 2)
            
        return (aval, Cval)
    
    def eval_finish(self, chal, szeta):
        """Complete evaluation"""
        self.nbits = None
        
        zvals = [sum((t * v) % self.q for (t, v) in zip(row, self.v1vals)) % self.q
                 for row in self.tvals]
        zvals = [(chal * z + d) % self.q for (d, z) in zip(self.dvals, zvals)]
        
        zh = (chal * sum((si * v1i) % self.q for (si, v1i) in zip(self.svals, self.v1vals)) + self.rhval) % self.q
        zc = (chal * szeta + self.rcval) % self.q
        
        if self.com.rec:
            self.com.rec.did_mul(len(zvals) + len(self.svals) + 2)
            self.com.rec.did_add(len(zvals) + len(self.svals) + 1)
            
        return (zvals, zh, zc)
    
    def eval_check(self, cvals, zvals, zh, zc, chal, zeta, vxeval, aval, Cval):
        """Verify witness evaluation
        Parameter order adjusted to: input related parameters first, then verification related parameters
        """
        if None in (cvals, zvals, zh, zc, chal, zeta, vxeval, aval, Cval):
            raise ValueError("Invalid input: None values detected in eval_check")
        if not all((self.v1vals, self.v2vals, self.r0val)):
            raise ValueError("Witness commit not properly initialized")
    
        # Verify part 1: Polynomial relationship
        lhs1 = (sum((c * v) % self.q for (c, v) in zip(cvals, self.v1vals)) * chal + aval) % self.q
        rhs1 = (sum((z * r) % self.q for (z, r) in zip(zvals, self.v2vals)) + zh) % self.q
    
        # Verify part 2: Contains correct computation of r0val
        lhs2 = ((zeta * vxeval * self.r0val) * chal + Cval) % self.q
        zV2 = (sum((zv * v2v) % self.q for (zv, v2v) in zip(zvals, self.v2vals)) * self.r0val) % self.q
        rhs2 = (zV2 + zc) % self.q
    
        if self.com.rec:
            n_mul = len(cvals) + len(zvals) * 2 + 4  # c*v1, z*v2, zeta*vxeval*r0, zV2*r0
            n_add = len(cvals) + len(zvals) * 2 + 2  # sums and final additions
            self.com.rec.did_mul(n_mul)
            self.com.rec.did_add(n_add)
    
        return lhs1 == rhs1 and lhs2 == rhs2
