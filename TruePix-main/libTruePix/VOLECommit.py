#!/usr/bin/python3
#
# VOLE (Vector Oblivious Linear Evaluation) 承诺方案实现
# 基于VOLE协议构建的承诺库，类比Pedersen承诺的功能

import json
from libTruePix.gateprover_vole import GateFunctionsVC
from libTruePix.circuitverifier import VerifierIOMLExt
from itertools import chain
import libTruePix.util as util
from libTruePix.defs import Defs
from typing import List, Tuple

class VOLECommit(object):
    """
    VOLE承诺主类，合并发送方和接收方功能
    实现与Pedersen承诺类似的功能接口，但基于VOLE协议原理
    
    核心变量说明:
    - q: 有限域大小(质数)
    - delta: 接收方的私有delta值
    - u: 发送方的固定u值(标量)
    - v: 发送方的v值列表(每个承诺对应一个v)
    - p: 接收方的p值列表(预先计算好的验证值)
    - messages: 存储承诺的消息列表
    - r: 存储承诺的随机数列表
    - uv_primes: 存储接收的承诺值(u_m, v_m)列表
    """

    def __init__(self, field_size=None, delta=None, rec=None, fs=None):
        """
        初始化VOLE承诺对象
        
        参数:
        :param field_size: 有限域大小(质数)
        :param delta: 接收方的私有delta值(若为None则随机生成)
        :param rec: 记录器对象
        :param fs: Fiat-Shamir随机预言机对象
        
        初始化流程:
        1. 设置有限域大小
        2. 生成或接收delta值
        3. 初始化其他变量
        """
        self.q = int(field_size) if field_size is not None else Defs.prime
        #self.delta = delta if delta is not None else util.rand_scalar(self.q)  #测试用，这里先选一个固定值
        self.delta = 153638010302539506362387700603596961853689011785599237290 #这里是测试值，实际使用的时候
        self.rec = rec
        self.fs = fs
        self.u = []  # 发送方的固定u值(标量)
        self.v = []  # 发送方的v值列表(每个承诺对应一个v)
        self.numVOLE=0  #当前使用的VOLE关系的数目
        self.p = []  # 接收方的p值列表(预先计算好的验证值)
        self.messages = []  # 存储承诺的消息列表
        self.r = []  # 存储承诺的随机数列表
        self.uv_primes = []  # 存储接收的承诺值(u_m, v_m)列表
        self.VOLEindex=0 #当前存储的VOLE关系数目

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
        """完全重置承诺状态"""
        self.u = util.rand_scalar(self.q)
        self.v = []
        self.p = []
        self.messages = []
        self.r = []
        self.uv_primes = []
        if self.fs:
            self.fs.reset()
        
    def _record_op(self, op_type, count=1):
        """记录运算操作到记录器"""
        if self.rec is not None:
            getattr(self.rec, f"did_{op_type}")(count)
    
    def set_field(self):
        """设置当前操作的有限域"""
        util.set_prime(self.q)
    
    def _rand_scalar(self):
        """生成随机数，优先使用Fiat-Shamir"""
        return self.fs.rand_scalar() if self.fs else util.rand_scalar(self.q)

    def load_from_file_prover(self, filename: str):
        """
        从文件加载VOLE关系(u, v)
        
        参数:
            filename: 包含(u,v)的文件路径
            
        返回:
            u和v列表的长度
        """
        with open(filename, 'r') as f:
            data = json.load(f)
            
            self.u = data['u']
            self.v = data['v']
            
        self.VOLEindex = len(self.u)
    
    def get_vole_instance(self, index: int) -> Tuple[int, int]:
        """
        获取指定索引的VOLE实例(u, v)
        
        参数:
            index: 要获取的实例索引
            
        返回:
            (u, v)元组
        """
        if self.VOLEindex <= 0:
            raise IndexError("VOLE instance index out of range")
        return (self.u[index], self.v[index])
    
    def get_all_instances(self) -> List[Tuple[int, int]]:
        """
        获取所有VOLE实例(u, v)
        
        返回:
            [(u1, v1), (u2, v2), ...]列表
        """
        return list(zip(self.u, self.v))

    def load_from_file_verifier(self, filename: str):
        """
        从文件加载VOLE关系(p, delta)
        
        参数:
            filename: 包含(p,delta)的文件路径
            
        返回:
            q列表的长度
        """
        with open(filename, 'r') as f:
            data = json.load(f)
            
            self.p = data['p']
            self.delta = data['delta']
            
        self.VOLEindex = len(self.p)
    
    def get_p_value(self, index: int) -> int:
        """
        获取指定索引的q值
        
        参数:
            index: 要获取的q值索引
            
        返回:
            p值
        """
        if self.VOLEindex <= 0:
            raise IndexError("P value index out of range")
        return self.p[index]
    
    def commit(self, m):
        """
        生成对消息m的VOLE承诺
        
        参数:
        :param m: 要承诺的消息值
        
        返回:
        :return: 承诺值(u_m, v_m)元组，其中:
                 u_m = u*r + m mod q
                 v_m = v*r mod q
        
        流程:
        1. 生成随机数r和v
        2. 计算u_m和v_m
        3. 计算接收方的验证值p
        4. 存储相关值
        """

        (u_r,v_r) = self.get_vole_instance(self.numVOLE)

        # 计算VOLE的IT-MAC
        #u_m = m % self.q #本质上来说，我们只考虑u,v关系，其中u被替换为m，因而只考虑v
        #这里还添加了一个盲化因子r，根据实际情况考虑是否去掉
        v_m = v_r % self.q
        d_m = m - u_r % self.q
        #这里需要调整，对应将校正值发送过去
        #self.p.append() #这里实际上是抽象为协商的具体过程

        self.messages.append(m)

        self._record_op('rng')
        self._record_op('add')
        self._record_op('mul')

        self.numVOLE+=1 #每进行一次承诺就对应增加一个索引
        self.VOLEindex-=1 #没进行一次承诺就消耗一个VOLE关系
        
        return v_m ,d_m #这里输出两组值，但实际上只用第一组进行运算，第二组存储在take里作为交互的一部分交给验证者
        #需要注意的是这里发送的不再是p，而是校正值，需要对应调整验证的计算方式
    
    def change_commit(self, d_m):
        """
        接收方对于承诺值进行替换，从对于随机结果的承诺到对Witness(这里是对p运算)
        
        参数:
        :param u_m: 承诺的u分量(u*r + m)
        :param v_m: 承诺的v分量(v*r)


        """

        p_u = self.get_p_value(self.numVOLE)

        p_m = p_u + d_m * self.delta #将结果替换为对m的承诺
        
        self.numVOLE+=1 #每进行一次承诺就对应增加一个索引
        self.VOLEindex-=1 #没进行一次承诺就消耗一个VOLE关系

        return p_m
    
    def pok_init(self):
        """
        初始化知识证明(PoK)
        对应Pedersen的pok_init，但使用VOLE的线性结构
        :return: (t1, t2) 随机数
        """
        t1 = self._rand_scalar()
        
        self._record_op('rng',2)
        return t1
    
    def pok_finish(self,m, v_m ,c):
        """
        完成知识证明的计算
        对应Pedersen的pok_finish，但验证方式不同
        :param m: 承诺的消息
        :param r: 随机数
        :param t1, t2: 初始随机数
        :param c: 挑战值
        :return: (z1, z2) 响应值
        :承诺值v_m=v
        :t1+c*v_m ≡ t1+ c*p_m (mod q)
        """
        z1 = (m * c) % self.q #这里先不考虑零知识性，如果需要考虑零知识性的情况下在这个基础上叠加（u,v）关系
        z2 = (v_m * c) % self.q
        
        self._record_op('mul', 2)
        return (z1, z2)
    
    def pok_check(self, z1, z2, c, pval):
        """
        验证知识证明
        VOLE特有的验证方式，使用delta进行验证
        :param z1, z2: 响应值
        :param c: 挑战值
        :param pval: 验证值
        :return: 验证是否通过
        :等式为：z1*delta+z2=c*p+u_t*delta+v_t
        """
        lhs = (z1 * self.delta + z2) % self.q
        rhs = (pval * c) % self.q
        
        self._record_op('mul', 2)
        self._record_op('add', 1)

        return lhs == rhs
    
    def open(self, m_index=0):
        """
        打开指定索引的承诺
        
        参数:
        :param m_index: 消息索引
        
        返回:
        :return: (m, u_m, v_m) 元组
        
        流程:
        1. 检查索引有效性
        2. 返回存储的消息和承诺值
        """
        if m_index >= len(self.messages):
            raise IndexError("Message index out of range")
            
        m = self.messages[m_index]
        u_m, v_m = self.uv_primes[m_index]
        return (m, u_m, v_m)
    
    def verify(self, m, p, v_m):
        """
        验证打开的承诺
        
        参数:
        :param m: 声称的消息
        :param p: 验证者存储的VOLE对应值
        :param v_m: 承诺的v分量
        
        返回:
        :return: 验证是否通过(bool)
        
        验证等式:
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
        初始化相等性测试的随机参数
        
        返回:
        :return: (t, u_t, v_t) 元组，其中:
                 t: 随机盲化因子
                 u_t: u*t mod q
                 v_t: v*t mod q
        """
        pass

    def est_eq(self, v_1, v_2, c):
        """
        相等性测试的响应计算
        
        参数:
        :param uv_1: 第一个承诺
        :param uv_2: 第二个承诺
        :param c: 挑战值
        
        返回:
        :return: z = t + (r1 - r2)*c mod q
        """
        v_z = (v_1 - v_2) * c % self.q
        #这里先这样写吧，保证验证过程可以通过

        self._record_op('sub', 2)
        self._record_op('mul', 2)
        self._record_op('add', 2)
        return v_z

    def est_eq_check(self,q_1, q_2, c, v_z):
        """
        相等性测试的验证
        
        参数:
        :param q_1 ,q_2: u_v关系的对应存储值，即验证者的存储值
        :param c: 挑战值
        :param v_z: 响应值v_z
        
        返回:
        :return: 是否通过验证(bool)
        """
        lhs = (q_1 - q_2) * c % self.q
        rhs = v_z
    
        self._record_op('sub')
        return lhs == rhs

    def est_val(self, v_r, c):
        """
        值测试的响应计算
        
        参数:
        :param v_r: 承诺的随机数
        :param c: 挑战值
        
        返回:
        :return: z = r*c mod q
        """
        v_z = (v_r * c) % self.q 

        self._record_op('mul')
        return v_z

    def est_val_check(self, p_x, c, val, v_z):
        """
        值测试的验证
        
        参数:
        :param p_x: 验证值
        :param c: 挑战值
        :param v_z: 响应值
        
        返回:
        :return: 是否通过验证(bool)
        """

        #需要修改，验证这一部分暂时先这么验证，分配弄好了以后再改
        lhs = v_z
        rhs = (p_x - val * self.delta)*c % self.q
        
        self._record_op('mul')
        self._record_op('sub')

        #测试用
        return lhs == rhs

    def prod_init(self):
        """初始化乘积证明"""
        #VOLE中目前无需初始化
        pass 

    def prod_finish(self, xvals, vval):
        """
        计算乘积证明的响应值
        
        参数:
        :param xvals: (x1, x2, prod) 元组
        :param uv_pval: (uv_1, uv_2, uv_3) 元组
        :param chal: 挑战值
        
        返回:
        :return: (a_1, a_2) 响应值
        """
        x1, x2, prod = xvals
        v_1, v_2, v_3 = vval

        a_1 = (v_1 * v_2) % self.q  # a_1 = v1 * v2
        a_2 = (x1 * v_2 + x2 * v_1 - v_3) % self.q  # a_2 = x1*v2 + x2*v1 - v3

        self._record_op('mul', 3)  
        self._record_op('sub', 1)
        self._record_op('add', 1)
        return (a_1, a_2)

    def prod_check(self,pval ,aval):
        """
        验证乘积证明
        
        参数:
        :param uv_index: 承诺索引三元组
        :param c: 挑战值
        :param a_1, a_2: 响应值
        
        返回:
        :return: 是否通过验证(bool)
        """
            
        lhs = (pval[0] * pval[1] - pval[2] * self.delta) % self.q
        rhs = (aval[0] + aval[1] * self.delta) % self.q

        self._record_op('mul', 3)
        self._record_op('add', 1)
        self._record_op('sub', 1)
        return lhs == rhs

    def multvector(self, base_vals, exp_vals): 
        """
        在有限域 q 上计算多指数运算: 
        tV_cval = sum( base_vals[i]^exp_vals[i] ) mod q
    
        参数:
            base_vals (list): 基数值列表 (整数或有限域元素)
            exp_vals (list): 指数值列表 (整数)
            q (int): 有限域的模数
    
        返回:
            int: 计算结果 tV_cval
        """
        if len(base_vals) != len(exp_vals):
            raise ValueError("base_vals 和 exp_vals 的长度必须相同")
    
        tV_cval = 0
    
        for base, exp in zip(base_vals, exp_vals):
            # 计算 base^exp mod q
            term = base * exp % self.q
            # 累加到结果
            tV_cval = (tV_cval + term) % self.q
    
        return tV_cval

    #这里需要修改，因为vole的承诺可以直接视作正常的系数

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

#考虑先修改完基于circuitnizkvole的部分，再对于向量内容进行扩展

class VOLEVecCommit(VOLECommit):
    """VOLE向量承诺实现，类比PedVecCommit"""
    
    def __init__(self, field_size=None, rec=None, maxbases=-1, fs=None):
        """
        初始化VOLE向量承诺
        :param field_size: 有限域大小
        :param rec: 记录器对象
        :param maxbases: 最大基数量(保留参数，VOLE中可能不需要)
        :param fs: Fiat-Shamir随机预言机对象
        """
        self.q = field_size if field_size is not None else Defs.prime
        self.rec = rec
        self.fs = fs
        self.vole = VOLECommit(self.q, rec=rec, fs=fs)  # 使用合并后的VOLECommit类
        self.reset()
        
    def reset(self):
        """重置内部状态"""
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
        """设置当前操作的有限域"""
        self.vole.set_field()

    def commit(self, m):
        """单个值承诺的便捷接口"""
        return self.commitvec([m])[0]
        
    def commitvec(self, xvals):
        """向量承诺
        Args:
            xvals: 要承诺的向量值列表
        Returns:
            list: 承诺值列表
        """
        if not xvals:
            raise ValueError("Cannot commit to empty vector")
        if not all(isinstance(x, int) for x in xvals):
            raise TypeError("All vector elements must be integers")
    
        try:
            # 对每个元素单独生成VOLE承诺
            cvals = [self.vole.commit(x) for x in xvals]
        
            self.xvals.append(xvals)
            self.totxvals += len(xvals)
        
            if self.rec:
                self.rec.did_mul(len(xvals))  # u*m计算
                self.rec.did_add(len(xvals))  # v - u*m计算
                self.rec.did_rng(len(xvals)*2)  # u和v的随机数生成
            
            return cvals
        except Exception as e:
            self.reset()  # 出错时重置状态
            raise RuntimeError(f"Vector commitment failed: {str(e)}")
    
    def vecpok_init(self):
        """初始化向量知识证明"""
        if self.fs is not None:
            self.rdvals = [self.fs.rand_scalar() for _ in range(len(self.xvals))]
            self.dvals = [[self.fs.rand_scalar() for _ in xvi] for xvi in self.xvals]
        else:
            self.rdvals = [util.rand_scalar(self.q) for _ in range(len(self.xvals))]
            self.dvals = [[util.rand_scalar(self.q) for _ in xvi] for xvi in self.xvals]
        
        # VOLE版本的delta计算
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
        """继续向量知识证明"""
        self.Jvec = Jvec
        self.rcont = util.rand_scalar(self.q)
        
        # 计算C值
        djval = sum((d * j) % self.q for (d, j) in zip(chain.from_iterable(self.dvals), Jvec)) % self.q
        self.Cval = (djval + self.rcont) % self.q  # 简化的线性版本
        
        if self.rec:
            self.rec.did_rng()
            self.rec.did_mul(self.totxvals)
            self.rec.did_add(self.totxvals)
            
        return self.Cval
    
    def vecpok_finish(self, j1, rs, Jxyz, rxyz, c):
        """完成向量知识证明"""
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
        """验证向量知识证明"""
        if None in (alvals, delvals, zvals, Cval, C0, Jvec, c):
            raise ValueError("Invalid input: None values detected")

        (zvecs, zdels, zc) = zvals
    
        # 检查1: 验证每个元素的线性关系
        passed = True
        for (alval, delval, zvec, zdel) in zip(alvals, delvals, zvecs, zdels):
            lhs = (alval * c + delval) % self.q
            rhs = sum((z * r) % self.q for (z, r) in zip(zvec, [zdel]*len(zvec))) % self.q
            passed = passed and (lhs == rhs)
        
            if self.rec:
                self.rec.did_mul(2)
                self.rec.did_add(len(zvec)+1)
    
        # 检查2: 验证J向量的线性关系
        jzval = sum((z * j) % self.q for (z, j) in zip(chain.from_iterable(zvecs), Jvec)) % self.q
        rhs2 = (jzval + zc) % self.q
    
        if self.rec:
            self.rec.did_mul(self.totxvals)
            self.rec.did_add(self.totxvals+1)
        
        return passed and (C0 * c + Cval) % self.q == rhs2

    def vecpok_check_lay(self, alvals, delvals, zvals, Cval, C0, xyz, Jvec, j1, Jxyzc, chal):
        """验证层的向量证明 (VOLE版本)"""
        if None in (alvals, delvals, zvals, Cval, C0, xyz, Jvec, j1, Jxyzc, chal):
            raise ValueError("Invalid input: None values detected in vecpok_check_lay")

        (X, Y, Z) = xyz
        (Jxc, Jyc, Jzc, Jcc) = Jxyzc  # 正确解包4元素元组

        # 计算j1和Jxyzc的挑战乘积
        j1c = (chal * j1) % self.q
        Jxc = (Jxc * chal) % self.q
        Jyc = (Jyc * chal) % self.q
        Jzc = (Jzc * chal) % self.q
        Jcc = (Jcc * chal) % self.q

        # 计算左侧 (VOLE版本是简单的线性组合)
        lhs2 = (C0 * j1c + X * Jxc + Y * Jyc + Z * Jzc + Cval * Jcc) % self.q

        # 计算右侧 (与通用检查相同)
        (zvecs, zdels, zc) = zvals
        jzval = sum((z * j) % self.q for (z, j) in zip(chain.from_iterable(zvecs), Jvec)) % self.q
        rhs2 = (jzval + zc) % self.q

        if self.rec:
            self.rec.did_mul(5)  # j1c, Jxc, Jyc, Jzc, Jcc
            self.rec.did_add(4)  # 4次加法
            self.rec.did_mul(self.totxvals)  # jzval计算
            self.rec.did_add(self.totxvals)  # jzval求和

        # 调用通用检查，传递正确的参数顺序
        return self.vecpok_check(alvals, delvals, zvals, lhs2, C0, Jvec, chal) and (lhs2 == rhs2)

    def vecpok_check_rdl(self, alvals, delvals, zvals, Cval, C0, xyz, Jvec, j1, Jxyzc, chal):
        """验证RDL的向量证明 (VOLE版本)"""
        X = xyz[0]
    
        # 计算j1和Jxc的挑战乘积
        j1c = (chal * j1) % self.q
        Jxc = (Jxyzc[0] * chal) % self.q
    
        # 计算左侧 (VOLE版本是简单的线性组合)
        lhs2 = (C0 * j1c + X * Jxc + Cval) % self.q
    
        # 计算右侧 (与通用检查相同)
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
        """创建多个值的知识证明"""
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


#这部分实际是根据orion来实现的，所以不用修改，正常使用就可以

class VOLEWitnessCommit(object):
    """VOLE见证承诺实现，类比WitnessCommit"""
    
    def __init__(self, com, fs=None, bitdiv=0):

        """
        初始化VOLE见证承诺
        :param com: VOLE承诺对象
        :param fs: Fiat-Shamir随机预言机对象(新增参数)
        :param bitdiv: 比特分割参数
        """
        self.com = com
        self.q = com.q
        self.bitdiv = bitdiv
        self.fs = fs  # 显式存储fs参数
        
        # 见证相关数据
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
        """生成见证承诺"""
        self.nbits = util.clog2(len(wvals))
        if self.bitdiv == 0:
            self.v1bits = 0
        else:
            self.v1bits = int(self.nbits / self.bitdiv)
        self.v2bits = self.nbits - self.v1bits
        
        # 构建矩阵形式的见证
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
        
        # VOLE版本的见证承诺
        for row in self.tvals:
            sval = self._rand_scalar()  # 改为使用内部方法
            cval = sum((x * sval) % self.q for x in row) % self.q
            self.svals.append(sval)
            cvals.append(cval)
        
        if self.com.rec:
            self.com.rec.did_rng(len(self.tvals))
            self.com.rec.did_mul(len(self.tvals[0]) * len(self.tvals))
            self.com.rec.did_add(len(self.tvals[0]) * len(self.tvals) - len(self.tvals))
            
        return cvals
    
    def _rand_scalar(self):
        """内部随机数生成方法，优先使用fs"""
        return util.rand_scalar(self.q)
    
    def set_rvals(self, rvals, r0val):
        """设置随机值"""
        self.r0val = r0val
        
        if self.nbits is not None:
            assert len(rvals) == self.nbits
        else:
            self.nbits = len(rvals)
            self.v1bits = self.nbits // 2
            self.v2bits = self.nbits - self.v1bits
        
        # VOLE版本的beta计算
        self.v1vals = [self._rand_scalar() for _ in range(self.v1bits)]
        self.v2vals = [self._rand_scalar() for _ in range(self.v2bits)]

    def eval_init(self):
        """初始化评估"""
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
        """完成评估"""
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
        """验证见证评估
        参数顺序调整为: 先输入相关参数，后验证相关参数
        """
        if None in (cvals, zvals, zh, zc, chal, zeta, vxeval, aval, Cval):
            raise ValueError("Invalid input: None values detected in eval_check")
        if not all((self.v1vals, self.v2vals, self.r0val)):
            raise ValueError("Witness commit not properly initialized")
    
        # 验证第一部分: 多项式关系
        lhs1 = (sum((c * v) % self.q for (c, v) in zip(cvals, self.v1vals)) * chal + aval) % self.q
        rhs1 = (sum((z * r) % self.q for (z, r) in zip(zvals, self.v2vals)) + zh) % self.q
    
        # 验证第二部分: 包含r0val的正确计算
        lhs2 = ((zeta * vxeval * self.r0val) * chal + Cval) % self.q
        zV2 = (sum((zv * v2v) % self.q for (zv, v2v) in zip(zvals, self.v2vals)) * self.r0val) % self.q
        rhs2 = (zV2 + zc) % self.q
    
        if self.com.rec:
            n_mul = len(cvals) + len(zvals) * 2 + 4  # c*v1, z*v2, zeta*vxeval*r0, zV2*r0
            n_add = len(cvals) + len(zvals) * 2 + 2  # sums and final additions
            self.com.rec.did_mul(n_mul)
            self.com.rec.did_add(n_add)
    
        return lhs1 == rhs1 and lhs2 == rhs2
