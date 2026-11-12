#!/usr/bin/env python3
"""Step 4: reproducible SHA-256 SAT/SMT preimage laboratory.

Uses system libz3 (ctypes) without Python packages. Z3 bit-blasts exact
SHA-256 operations to Boolean SAT, preserving carry, XOR, Ch, and Maj.
Optional GF(2) equations are sound consequences of a lifted AND relaxation.

The parameterized task is restricted preimage search among W0 in [0, 2**n).
Unmodified SHA-256 padding and IV; 64 rounds agree with hashlib.
All timings include a model build and a separate solve measurement. Timeouts
are reported as 'unknown', NEVER interpreted as impossibility/proof.
"""
from __future__ import annotations
import argparse, ctypes as C, ctypes.util, hashlib, json, time
from pathlib import Path
from sha256_tree_lab import IV, K, TAIL, block_words, compress
from sha256_matrix_hybrid import LiftedCircuit, projected_input_system, target_equations
MASK = (1 << 32) - 1

class Z:
    def __init__(self, timeout_ms: int):
        self.lib = C.CDLL(ctypes.util.find_library('z3') or 'libz3.so.4')
        L=self.lib
        self._fun('Z3_mk_config', C.c_void_p, [])
        self._fun('Z3_del_config', None, [C.c_void_p])
        self._fun('Z3_mk_context', C.c_void_p, [C.c_void_p])
        self._fun('Z3_del_context', None, [C.c_void_p])
        self._fun('Z3_mk_solver', C.c_void_p, [C.c_void_p])
        self._fun('Z3_solver_inc_ref', None, [C.c_void_p,C.c_void_p])
        self._fun('Z3_solver_dec_ref', None, [C.c_void_p,C.c_void_p])
        self._fun('Z3_solver_assert', None, [C.c_void_p,C.c_void_p,C.c_void_p])
        self._fun('Z3_solver_check', C.c_int, [C.c_void_p,C.c_void_p])
        self._fun('Z3_solver_get_model', C.c_void_p, [C.c_void_p,C.c_void_p])
        self._fun('Z3_model_inc_ref', None, [C.c_void_p,C.c_void_p])
        self._fun('Z3_model_dec_ref', None, [C.c_void_p,C.c_void_p])
        self._fun('Z3_model_eval', C.c_bool, [C.c_void_p,C.c_void_p,C.c_void_p,C.c_bool,C.POINTER(C.c_void_p)])
        self._fun('Z3_get_numeral_uint64', C.c_bool, [C.c_void_p,C.c_void_p,C.POINTER(C.c_uint64)])
        self._fun('Z3_get_bool_value', C.c_int, [C.c_void_p,C.c_void_p])
        self._fun('Z3_mk_bv_sort', C.c_void_p, [C.c_void_p,C.c_uint])
        self._fun('Z3_mk_bool_sort', C.c_void_p, [C.c_void_p])
        self._fun('Z3_mk_string_symbol', C.c_void_p, [C.c_void_p,C.c_char_p])
        self._fun('Z3_mk_const', C.c_void_p, [C.c_void_p,C.c_void_p,C.c_void_p])
        self._fun('Z3_mk_unsigned_int64', C.c_void_p, [C.c_void_p,C.c_uint64,C.c_void_p])
        self._fun('Z3_mk_true', C.c_void_p, [C.c_void_p])
        self._fun('Z3_mk_false', C.c_void_p, [C.c_void_p])
        self._fun('Z3_mk_eq', C.c_void_p, [C.c_void_p,C.c_void_p,C.c_void_p])
        self._fun('Z3_mk_not', C.c_void_p, [C.c_void_p,C.c_void_p])
        for op in ('bvadd','bvxor','bvand','bvor','bvlshr','bvshl','bvule'):
            self._fun('Z3_mk_'+op, C.c_void_p, [C.c_void_p,C.c_void_p,C.c_void_p])
        self._fun('Z3_mk_xor', C.c_void_p, [C.c_void_p,C.c_void_p,C.c_void_p])
        self._fun('Z3_mk_and', C.c_void_p, [C.c_void_p,C.c_uint,C.POINTER(C.c_void_p)])
        self._fun('Z3_mk_extract', C.c_void_p, [C.c_void_p,C.c_uint,C.c_uint,C.c_void_p])
        self._fun('Z3_mk_params', C.c_void_p, [C.c_void_p])
        self._fun('Z3_params_inc_ref', None, [C.c_void_p,C.c_void_p])
        self._fun('Z3_params_dec_ref', None, [C.c_void_p,C.c_void_p])
        self._fun('Z3_params_set_uint', None, [C.c_void_p,C.c_void_p,C.c_void_p,C.c_uint])
        self._fun('Z3_solver_set_params', None, [C.c_void_p,C.c_void_p,C.c_void_p])
        self._fun('Z3_solver_get_reason_unknown', C.c_char_p, [C.c_void_p,C.c_void_p])
        self.cfg=L.Z3_mk_config()
        self.ctx=L.Z3_mk_context(self.cfg)
        L.Z3_del_config(self.cfg)
        self.solver=L.Z3_mk_solver(self.ctx)
        L.Z3_solver_inc_ref(self.ctx,self.solver)
        self.bvs=L.Z3_mk_bv_sort(self.ctx,32)
        self.bool_sort=L.Z3_mk_bool_sort(self.ctx)
        self.val_cache={}
        self.timeout_ms=timeout_ms
        params=L.Z3_mk_params(self.ctx); L.Z3_params_inc_ref(self.ctx,params)
        sym=L.Z3_mk_string_symbol(self.ctx,b'timeout')
        L.Z3_params_set_uint(self.ctx,params,sym,timeout_ms)
        L.Z3_solver_set_params(self.ctx,self.solver,params)
        L.Z3_params_dec_ref(self.ctx,params)
    def _fun(self,name,returns,args):
        f=getattr(self.lib,name); f.restype=returns; f.argtypes=args
    def close(self):
        if getattr(self,'solver',None):
            self.lib.Z3_solver_dec_ref(self.ctx,self.solver); self.solver=None
            self.lib.Z3_del_context(self.ctx); self.ctx=None
    def __enter__(self):return self
    def __exit__(self,*exc):self.close()
    def call(self,name,*args):return getattr(self.lib,'Z3_mk_'+name)(self.ctx,*args)
    def var(self,name,boolean=False):
        return self.call('const',self.call('string_symbol',name.encode()),self.bool_sort if boolean else self.bvs)
    def num(self,n):
        n&=MASK
        if n not in self.val_cache:self.val_cache[n]=self.call('unsigned_int64',n,self.bvs)
        return self.val_cache[n]
    def add(self,*args):
        out=args[0]
        for a in args[1:]:out=self.call('bvadd',out,a)
        return out
    def xor(self,*args):
        out=args[0]
        for a in args[1:]:out=self.call('bvxor',out,a)
        return out
    def band(self,a,b):return self.call('bvand',a,b)
    def bor(self,a,b):return self.call('bvor',a,b)
    def bnot(self,a):return self.xor(a,self.num(MASK))
    def rot(self,a,n):return self.bor(self.call('bvlshr',a,self.num(n)),self.call('bvshl',a,self.num(32-n)))
    def shr(self,a,n):return self.call('bvlshr',a,self.num(n))
    def assert_(self, expr): self.lib.Z3_solver_assert(self.ctx,self.solver,expr)
    def eq(self,a,b):return self.call('eq',a,b)
    def extract(self,a,hi,lo):return self.call('extract',hi,lo,a)
    def bool_xor(self,a,b):return self.call('xor',a,b)
    def true(self):return self.call('true')
    def false(self):return self.call('false')
    def check(self):
        tic=time.perf_counter(); res=self.lib.Z3_solver_check(self.ctx,self.solver)
        seconds=time.perf_counter()-tic
        if res == 1:
            model=self.lib.Z3_solver_get_model(self.ctx,self.solver)
            self.lib.Z3_model_inc_ref(self.ctx,model)
            return 'sat',model,seconds,None
        if res == -1:return 'unsat',None,seconds,None
        reason=self.lib.Z3_solver_get_reason_unknown(self.ctx,self.solver)
        return 'unknown',None,seconds,reason.decode() if reason else None
    def model_num(self,model,term):
        ast=C.c_void_p()
        assert self.lib.Z3_model_eval(self.ctx,model,term,True,C.byref(ast))
        value=C.c_uint64()
        assert self.lib.Z3_get_numeral_uint64(self.ctx,ast,C.byref(value))
        return value.value
    def model_bool(self,model,term):
        ast=C.c_void_p()
        assert self.lib.Z3_model_eval(self.ctx,model,term,True,C.byref(ast))
        truth=self.lib.Z3_get_bool_value(self.ctx,ast)
        assert truth in (-1,1),truth
        return truth == 1
    def release_model(self,m):
        if m:self.lib.Z3_model_dec_ref(self.ctx,m)

def sha256_bv(z, input_ast, rounds):
    w=[input_ast]+[z.num(x) for x in block_words(0)[1:]]
    big0=lambda x:z.xor(z.rot(x,2),z.rot(x,13),z.rot(x,22))
    big1=lambda x:z.xor(z.rot(x,6),z.rot(x,11),z.rot(x,25))
    small0=lambda x:z.xor(z.rot(x,7),z.rot(x,18),z.shr(x,3))
    small1=lambda x:z.xor(z.rot(x,17),z.rot(x,19),z.shr(x,10))
    for j in range(16,rounds):w.append(z.add(small1(w[j-2]),w[j-7],small0(w[j-15]),w[j-16]))
    a,b,c,d,e,f,g,h=[z.num(x) for x in IV]
    for j in range(rounds):
        ch=z.xor(z.band(e,f),z.band(z.bnot(e),g))
        maj=z.xor(z.band(a,b),z.band(a,c),z.band(b,c))
        t1=z.add(h,big1(e),ch,z.num(K[j]),w[j])
        t2=z.add(big0(a),maj)
        a,b,c,d,e,f,g,h=z.add(t1,t2),a,b,c,z.add(d,t1),e,f,g
    return [z.add(x,z.num(y)) for x,y in zip((a,b,c,d,e,f,g,h),IV)]

def add_projected_equations(z,x,rounds,n,target):
    c=LiftedCircuit(n)
    out=c.compress(rounds)
    projected=projected_input_system(target_equations(out,target),n)
    for eq in projected['input_equations']:
        bits=int(eq['coefficients_hex'],16)
        rhs=eq['rhs']
        # Parity of known input bits == rhs: GF(2) linear consequence
        indices=[i for i in range(n) if (bits>>i)&1]
        term=z.false()
        for i in indices:
            is_one=z.eq(z.extract(x,i,i),z.call('unsigned_int64',1,z.call('bv_sort',1)))
            term=z.bool_xor(term,is_one)
        z.assert_(z.eq(term,z.true() if rhs else z.false()))
    return {'rank':projected['input_constraint_rank'],
            'remaining_input_space':projected['candidate_count_under_linear_relaxation'],
            'AND_gates':len(c.gates)}

def run_xor_and(rounds, n, secret, timeout_ms=2000, target_bits=256):
    """Exact GF(2)-lifted system solved as native Boolean XOR/AND constraints.

    Unlike the linear projection, we retain EVERY nonlinear gate relation.
    This encoding can be much larger than native 32-bit bit-vector SMT.
    """
    assert 1<=rounds<=64 and 1<=n<=24 and 0<=secret<(1<<n)
    target=compress(secret,rounds)
    build0=time.perf_counter()
    lifted=LiftedCircuit(n)
    output=lifted.compress(rounds)
    with Z(timeout_ms) as z:
        inputs=[z.var('x'+str(i),boolean=True) for i in range(n)]
        gate_variables=[z.var('g'+str(i),boolean=True) for i in range(len(lifted.gates))]
        variables=inputs+gate_variables
        expr_cache={0:z.false(),1:z.true()}
        # affine input bitset: low bit is constant; bit j+1 is v_j
        def expr(e):
            if e in expr_cache:return expr_cache[e]
            out=z.true() if e&1 else z.false()
            v=e>>1
            while v:
                bit=v & -v
                j=bit.bit_length()-1
                out=z.bool_xor(out,variables[j])
                v^=bit
            expr_cache[e]=out
            return out
        for idx,(a,b) in enumerate(lifted.gates):
            args=(C.c_void_p*2)(expr(a),expr(b))
            nonlinear=z.call('and',2,args)
            z.assert_(z.eq(gate_variables[idx],nonlinear))
        count=0
        for word_index,word in enumerate(output):
            for bit,affine in enumerate(word):
                if target_bits!=256 and (word_index!=0 or bit<32-target_bits):continue
                target_bit=(target[word_index]>>bit)&1
                z.assert_(z.eq(expr(affine),z.true() if target_bit else z.false()))
                count+=1
        build_seconds=time.perf_counter()-build0
        verdict,model,solve_seconds,reason=z.check()
        recovered=None; verified=None
        if verdict=='sat':
            recovered=sum(int(z.model_bool(model,term))<<i for i,term in enumerate(inputs))
            actual=compress(recovered,rounds)
            verified=actual==target if target_bits==256 else (actual[0]>>(32-target_bits))==(target[0]>>(32-target_bits))
            assert verified,(rounds,n,recovered)
        z.release_model(model)
    return {'rounds':rounds,'unknown_bits':n,'secret':secret,'method':'xor-and','target_bits':target_bits,
            'solver':'Z3 native Boolean XOR/AND with exact lifted nonlinear gates',
            'timeout_ms':timeout_ms,'result':verdict,'reason_if_unknown':reason,
            'witness':recovered,'witness_verified':verified,'and_gates':len(lifted.gates),
            'output_constraints':count, 'affine_expr_cache_size':len(expr_cache),
            'build_seconds':round(build_seconds,5),'solve_seconds':round(solve_seconds,5),
            'total_seconds':round(time.perf_counter()-build0,5)}


def run(rounds, n, secret, mode='bv', timeout_ms=2000, target_bits=256):
    # 'bv' is native bit-vector SMT; 'hybrid' adds sound projected XOR constraints.
    if mode=='xor-and':return run_xor_and(rounds,n,secret,timeout_ms,target_bits)
    if mode not in ('bv','hybrid'):raise ValueError(mode)
    assert 1<=rounds<=64 and 1<=n<=24 and 0<=secret<(1<<n)
    assert target_bits in (8,16,32,256)
    target=compress(secret,rounds)
    build0=time.perf_counter()
    with Z(timeout_ms) as z:
        input_ast=z.var('input_W0')
        z.assert_(z.call('bvule', input_ast,z.num((1<<n)-1)))
        outputs=sha256_bv(z,input_ast,rounds)
        if target_bits==256:
            for a,b in zip(outputs,target):z.assert_(z.eq(a,z.num(b)))
        else:
            shift=32-target_bits
            z.assert_(z.eq(z.call('bvlshr',outputs[0],z.num(shift)),z.num(target[0]>>shift)))
        extras={'rank':0,'remaining_input_space':1<<n,'AND_gates':None}
        if mode=='hybrid' and target_bits==256:
            extras=add_projected_equations(z,input_ast,rounds,n,target)
        build_seconds=time.perf_counter()-build0
        verdict,model,solve_seconds,reason=z.check()
        recovered=None; matches_target=None
        if verdict=='sat':
            recovered=z.model_num(model,input_ast)
            actual=compress(recovered,rounds)
            matches_target=(actual==target if target_bits==256 else (actual[0]>>(32-target_bits))==(target[0]>>(32-target_bits)))
            assert matches_target,(rounds,n,mode,recovered)
        z.release_model(model)
        alternate_status=None;alternate_seconds=None;alternate_witness=None
        if verdict=='sat' and target_bits==256 and rounds<=8:
            z.assert_(z.call('not',z.eq(input_ast,z.num(recovered))))
            alternate_status,other_model,alternate_seconds,_=z.check()
            if alternate_status=='sat':
                alternate_witness=z.model_num(other_model,input_ast)
                assert alternate_witness!=recovered and compress(alternate_witness,rounds)==target
            z.release_model(other_model)
    total_seconds=time.perf_counter()-build0
    return {'rounds':rounds,'unknown_bits':n,'secret':secret,'method':mode,'target_bits':target_bits,
            'other_solution_check':alternate_status,'other_solution_seconds':None if alternate_seconds is None else round(alternate_seconds,5),
            'other_solution_witness':alternate_witness,
            'solver':'Z3 bit-vector to Boolean SAT', 'timeout_ms':timeout_ms,
            'result':verdict,'reason_if_unknown':reason,
            'witness':recovered,'witness_verified':matches_target,
            'build_seconds':round(build_seconds,5),'solve_seconds':round(solve_seconds,5),
            'total_seconds':round(total_seconds,5),'projection':extras}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--rounds',nargs='+',type=int,default=[1,2,4,8,16,64])
    p.add_argument('--unknown-bits',type=int,default=8)
    p.add_argument('--secret',type=int,default=173)
    p.add_argument('--timeout-ms',type=int,default=2000)
    p.add_argument('--methods',nargs='+',choices=['bv','hybrid','xor-and'],default=['bv','hybrid'])
    p.add_argument('--target-bits',type=int,choices=[8,16,32,256],default=256)
    p.add_argument('--output',default='sha256_step4_results.json')
    a=p.parse_args()
    for c in [0,a.secret,(1<<a.unknown_bits)-1]:
        assert ''.join(f'{v:08x}' for v in compress(c,64))==hashlib.sha256(c.to_bytes(4,'big')+TAIL).hexdigest()
    rows=[]
    for nround in a.rounds:
        for mode in a.methods:
            print(f'r={nround}, bits={a.unknown_bits}, method={mode}',flush=True)
            row=run(nround,a.unknown_bits,a.secret,mode,a.timeout_ms,a.target_bits)
            rows.append(row)
            print(f"   {row['result']}, build={row['build_seconds']}s, solve={row['solve_seconds']}s, witness={row['witness']}",flush=True)
    out={'experiment':'exact SHA-256 SAT/SMT with optional redundant projected XOR constraints',
         'notes':['No solution claims are made for unknown/timeout.','Full 64 rounds checked against hashlib.',
                  'Z3 solver times are not directly comparable with brute force unless encoding costs are included.',
                  'The projection computes only constraints from the linear relaxation, not full nonlinear elimination.'],
         'runs':rows}
    Path(a.output).write_text(json.dumps(out,indent=2))
    print('Saved',a.output,flush=True)

if __name__=='__main__':main()
