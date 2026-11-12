#!/usr/bin/env python3
"""SHA-256 step 3: exact GF(2) matrix / XOR-AND lifting experiment.

No external dependencies. Models authentic SHA-256 compression, starting from a
40-byte padded single block, in which the low N bits of W0 are unknown.

A bit is represented as an affine GF(2) expression over the N input bits and
new variables for nonlinear (AND) outputs. Each AND introduces the *exact*
constraint y = u & v. XOR equations are eliminated symbolically, so this is an
XOR-AND circuit (an exact quadratic Boolean system in extended variables).

IMPORTANT: Treating AND outputs as independent is only a relaxation. Its linear
rank does NOT represent a preimage attack. The report explicitly distinguishes
linear-projection constraints from the full nonlinear circuit.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import random
import time
from pathlib import Path
from sha256_tree_lab import IV, K, MASK, TAIL, block_words, compress


def rotr(x: int, n: int) -> int:
    return (x >> n | x << (32-n)) & MASK


def linear_map_matrix(fn):
    """Return 32 row bitmasks for a linear GF(2) map F2^32 -> F2^32."""
    columns = [fn(1 << i) for i in range(32)]
    return [sum(((columns[j] >> i) & 1) << j for j in range(32))
            for i in range(32)]


def rank_gf2(rows):
    basis = {}
    for row in rows:
        while row:
            pivot = row.bit_length()-1
            if pivot in basis:
                row ^= basis[pivot]
            else:
                basis[pivot] = row
                break
    return len(basis)


def matrix_eval(rows, word):
    return sum(((r & word).bit_count() & 1) << i for i, r in enumerate(rows))


def rotation_matrix_report():
    ops = {
        'ROTR_2':lambda x:rotr(x,2),
        'ROTR_13':lambda x:rotr(x,13),
        'BIG_SIGMA_0':lambda x:rotr(x,2)^rotr(x,13)^rotr(x,22),
        'BIG_SIGMA_1':lambda x:rotr(x,6)^rotr(x,11)^rotr(x,25),
        'SMALL_SIGMA_0':lambda x:rotr(x,7)^rotr(x,18)^(x>>3),
        'SMALL_SIGMA_1':lambda x:rotr(x,17)^rotr(x,19)^(x>>10),
    }
    rng = random.Random(331)
    metrics = {}
    for name, op in ops.items():
        rows = linear_map_matrix(op)
        for _ in range(50):
            x = rng.getrandbits(32)
            assert matrix_eval(rows,x)==op(x)
            assert op(x ^ (1<<7)) == op(x) ^ op(1<<7)
        metrics[name] = {'rank':rank_gf2(rows),'matrix_rows_hex':[f'{r:08x}' for r in rows]}
    return metrics


class LiftedCircuit:
    """Affine expressions encoded with integer bitsets: bit 0 = constant 1.

    Bits 1..n represent independent input variables. Each nonlinear AND output
    becomes a fresh variable with the exact quadratic gate constraint stored.
    """
    def __init__(self, n: int):
        self.n=n
        self.next_var=n+1
        self.gates=[]
        self.and_cache={}
        self.and_requests=0
        self.and_simplified=0
        self.xor_requests=0
        self.additions=0
        self.total_words=0

    def var(self, j):return 1 << (j+1)
    def const(self, val):return 1 if val else 0
    def word_const(self, value):return tuple((value>>i)&1 for i in range(32))
    def xor(self, a,b):
        self.xor_requests+=1
        return a^b
    def and_(self,a,b):
        self.and_requests+=1
        if a==0 or b==0:
            self.and_simplified+=1;return 0
        if a==1:
            self.and_simplified+=1;return b
        if b==1 or a==b:
            self.and_simplified+=1;return a
        if a==(b^1):
            self.and_simplified+=1;return 0
        if a>b:a,b=b,a
        key=(a,b)
        out=self.and_cache.get(key)
        if out is not None:
            self.and_simplified+=1;return out
        out=1<<self.next_var
        self.next_var+=1
        self.and_cache[key]=out
        self.gates.append((a,b))
        return out

    def word_xor(self,a,b):return tuple(self.xor(x,y) for x,y in zip(a,b))
    def word_and(self,a,b):return tuple(self.and_(x,y) for x,y in zip(a,b))
    def rotr(self,a,n):return tuple(a[(i+n)%32] for i in range(32))
    def shr(self,a,n):return tuple(a[i+n] if i+n<32 else 0 for i in range(32))
    def big0(self,a):return self.word_xor(self.word_xor(self.rotr(a,2),self.rotr(a,13)),self.rotr(a,22))
    def big1(self,a):return self.word_xor(self.word_xor(self.rotr(a,6),self.rotr(a,11)),self.rotr(a,25))
    def small0(self,a):return self.word_xor(self.word_xor(self.rotr(a,7),self.rotr(a,18)),self.shr(a,3))
    def small1(self,a):return self.word_xor(self.word_xor(self.rotr(a,17),self.rotr(a,19)),self.shr(a,10))
    def choice(self,e,f,g):
        # g XOR [ e AND (f XOR g) ]
        return self.word_xor(g,self.word_and(e,self.word_xor(f,g)))
    def majority(self,a,b,c):
        # (a AND b) XOR [ c AND (a XOR b) ]
        return self.word_xor(self.word_and(a,b),self.word_and(c,self.word_xor(a,b)))
    def add(self,a,b):
        """Exact ripple-carry addition mod 2^32; omit carry-out bit 32."""
        out=[]
        carry=0
        for i in range(32):
            p=self.xor(a[i],b[i])
            out.append(self.xor(p,carry))
            if i<31:
                carry=self.xor(self.and_(a[i],b[i]),self.and_(p,carry))
        self.additions+=1
        return tuple(out)
    def sum(self,*words):
        ans=words[0]
        for w in words[1:]:ans=self.add(ans,w)
        return ans

    def compress(self,rounds):
        words=block_words(0)
        w=[tuple(self.var(i) if i<self.n else ((words[0]>>i)&1) for i in range(32))]
        w.extend(self.word_const(word) for word in words[1:])
        a,b,c,d,e,f,g,h=map(self.word_const,IV)
        for i in range(rounds):
            if i>=len(w):
                w.append(self.sum(self.small1(w[i-2]),w[i-7],self.small0(w[i-15]),w[i-16]))
            t1=self.sum(h,self.big1(e),self.choice(e,f,g),self.word_const(K[i]),w[i])
            t2=self.add(self.big0(a),self.majority(a,b,c))
            a,b,c,d,e,f,g,h=self.add(t1,t2),a,b,c,self.add(d,t1),e,f,g
        state=(a,b,c,d,e,f,g,h)
        output=tuple(self.add(word,self.word_const(init)) for word,init in zip(state,IV))
        return output

    def evaluate(self,output,x):
        """Verify the entire quadratic gate network exactly for assignment x."""
        assert 0<=x<(1<<self.n)
        bits=1 | (x<<1)
        for i,(a,b) in enumerate(self.gates):
            gateval=((bits&a).bit_count()&1) & ((bits&b).bit_count()&1)
            if gateval:bits |= 1 << (self.n+1+i)
        return tuple(sum((((bits & expr).bit_count()&1)<<i) for i,expr in enumerate(word))
                     for word in output)


def target_equations(words, target):
    # Each equation: affine_expr XOR target_bit = 0, bit0 is constant term.
    return [expr ^ ((target[word_index]>>bit)&1)
            for word_index,word in enumerate(words) for bit,expr in enumerate(word)]


def projected_input_system(rows, n):
    """Eliminate all nonlinear gate variables, retaining GF(2) input equations.

    This projects ONLY the linear relaxation that treats AND gate outputs as
    free variables. It NEVER uses nonlinear AND constraints.
    """
    high_mask=~((1<<(n+1))-1)
    basis={}; projected=[]
    for row in rows:
        while row & high_mask:
            pivot=row.bit_length()-1
            old=basis.get(pivot)
            if old is None:
                basis[pivot]=row
                break
            row ^= old
        else:
            projected.append(row)
    input_basis={}; inconsistent=False
    for row in projected:
        vals=row>>1
        while vals:
            pivot=vals.bit_length()-1
            old=input_basis.get(pivot)
            if old is None:
                input_basis[pivot]=(vals,row&1)
                break
            vals ^= old[0]
            row_const=(row&1)^old[1]
            row=(vals<<1)|row_const
        else:
            if row&1:inconsistent=True
    return {
        'output_equations':len(rows),
        'independent_high_variable_pivots':len(basis),
        'input_only_equations_after_projection':len(projected),
        'input_constraint_rank':len(input_basis),
        'inconsistent':inconsistent,
        'candidate_count_under_linear_relaxation':0 if inconsistent else 1 << (n-len(input_basis)),
        'input_equations':[
            {'coefficients_hex':hex(v), 'rhs':c} for v,c in input_basis.values()
        ],
    }


def run_one(rounds,n,secret,check_n=3):
    start=time.perf_counter()
    model=LiftedCircuit(n)
    output=model.compress(rounds)
    build=time.perf_counter()-start
    target=compress(secret,rounds)
    rng=random.Random(736+rounds)
    samples={0,secret,(1<<n)-1}
    samples.update(rng.randrange(1<<n) for _ in range(check_n))
    verify_t=time.perf_counter()
    for candidate in samples:
        got=model.evaluate(output,candidate)
        want=compress(candidate,rounds)
        assert got==want,(candidate,rounds,'circuit mismatch')
    verify_seconds=time.perf_counter()-verify_t
    eqns=target_equations(output,target)
    elimination_t=time.perf_counter()
    projected=projected_input_system(eqns,n)
    elimination_seconds=time.perf_counter()-elimination_t
    # Rank 256 output equations as GF2 affine equations over all lifted vars.
    combined_rank=rank_gf2([r>>1 for r in eqns])
    # Check actual preimages of first 8 or 16 digest bits by direct enumeration;
    # this is ONLY practical for small n. These are not from the linear relaxation.
    brute={};hybrid={}
    if n<=12:
        start_b=time.perf_counter()
        matches=0; prefix8=0; prefix16=0
        for x in range(1<<n):
            out=compress(x,rounds)
            matches+=out==target
            prefix8+= (out[0]>>24)==(target[0]>>24)
            prefix16+= (out[0]>>16)==(target[0]>>16)
        brute={'matching_full_digests':matches, 'matching_first_8_bits':prefix8,
               'matching_first_16_bits':prefix16,
               'bruteforce_seconds':time.perf_counter()-start_b}
        # Hybrid exact search: use only proven projected equations as a cheap
        # filter, then evaluate all remaining inputs with genuine SHA-256.
        # This explicitly includes the cost of constructing the constraints.
        start_h=time.perf_counter()
        lin_eq=[(int(e['coefficients_hex'],16),e['rhs'])
                for e in projected['input_equations']]
        checked=found=0
        for x in range(1<<n):
            if all(((coef & x).bit_count() & 1)==rhs for coef,rhs in lin_eq):
                checked += 1
                found += compress(x,rounds)==target
        hybrid={'candidates_hashed':checked, 'preimages_found':found,
                'filter_plus_hash_seconds':time.perf_counter()-start_h}
        hybrid['total_seconds_including_symbolic_build']= (
            build+elimination_seconds+hybrid['filter_plus_hash_seconds'])
        assert found==matches
        assert checked==projected['candidate_count_under_linear_relaxation']
    return {
        'rounds':rounds,'unknown_bits':n,'secret':secret,
        'AND_gates':len(model.gates),'AND_requests':model.and_requests,
        'AND_constant_or_duplicate_simplifications':model.and_simplified,
        'XOR_requests':model.xor_requests,'modular_additions':model.additions,
        'affine_variables_total_including_inputs':model.next_var-1,
        'linear_constraint_rank_all_vars':combined_rank,
        'matrix_build_seconds':build,'matrix_elimination_seconds':elimination_seconds,
        'validation_seconds':verify_seconds,'validated_assignments':len(samples),
        'linear_projection':projected,'bruteforce':brute,'hybrid_search':hybrid
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rounds',type=int,nargs='+',default=[1,2,4,8,16])
    parser.add_argument('--unknown-bits',type=int,default=8)
    parser.add_argument('--secret',type=int,default=173)
    parser.add_argument('--output',default='sha256_matrix_results.json')
    args=parser.parse_args()
    assert all(1<=r<=64 for r in args.rounds)
    assert 1<=args.unknown_bits<=24
    assert 0<=args.secret<(1<<args.unknown_bits)
    # Full 64 rounds must reproduce standard hashlib.sha256 (one padded block).
    for x in [0,args.secret,(1<<args.unknown_bits)-1]:
        digest=''.join(f'{v:08x}' for v in compress(x,64))
        assert digest == hashlib.sha256(x.to_bytes(4,'big')+TAIL).hexdigest()
    result={'experiment':'GF(2) exact linear operations + lifted AND-gate constraints',
            'note':'input projection uses only the relaxation treating all AND outputs as independent; it does not solve the original nonlinear equations',
            'matrix_operators':rotation_matrix_report(),
            'runs':[]}
    for rounds in args.rounds:
        print(f'Building {rounds} rounds with {args.unknown_bits} variable bits...',flush=True)
        row=run_one(rounds,args.unknown_bits,args.secret)
        result['runs'].append(row)
        print(f" r={rounds:2d} AND gates={row['AND_gates']:6d} "
              f"linear rank={row['linear_constraint_rank_all_vars']:3d} "
              f"projected input rank={row['linear_projection']['input_constraint_rank']:2d} "
              f"build={row['matrix_build_seconds']:.3f}s",flush=True)
    Path(args.output).write_text(json.dumps(result,indent=2))
    print('Saved',args.output)

if __name__=='__main__':main()
