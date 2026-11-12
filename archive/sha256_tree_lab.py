#!/usr/bin/env python3
"""Reproducible SHA-256 reduced-round constraint-tree laboratory.

Works on a genuine, padded 40-byte single-block SHA-256 message with an
unknown low-bit region in message word W0. Tests whether a *sound* known-bit
abstraction can prune partial assignments to W0 against a target digest.

The BDD measurement is built from a truth table (i.e. enumerative), and is
NOT a shortcut. Its node count measures compressibility, not inversion speed.
"""
from __future__ import annotations
import argparse, hashlib, json, time
from collections import defaultdict
from dataclasses import dataclass

MASK = (1 << 32) - 1
IV = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)
K = (0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
     0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
     0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
     0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
     0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
     0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
     0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
     0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2)

def rotr(x, n): return ((x >> n) | (x << (32-n))) & MASK

def sigma0(x): return rotr(x,7) ^ rotr(x,18) ^ (x >> 3)
def sigma1(x): return rotr(x,17) ^ rotr(x,19) ^ (x >> 10)
def big0(x): return rotr(x,2) ^ rotr(x,13) ^ rotr(x,22)
def big1(x): return rotr(x,6) ^ rotr(x,11) ^ rotr(x,25)

# 40-byte message, with 32-bit W0 adjustable. sha256 padding is unmodified.
TAIL = bytes(range(1,37))
def block_words(w0):
    msg = w0.to_bytes(4,'big') + TAIL
    padded = msg + b'\x80' + b'\x00' * (55-len(msg)) + (len(msg)*8).to_bytes(8,'big')
    return [int.from_bytes(padded[i:i+4], 'big') for i in range(0,64,4)]

def compress(w0, rounds):
    w = block_words(w0)
    for i in range(16, rounds):
        w.append((sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16]) & MASK)
    a,b,c,d,e,f,g,h = IV
    for i in range(rounds):
        terms=(h,big1(e),(e & f) ^ (~e & g),K[i],w[i])
        t1=sum(terms)&MASK
        t2=(big0(a)+((a&b)^(a&c)^(b&c)))&MASK
        a,b,c,d,e,f,g,h = (t1+t2)&MASK, a,b,c,(d+t1)&MASK,e,f,g
    out=tuple((x+y)&MASK for x,y in zip(IV,(a,b,c,d,e,f,g,h)))
    return out

@dataclass(frozen=True)
class T:
    v: int             # known 1 bits (all other bits zero)
    k: int             # which bits are known
    def __post_init__(self):
        assert (self.v & ~self.k) == 0

def const(x): return T(x&MASK, MASK)
def txor(a,b): return T((a.v^b.v)&(a.k&b.k), a.k&b.k)
def tnot(a): return T((~a.v)&a.k&MASK, a.k)
def tand(a,b):
    zeros=((a.k&~a.v)|(b.k&~b.v))&MASK
    ones=a.v&b.v
    return T(ones,zeros|ones)
def tor(a,b): return tnot(tand(tnot(a),tnot(b)))
def trot(a,n): return T(rotr(a.v,n),rotr(a.k,n))
def tshr(a,n): return T(a.v>>n, (a.k>>n) | (MASK ^ (MASK>>n)))

def tadd(a,b,diag=None):
    if a.k==MASK and b.k==MASK: return const(a.v+b.v)
    ov=0; ok=0; carries=1 # carry=0 possible; bit 0 means carry=0, bit 1 means carry=1
    for i in range(32):
        ab=(2 if ((a.v>>i)&1) else 1) if ((a.k>>i)&1) else 3
        bb=(2 if ((b.v>>i)&1) else 1) if ((b.k>>i)&1) else 3
        if diag is not None and carries==3: diag["ambiguous_carry_inputs"] += 1
        sumset=0; nextc=0
        for ai in (0,1):
            if not (ab&(1<<ai)): continue
            for bi in (0,1):
                if not (bb&(1<<bi)): continue
                for ci in (0,1):
                    if not (carries&(1<<ci)): continue
                    s=ai+bi+ci
                    sumset|=1<<(s&1)
                    nextc|=1<<(s>>1)
        if sumset!=3:
            ok |= 1<<i
            if sumset==2: ov |= 1<<i
        carries=nextc
    return T(ov,ok)

def tsum(*xs,diag=None):
    acc=xs[0]
    for x in xs[1:]: acc=tadd(acc,x,diag)
    return acc

def ts0(x): return txor(txor(trot(x,7),trot(x,18)),tshr(x,3))
def ts1(x): return txor(txor(trot(x,17),trot(x,19)),tshr(x,10))
def tb0(x): return txor(txor(trot(x,2),trot(x,13)),trot(x,22))
def tb1(x): return txor(txor(trot(x,6),trot(x,11)),trot(x,25))
def tchoice(x,y,z): return txor(tand(x,y),tand(tnot(x),z))
def tmajority(x,y,z): return txor(txor(tand(x,y),tand(x,z)),tand(y,z))

def compress_t(w0, rounds, gather_carries=False):
    ww=[w0]+[const(x) for x in block_words(0)[1:]]
    for i in range(16,rounds):
        ww.append(tsum(ts1(ww[i-2]),ww[i-7],ts0(ww[i-15]),ww[i-16]))
    a,b,c,d,e,f,g,h=map(const,IV)
    stats=[]; carry_stats=[]
    for i in range(rounds):
        diag={"ambiguous_carry_inputs":0} if gather_carries else None
        t1=tsum(h,tb1(e),tchoice(e,f,g),const(K[i]),ww[i],diag=diag)
        t2=tadd(tb0(a),tmajority(a,b,c),diag)
        a,b,c,d,e,f,g,h=tadd(t1,t2,diag),a,b,c,tadd(d,t1,diag),e,f,g
        stats.append(sum(x.k.bit_count() for x in (a,b,c,d,e,f,g,h)))
        if diag is not None: carry_stats.append(diag["ambiguous_carry_inputs"])
    result=(tuple(tadd(x,const(v)) for x,v in zip((a,b,c,d,e,f,g,h),IV)),stats)
    return (*result,carry_stats) if gather_carries else result

def abstraction_matches(abs_words,target):
    return all(((a.v^b)&a.k)==0 for a,b in zip(abs_words,target))

def bdd_counts(truth, n):
    """Build a reduced ordered BDD from a truth table (exhaustive baseline).
    Variable order: unknown bit n-1, then n-2, ... 0.
    """
    unique={}; layers=defaultdict(int); nodes=0
    def build(start,size,depth):
        nonlocal nodes
        if size==1: return int(truth[start])
        half=size//2
        lo=build(start,half,depth+1)
        hi=build(start+half,half,depth+1)
        if lo==hi: return lo
        key=(depth,lo,hi)
        if key not in unique:
            unique[key]=len(unique)+2
            layers[depth]+=1
        return unique[key]
    root=build(0,1<<n,0)
    return {'nodes':len(unique), 'max_width':max(layers.values(),default=0),
            'layer_widths':[layers[i] for i in range(n)], 'root':root}

def tree_probe(rounds,n,secret,record_leaf=False):
    unknown_mask=(1<<n)-1
    target=compress(secret,rounds)
    results={'rounds':rounds,'unknown_bits':n,'target_source':secret,
             'internal_nodes':0,'pruned':0,'prune_by_depth':defaultdict(int),
             'leaves_evaluated':0,'solutions':0,'abstract_evaluations':0,
             'min_known_state_bits_at_root':None}
    # Prefix traverses W0 low n bits from MSB to LSB.
    def walk(depth,bits):
        results['abstract_evaluations']+=1
        known_input_mask = MASK ^ ((1 << (n-depth))-1)
        ab,stage=compress_t(T(bits,known_input_mask),rounds)
        results['internal_nodes']+=int(depth<n)
        if depth==0: results['known_state_bits_at_root_per_round']=stage
        if not abstraction_matches(ab,target):
            results['pruned']+=1
            results['prune_by_depth'][depth]+=1
            return
        if depth==n:
            results['leaves_evaluated']+=1
            if compress(bits,rounds)==target: results['solutions']+=1
            return
        bit=1<<(n-depth-1)
        walk(depth+1,bits)
        walk(depth+1,bits|bit)
    start=time.perf_counter()
    walk(0,0)
    results['tree_seconds']=round(time.perf_counter()-start,5)
    results['prune_by_depth']=dict(sorted(results['prune_by_depth'].items()))
    assert results['solutions']>=1
    return results

def run(n,round_list,secret):
    if n>16: raise ValueError('Set --unknown-bits <=16 to keep the exhaustive checks modest.')
    if not 0<=secret<(1<<n): raise ValueError('secret must fit unknown bits.')
    # Validate true SHA-256 compression and the abstract semantics on samples.
    for x in (0,secret,(1<<n)-1):
        digest=''.join(f'{v:08x}' for v in compress(x,64))
        assert digest==hashlib.sha256(x.to_bytes(4,'big')+TAIL).hexdigest(), 'SHA-256 mismatch'
    data={'settings':{'unknown_bits':n,'secret':secret,'rounds':round_list,
                      'word_unknown_region':f'W0 low {n} bits'},'results':[]}
    for rounds in round_list:
        t=time.perf_counter()
        targets=[compress(x,rounds) for x in range(1<<n)]
        enumerate_seconds=time.perf_counter()-t
        chosen=targets[secret]
        # For target predicate based on first k hash bits (MSB first),
        # truth table tests exact digest prefix equality.
        full_matches=sum(x==chosen for x in targets)
        sample=targets[secret]
        tests=[]
        for k in (1,4,8,12):
            kk=min(k,32)
            mask=((1<<kk)-1)<<(32-kk)
            vals=[(int((v[0]&mask)==(sample[0]&mask))) for v in targets]
            d=bdd_counts(vals,n)
            tests.append({'target_prefix_bits':kk,'candidate_count':sum(vals),
                          'bdd_nodes':d['nodes'],'bdd_max_width':d['max_width']})
        # A single output bit BDD measures complexity of the actual Boolean function.
        fn_bit=31 # digest word 0 high bit
        fn=bdd_counts([(v[0]>>fn_bit)&1 for v in targets],n)
        probe=tree_probe(rounds,n,secret)
        _,_,carry_ambiguity=compress_t(T(0, MASK^((1<<n)-1)),rounds,gather_carries=True)
        # Verify sound abstraction against all candidates that share a 3-bit prefix.
        prefix_depth=min(3,n)
        for prefix in range(1<<prefix_depth):
            shared=prefix<<(n-prefix_depth)
            known_mask=MASK^((1<<(n-prefix_depth))-1)
            abstract,_=compress_t(T(shared,known_mask),rounds)
            for x in range(shared,shared+(1<<(n-prefix_depth))):
                v=targets[x]
                assert all(((a.v^b)&a.k)==0 for a,b in zip(abstract,v)), 'unsound pruning abstraction'
        data['results'].append({'rounds':rounds,'bruteforce_seconds':round(enumerate_seconds,5),
            'full_digest_matches':full_matches,'bdd_one_bit':{'nodes':fn['nodes'],
            'max_width':fn['max_width'], 'layer_widths':fn['layer_widths']},
            'target_bdds':tests,'tree':probe,
            'root_ambiguous_carry_inputs_by_round':carry_ambiguity})
    return data

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--unknown-bits',type=int,default=8)
    p.add_argument('--rounds',type=int,nargs='+',default=[1,2,4,8,12,16])
    p.add_argument('--secret',type=int,default=173)
    p.add_argument('--output',default='sha256_tree_results.json')
    args=p.parse_args()
    if any(r<1 or r>64 for r in args.rounds): p.error('Rounds must be 1..64')
    result=run(args.unknown_bits,args.rounds,args.secret)
    with open(args.output,'w') as f: json.dump(result,f,indent=2)
    print('SHA-256 compression validated against hashlib (64 rounds).')
    print('Rnds | 1-bit BDD (nodes/width) | tree pruned | tree leaves | bf sec | tree sec | root known state bits')
    for res in result['results']:
        b=res['bdd_one_bit']; t=res['tree']
        print(f"{res['rounds']:>4} | {b['nodes']:>5}/{b['max_width']:<5}             | {t['pruned']:>5}       | {t['leaves_evaluated']:>5}       | {res['bruteforce_seconds']:.3f}  | {t['tree_seconds']:.3f}    | {t['known_state_bits_at_root_per_round'][-1]}")
    print('Wrote:',args.output)
