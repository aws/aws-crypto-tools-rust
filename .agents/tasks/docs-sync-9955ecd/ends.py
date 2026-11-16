import sys,os
R=os.path.expanduser("~/Desktop/ESDK-Rust-Verus/MPL/esdk-native-mpl")
# usage: file r1 r2 ...   prints first and last line of each range, trimmed
f=sys.argv[1]; L=open(os.path.join(R,f)).read().split('\n')
for r in sys.argv[2:]:
    s,_,e=r.partition('-'); s=int(s); e=int(e) if e else s
    print(f'{r:>10} | {L[s-1].strip()[:70]:70} || {L[e-1].strip()[:50] if e!=s else ""}')
