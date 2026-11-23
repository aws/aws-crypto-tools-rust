#!/usr/bin/env python3
import sys,os
R=os.path.expanduser("~/Desktop/ESDK-Rust-Verus/MPL/esdk-native-mpl")
for a in sys.argv[1:]:
    f,r=(a.rsplit('@',1) if '@' in a else a.rsplit(':',1))
    s,_,e=r.partition('-'); s=int(s); e=int(e) if e else s
    L=open(os.path.join(R,f)).read().split('\n')
    print('---',a)
    for i in range(s,e+1): print(f'{i}: {L[i-1][:140]}')
