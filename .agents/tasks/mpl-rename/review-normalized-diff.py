import re,subprocess,sys
R='/Users/mahnush/Desktop/ESDK-Rust-Verus/MPL/esdk-native-mpl'
def g(*a): return subprocess.run(['git','-C',R]+list(a),capture_output=True,text=True).stdout
N=re.compile(r'(?:mpl-)?(threat-model|spec-security-analysis|verification-targets|completeness-audit|bug-reports)')
ns=g('diff','-M','--name-status','HEAD').splitlines()
bad=0;tot=0
for l in ns:
    p=l.split('\t'); st=p[0]
    old,new=(p[1],p[2]) if st.startswith('R') else (p[1],p[1])
    if new.endswith('.docx'): continue
    a=g('show','HEAD:'+old); b=open(R+'/'+new,encoding='utf-8').read()
    # pre-existing mpl- before these names at HEAD?
    pre=re.findall(r'mpl-(?:threat-model|spec-security-analysis|verification-targets|completeness-audit|bug-reports)',a)
    na,nb=N.sub(r'\1',a),N.sub(r'\1',b)
    tot+=1
    if na!=nb: bad+=1; print('RESIDUAL DIFF',old,new)
    if pre: print('HEAD already has mpl- form:',old,len(pre))
print('files',tot,'residual-diff files',bad)
