import re,os,random,subprocess,glob
R=os.getcwd()
files=[f for f in subprocess.run(['git','diff','-M','--name-only','HEAD'],capture_output=True,text=True).stdout.split() if f.endswith(('.md',))]
files+= [f for f in subprocess.run(['git','diff','-M','--name-only','HEAD','--','.kiro'],capture_output=True,text=True).stdout.split()]
files=sorted(set(files))
TOK=re.compile(r'((?:https://github\.com/[^\s)`"\']*?/(?:blob|tree)/MPL-Verus/)?(?:\.\./|\./|docs/)*(?:chorus/)?mpl-(?:threat-model|spec-security-analysis|verification-targets|completeness-audit|bug-reports)[A-Za-z0-9_./-]*)(#[A-Za-z0-9_-]+)?')
cands=[]
for f in files:
    for i,l in enumerate(open(f,encoding='utf-8'),1):
        for m in TOK.finditer(l):
            cands.append((f,i,m.group(1).rstrip('.,;:'),m.group(2)))
random.seed(20240607)
print('total reference occurrences:',len(cands))
sample=random.sample(cands,20)
def resolve(f,t):
    t2=re.sub(r':\d+(-\d+)?$','',t)
    if t2.startswith('https://github.com'):
        p=t2.split('/MPL-Verus/',1)[1]; return os.path.exists(p),p
    base=os.path.dirname(f)
    for c in [os.path.normpath(os.path.join(base,t2)), t2, os.path.join('docs',t2), os.path.join('docs/mpl-verification-targets',t2),os.path.join('docs/mpl-bug-reports',t2)]:
        if os.path.exists(c): return True,c
    return False,t2
for n,(f,i,t,a) in enumerate(sample,1):
    ok,p=resolve(f,t)
    print(f'{n:2}. {f}:{i}  `{t}{a or ""}` -> {p}  {"RESOLVES" if ok else "UNRESOLVED"}')
print('=== FULL SWEEP')
bad=[(f,i,t,a) for f,i,t,a in cands if not resolve(f,t)[0]]
print('unresolved:',len(bad))
for b in bad[:30]: print(b)
# anchors
def slug(h):
    h=re.sub(r'`','',h.strip().lower()); h=re.sub(r'[^\w\- ]','',h); return h.replace(' ','-')
