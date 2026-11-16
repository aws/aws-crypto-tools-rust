import sys,re
# usage: ctx.py doc docline codefile:lines [codefile:lines...]
doc,dl=sys.argv[1],int(sys.argv[2])
t=open(doc).read().split("\n")[dl-1]
print("DOC:",t[:700])
for a in sys.argv[3:]:
    f,r=a.split(":")
    s,_,e=r.partition("-"); s=int(s); e=int(e or s)
    L=open(f,errors="replace").read().split("\n")
    for i in range(s,e+1):
        print(f"  {f}:{i}: {L[i-1].strip()[:110]}" if i<=len(L) else f"  {f}:{i}: <OOR {len(L)}>")
