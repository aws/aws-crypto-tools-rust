import re
blocks={}
for f in ["docs/verification-targets/01-threat-driven.md","docs/verification-targets/02-capability-driven.md"]:
    L=open(f).read().split("\n")
    cur=None;start=None
    for i,l in enumerate(L):
        m=re.search(r"id: VR-2026-([TC]\d\d)",l)
        if m:
            cur=m.group(1); blocks[cur]={"file":f,"start":i+1,"lines":[]}
        elif l.startswith("## ") and cur: cur=None
        if cur: blocks[cur]["lines"].append((i+1,l))
for t,b in sorted(blocks.items()):
    txt="\n".join(l for _,l in b["lines"])
    tr=[]; inth=False
    for n,l in b["lines"]:
        if "threat_references" in l: inth=True; 
        elif re.match(r"\s{2}\w",l) and not l.strip().startswith("- "): inth=False
        if inth: tr+=re.findall(r"TM-MPL-\d{3}",l)
    allTM=sorted(set(re.findall(r"TM-MPL-\d{3}",txt)))
    cap=[l.strip() for _,l in b["lines"] if "capability_reference" in l]
    bugs=sorted(set(re.findall(r"BUG-0\d(?:\([ab]\))?[ab]?",txt)))
    deps=sorted(set(re.findall(r"VR-2026-([TC]\d\d)",txt))-{t})
    print(t,b["file"][-22:],b["start"],"thr_refs=",sorted(set(tr)),"allTM=",allTM,"cap=",cap[:1],"bugs=",bugs,"VRrefs=",deps)
