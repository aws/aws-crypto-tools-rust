#!/usr/bin/env python3
"""Extract RFC2119 requirement units from the 13 MPL framework specs.
Output: sweep1-requirements.tsv (id, file, line, heading, kw, text)."""
import re, json, sys, os
ROOT = "spec/framework/"
FILES = [("ALG","algorithm-suites.md"),("STR","structures.md"),("CPO","commitment-policy.md"),
 ("KRI","keyring-interface.md"),("RAK","raw-aes-keyring.md"),("HKR","aws-kms/aws-kms-hierarchical-keyring.md"),
 ("MRK","aws-kms/aws-kms-mrk-match-for-decrypt.md"),("CMI","cmm-interface.md"),("DCM","default-cmm.md"),
 ("CMC","cryptographic-materials-cache.md"),("LCM","local-cryptographic-materials-cache.md"),
 ("STC","storm-tracking-cryptographic-materials-cache.md"),("BKS","branch-key-store.md")]
KW = re.compile(r"\b(MUST NOT|MUST|SHALL NOT|SHALL|SHOULD NOT|SHOULD|REQUIRED|MAY|RECOMMENDED)\b")
STRONG = re.compile(r"\b(MUST NOT|MUST|SHALL NOT|SHALL|SHOULD NOT|SHOULD|REQUIRED)\b")
def clean(s):
    s = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", s)   # links
    s = re.sub(r"\s+", " ", s).strip()
    return s
rows=[]
for abbr,f in FILES:
    lines=open(ROOT+f,encoding="utf-8").read().split("\n")
    heads=[]; i=0; n=0
    in_code=False
    # build blocks
    blocks=[]; cur=[]; start=0
    for idx,l in enumerate(lines):
        if l.strip().startswith("```"):
            in_code = not in_code
        if (not in_code) and (l.strip()=="" ):
            if cur: blocks.append((start,cur)); cur=[]
            continue
        if not cur: start=idx+1
        cur.append(l)
    if cur: blocks.append((start,cur))
    for start,bl in blocks:
        first=bl[0]
        m=re.match(r"^(#+)\s+(.*)",first)
        if m:
            lvl=len(m.group(1)); heads=heads[:lvl-1]+[m.group(2).strip()]
            continue
        if first.startswith("[//]"): continue
        text=" ".join(bl)
        if not STRONG.search(text):
            continue
        # tables: skip table rows that only carry MUST in prose? keep, flagged
        # units: lead-in blocks (first sentence ends with ':') -> one unit
        # otherwise split sentences; bullets -> each bullet a unit
        units=[]
        is_list=any(re.match(r"^\s*([-*]|\d+\.)\s",x) for x in bl)
        if is_list:
            # group: non-bullet lines before bullets are lead-in
            lead=[];items=[]
            for ln_i,x in enumerate(bl):
                if re.match(r"^\s*([-*]|\d+\.)\s",x): items.append([start+ln_i,x.strip()])
                elif items: items[-1][1]+=" "+x.strip()
                else: lead.append(x.strip())
            leadt=" ".join(lead)
            if leadt and STRONG.search(leadt):
                units.append((start, clean(text)))   # whole block under a lead-in requirement
            else:
                for ln,t in items:
                    if STRONG.search(t): units.append((ln,clean((leadt+" ") if leadt else "")+clean(t)))
                if leadt and not items: units.append((start,clean(leadt)))
        elif first.lstrip().startswith("|"):
            for ln_i,x in enumerate(bl):
                if STRONG.search(x): units.append((start+ln_i,clean(x)))
        else:
            sents=re.split(r"(?<=[.!?])\s+(?=[A-Z`\[*(])", clean(text))
            for s in sents:
                if STRONG.search(s): units.append((start,s))
        for ln,t in units:
            n+=1
            kw=sorted(set(STRONG.findall(t)))
            rows.append(dict(id=f"{abbr}-{n:03d}",file=f,line=ln,heading=" > ".join(heads[1:]) if len(heads)>1 else (heads[0] if heads else ""),kw="/".join(kw),text=t))
json.dump(rows,open(".agents/tasks/audit-light/sweep1-requirements.json","w"),indent=1)
from collections import Counter
c=Counter(r["file"] for r in rows)
for k,v in c.items(): print(v,k)
print(len(rows))
