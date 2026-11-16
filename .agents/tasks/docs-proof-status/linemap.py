import subprocess, difflib, sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
def mapping(path):
    old = subprocess.run(["git","-C",ROOT,"show","HEAD:"+path],capture_output=True,text=True).stdout.split("\n")
    new = open(os.path.join(ROOT,path)).read().split("\n")
    # compare with proof columns/fields stripped so modified rows match
    def norm(l):
        return l
    sm = difflib.SequenceMatcher(None, old, new, autojunk=False)
    m = {}
    for tag,i1,i2,j1,j2 in sm.get_opcodes():
        if tag=="equal":
            for k in range(i2-i1): m[i1+k+1]=j1+k+1
        elif tag=="replace" and (i2-i1)==(j2-j1):
            for k in range(i2-i1): m[i1+k+1]=j1+k+1
    return m
if __name__=="__main__":
    path=sys.argv[1]; m=mapping(path)
    for n in sys.argv[2:]:
        print(path, n, "->", m.get(int(n)))
