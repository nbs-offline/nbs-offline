# this is stupid, lazy and chatgpt generated

import sys
import re
import os

def parse_hexdump(text):
    out=[]
    hexdigits=set("0123456789abcdefABCDEF")
    for line in text.splitlines():
        line=line.strip()
        if not line:
            continue
        tokens=line.split()
        if not tokens:
            continue
        first=tokens[0]
        if all(c in hexdigits for c in first) and len(first)>2:
            tokens=tokens[1:]
        for tok in tokens:
            if len(tok)==2 and all(c in hexdigits for c in tok):
                out.append(int(tok,16))
            else:
                break
    print(''.join(f'{b:02x}' for b in out))
    return bytes(out)

def main():
    data=sys.stdin.read()
    if not data:
        print("no input")
        return
    m=re.search(r"Type:\s*(\d+)",data)
    if not m:
        print("could not find Type: in input")
        return
    fname=m.group(1)+".bin"
    os.makedirs("dumps",exist_ok=True)
    path=os.path.join("dumps",fname)
    b=parse_hexdump(data)
    with open(path,"wb") as f:
        f.write(b)
    print(f"Wrote {len(b)} bytes to {path}")

if __name__=="__main__":
    main()
