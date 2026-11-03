# RFC 9162 section 2.1; Python 3.10+, stdlib [a-Shell ok].
import hashlib
H=lambda value:hashlib.sha256(value).digest()
def root(leaves):
    if not leaves:return H(b'')
    if len(leaves)==1:return H(b'\x00'+leaves[0])
    k=1<<((len(leaves)-1).bit_length()-1)
    return H(b'\x01'+root(leaves[:k])+root(leaves[k:]))
def inclusion(leaf,index,size,path,expected):
    if type(index) is not int or type(size) is not int or not 0<=index<size:return False
    if len(leaf)!=32 or len(expected)!=32 or any(len(x)!=32 for x in path):return False
    fn=index;sn=size-1;r=H(b'\x00'+leaf)
    for p in path:
        if sn==0:return False
        if fn&1 or fn==sn:
            r=H(b'\x01'+p+r)
            if not fn&1:
                while fn!=0 and not fn&1:fn>>=1;sn>>=1
        else:r=H(b'\x01'+r+p)
        fn>>=1;sn>>=1
    return sn==0 and r==expected
