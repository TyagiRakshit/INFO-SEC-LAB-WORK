"""LAB 6: Educational Schnorr plus ECDSA helpers."""
import secrets, hashlib
from Crypto.Util import number
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def schnorr_keys(bits=512):
    # Educational prime-order subgroup construction: p=2q+1 prime.
    while True:
        q=number.getPrime(bits-1);p=2*q+1
        if number.isPrime(p):break
    h=2
    while pow(h,2,p)==1:h+=1
    g=pow(h,2,p)  # order q, as q is prime and g != 1
    x=secrets.randbelow(q-1)+1;y=pow(g,x,p)
    return (p,q,g,y),x

def challenge(R,data,q):
    encoded=R.to_bytes((R.bit_length()+7)//8 or 1,'big')
    return int.from_bytes(hashlib.sha256(len(encoded).to_bytes(4,'big')+encoded+data).digest(),'big')%q

def schnorr_sign(data,public,private):
    p,q,g,y=public;k=secrets.randbelow(q-1)+1
    R=pow(g,k,p);e=challenge(R,data,q);s=(k+private*e)%q
    return {'e':e,'s':s}
def schnorr_verify(data,signature,public):
    try:
        p,q,g,y=public;e=int(signature['e']);s=int(signature['s'])
        if not (0<=e<q and 0<=s<q):return False
        R=pow(g,s,p)*pow(pow(y,-1,p),e,p)%p
        return e==challenge(R,data,q)
    except (ValueError,KeyError,TypeError):return False

def ecdsa_sign(data,private):return private.sign(data,ec.ECDSA(hashes.SHA256()))
def ecdsa_verify(data,signature,public):
    try:public.verify(signature,data,ec.ECDSA(hashes.SHA256()));return True
    except (InvalidSignature,ValueError):return False
