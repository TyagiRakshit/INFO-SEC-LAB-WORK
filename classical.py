"""LAB 1: Educational classical ciphers. Not secure for real data."""
import math

def letters(s): return ''.join(c for c in s.upper() if 'A' <= c <= 'Z')
def shift(text, key, decrypt=False):
    k = (-key if decrypt else key) % 26
    return ''.join(chr((ord(c)-65+k)%26+65) for c in letters(text))
def multiplicative(text, key, decrypt=False):
    if math.gcd(key,26)!=1: raise ValueError('Key must be coprime to 26')
    k=pow(key,-1,26) if decrypt else key
    return ''.join(chr(((ord(c)-65)*k)%26+65) for c in letters(text))
def affine(text, a, b, decrypt=False):
    if math.gcd(a,26)!=1: raise ValueError('a must be coprime to 26')
    if decrypt:
        inv=pow(a,-1,26)
        return ''.join(chr((inv*(ord(c)-65-b))%26+65) for c in letters(text))
    return ''.join(chr((a*(ord(c)-65)+b)%26+65) for c in letters(text))
def vigenere(text, keyword, decrypt=False):
    key=letters(keyword)
    if not key: raise ValueError('Keyword must contain letters')
    sign=-1 if decrypt else 1
    return ''.join(chr(((ord(c)-65+sign*(ord(key[i%len(key)])-65))%26)+65) for i,c in enumerate(letters(text)))
def autokey(text, initial, decrypt=False):
    if not 0<=initial<26: raise ValueError('Initial shift must be 0..25')
    data=[ord(c)-65 for c in letters(text)]; out=[]
    for i,value in enumerate(data):
        k=initial if i==0 else (out[i-1] if decrypt else data[i-1])
        out.append((value-k if decrypt else value+k)%26)
    return ''.join(chr(x+65) for x in out)
def playfair_matrix(keyword):
    alphabet=letters(keyword).replace('J','I')+'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    unique=''.join(dict.fromkeys(alphabet))
    return [unique[i:i+5] for i in range(0,25,5)]
def playfair(text, keyword, decrypt=False):
    grid=playfair_matrix(keyword); pos={c:(i,j) for i,row in enumerate(grid) for j,c in enumerate(row)}
    chars=letters(text).replace('J','I'); pairs=[]
    if decrypt:
        if len(chars)%2: raise ValueError('Ciphertext length must be even')
        pairs=[chars[i:i+2] for i in range(0,len(chars),2)]
    else:
        i=0
        while i<len(chars):
            a=chars[i]; b=chars[i+1] if i+1<len(chars) else 'X'
            if a==b: b='X' if a!='X' else 'Q'; i+=1
            else: i+=2
            pairs.append(a+b)
    result=[]; delta=-1 if decrypt else 1
    for a,b in pairs:
        r1,c1=pos[a];r2,c2=pos[b]
        if r1==r2: result.extend([grid[r1][(c1+delta)%5],grid[r2][(c2+delta)%5]])
        elif c1==c2: result.extend([grid[(r1+delta)%5][c1],grid[(r2+delta)%5][c2]])
        else: result.extend([grid[r1][c2],grid[r2][c1]])
    return ''.join(result) # Remove filler X manually after decryption.
def hill2(text, matrix, decrypt=False):
    a,b=matrix[0];c,d=matrix[1];det=(a*d-b*c)%26
    if math.gcd(det,26)!=1: raise ValueError('Matrix determinant must be invertible mod 26')
    if decrypt:
        inv=pow(det,-1,26);a,b,c,d=(d*inv)%26,(-b*inv)%26,(-c*inv)%26,(a*inv)%26
    s=letters(text)
    if len(s)%2: s+='X'
    result=''
    for i in range(0,len(s),2):
        x,y=ord(s[i])-65,ord(s[i+1])-65
        result+=chr((a*x+b*y)%26+65)+chr((c*x+d*y)%26+65)
    return result
def brute_force_caesar(ciphertext): return {k:shift(ciphertext,k,True) for k in range(26)}
def brute_force_affine(ciphertext):
    return {(a,b):affine(ciphertext,a,b,True) for a in range(26) if math.gcd(a,26)==1 for b in range(26)}
