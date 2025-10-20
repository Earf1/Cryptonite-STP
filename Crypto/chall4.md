# Challenge 4 

## Solution

**Flag:** `MCTF{hardy_muskat_williams2coppersmith}`

Looking at this challenge, i knew it was some rsa method being deployed but it was done in a very weird way.

The script gave me several interesting details

```py
from sage.all import randint, next_prime
from Crypto.Util.number import bytes_to_long

class RSA:
    def __init__(self, hb, lb) -> None:
        self.hb = hb
        self.lb = lb
        self.u1 = randint(0, 2**30)
        self.u2 = randint(0, 2**30)
        self.keygen()
    
    def keygen(self) -> None:
        self.base = randint(2**self.hb-1, 2**self.hb)
        self.e = 0x10001
        self.p = next_prime(self.u1*self.base + randint(2, 2**self.lb))
        self.q = next_prime(self.u2*self.base + randint(2, 2**self.lb))
        self.n = self.p * self.q

    def sum(self):
        return self.u1**2 + self.u2**2

    def encrypt(self, m: bytes) -> int:
        m_ = bytes_to_long(m)
        c = pow(m_, self.e, self.n)
        return c
```

We're given:
- `c0`: Sum of squares of two mystery values
- `c1`: The encrypted flag (our target)
- `c2` and `c3`: Two encrypted known plaintexts

### Modulus Recovery using knoiwn plaintext

The fact that we have multiple ciphertexts with known plaintexts under the same unknown modulus, made me go towards using GCD

Since RSA encryption follows $$c \equiv m^e \$$, we know:
- $$m_2^e - c_2 \equiv 0 \pmod{N}$$
- $$m_3^e - c_3 \equiv 0 \pmod{N}$$

Both expressions are multiples of N, so if i get their GCD ill be able to get to N

```python
from sage.all import *
from Crypto.Util.number import bytes_to_long

# Given values
c0 = 815188129004593690
c1 = [REDACTED]
c2 = [REDACTED]
c3 = [REDACTED]
e = 0x10001

# Known messages
m2 = bytes_to_long(b'Lorem Ipsum is simply dummy text of')
m3 = bytes_to_long(b'blah blah blah')

poly1 = pow(m2, e) - c2
poly2 = pow(m3, e) - c3
N = gcd(poly1, poly2)
print(f"Recovered N: {N}")
print(f"Bit length: {N.nbits()}")
```

This gave me a 4155 bit modulus 

### Standard Factorization Attempts

Naturally, I tried throwing this into FactorDB but didnt find any luuck. The modulus wasnt there in their database

Next, I thought of using General Number Field Sieve. But the computational time was coming out in centuries ://

I also checked if N was prime using `is_prime()`. Which confirmed that the number is definitely factorable just not through typical bruteforcing.

### Exploiting the Sum of Squares

The value `c0 = u1² + u2²` caught my attention. This is a number theory problem: finding integer solutions to a sum of two squares (i googled this formula and got the number theory problem)

I implemented an exhaustive search algorithm:

```python
from math import isqrt

def find_sum_of_squares(target):
    solutions = []
    limit = isqrt(target) + 1
    
    for u1 in range(limit):
        if u1 % 1000000 == 0:
            print(f"Progress: {u1}/{limit}")
        
        remainder = target - u1*u1
        if remainder < 0:
            break
        
        u2 = isqrt(remainder)
        if u2*u2 == remainder:
            solutions.append((u1, u2))
            print(f"Found: u1={u1}, u2={u2}")
    
    return solutions

base_pairs = find_sum_of_squares(c0)
```

For a valid sum of 2 squares, im supposed to find 8 distinct pairs, However, due to symmetry (swapping u1/u2) and signs, there were really only 5 unique absolute values to consider

### Direct Prime Reconstruction

I initially tried to directly compute candidate primes:

```python
base_candidates = [2**2048 - 1, 2**2048]

for base in base_candidates:
    for u1, u2 in all_pairs:
        # Try all possible offsets from 2 to 2^256
        for offset in range(2, min(1000000, 2**256)):
            p_candidate = next_prime(u1 * base + offset)
            if N % p_candidate == 0:
                print(f"Found factor!")
```

This was hopelessly slow as i had to check for 2^256 combinations.

### Partial Key Knowledge Attack

Looking at what we actually know about `p`, i found that:
```python
# Calculate the information content
u1_example = 492011439
base_bits = 2048
offset_bits = 256

# p = next_prime(u1 * base + offset)
# The term (u1 * base) contributes ~2077 bits
# The offset contributes only ~256 bits

known_bits = base_bits + u1_example.bit_length()
unknown_bits = offset_bits

print(f"Total bits in p: ~{known_bits}")
print(f"Unknown bits: {unknown_bits}")
print(f"Known percentage: {(known_bits/(known_bits+unknown_bits))*100:.2f}%")
```

We know approximately 89% of the bits of p

This is where Coppersmith's method becomes applicable, 
I had to read up a lot of writeups on how to apply this method in this specific scenario but i was able to get this script. 

The theory: Given a polynomial $$f(x) = p' + x$$ where:
- $$p'$$ is our approximation (u1 × base)
- $$x$$ is the unknown small offset
- We want $$f(x_0) \equiv 0 \pmod{p}$$ for some small $$x_0$$

Coppersmith proved that lattice reduction (LLL) can find roots up to a certain bound much faster than brute force.

```python
from sage.all import *

N = [YOUR_RECOVERED_N]
u1_candidates = [60616161, 96674589, 492011439, 615951939, 660144937]
base_options = [2**2048 - 1, 2**2048]
X_maximum = 2**256

print("Initiating Coppersmith small roots attack...")

for base in base_options:
    for u1 in u1_candidates:
        approx_p = u1 * base
        
        # Set up the polynomial ring
        ZmodN = Zmod(N)
        PR = PolynomialRing(ZmodN, 'x')
        x = PR.gen()
        
        # Our polynomial: f(x) = approx_p + x should be 0 mod p
        f = approx_p + x
        
        # applying coppersmith
        # beta = 0.4 means we expect our factor to be roughly N^0.4
        small_roots = f.small_roots(X=X_maximum, beta=0.4)
        
        if small_roots:
            for root in small_roots:
                potential_p = Integer(approx_p + root)
                
                # Verifying if its a factor
                if N % potential_p == 0:
                    potential_q = N // potential_p
                    print(f"\n[SUCCESS] Factored N!")
                    print(f"u1 used: {u1}")
                    print(f"base used: {base.nbits()} bits")
                    print(f"p = {potential_p}")
                    print(f"q = {potential_q}")
                    print(f"Verification: p*q == N? {potential_p * potential_q == N}")
                    
                    # Exit
                    import sys
                    sys.exit(0)
```

**Output:**
```
[SUCCESS] Factored N!
u1 used: 492011439
base used: 2048 bits
p = 15900336661317465318564232208300058060118974033590457019229973489363475782853135829256950377256219834741960372018328811182551816335678655644429777687507703877261008561318294633235390823703775543774109998188286718941095289798357972959015077680491413700440182742648763524394072929618827716086700442160867328316461837205776468887145957810416351703579690269178218550372302736409801974421180866639460792497218914751202481098366169305124702334471240963494119699607775093336383843968430950257156340121736865514491012602531675516010309647192428019953460929328787281821611122670785136667494506131169958317348307605392021384747242028329
q = [CALCULATED_Q_VALUE]
Verification: p*q == N? True
```

The attack worked on the third u1 candidate.

### Standard RSA Decryption

With p and q in hand, the rest was simple RSA decryption

```python
from Crypto.Util.number import long_to_bytes

# Compute Euler's totient
phi_N = (p - 1) * (q - 1)

# Calculate private exponent
d = pow(e, -1, phi_N)

# Decrypt the flag
flag_numeric = pow(c1, d, N)
flag = long_to_bytes(flag_numeric)

print(f"FLAG: {flag.decode()}")
```

---
## Vulnerability Analysis

The core weakness in this RSA implementation is the **structured prime generation**. By using `p = next_prime(u1*base + small_offset)`:

1. The high-order ~2048 bits are deterministic once u1 and base are known
2. Only 256 bits of entropy remain unknown
3. This creates a "partial information" scenario perfect for lattice attacks

In production RSA, primes should be generated with **full entropy across all bits** to prevent such attacks.

---

## Key Takeaways

- **Known plaintext attacks** can reveal the modulus through GCD relations
- **Sum of squares** decomposition can be efficiently solved for small values
- **Coppersmith's method** is highly useful when >35-40% of prime bits are known

