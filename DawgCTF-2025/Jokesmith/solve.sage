import os; os.environ['TERM'] = 'xterm-256color'

from pwn import *
from Crypto.Util.number import long_to_bytes, bytes_to_long

context.log_level = 'info'

io = remote('connect.umbccd.net', 20549)

FLAG = r"DawgCTF{XXXXXXXXXXXXXXXXXXXXXXXXXXXX}"

inputs = ["1", "3", "5"]
assert all(ord(x) % 2 == 1 for x in inputs)

jokes = [
    "Why did the prime break up with the modulus? Because it wasn't factoring in its feelings",
    "Why did the cryptographer bring RSA to the dance? Because it had great curves — wait, no, wrong cryptosystem",
    "Why did the CTF player cross the road? To get to the "
]
transcript = []

for i in range(3):
    io.sendlineafter(b': ', inputs[i].encode())
    transcript.append(inputs[i])
    transcript.append(jokes[i])

io.recvuntil(b'private\n')

known = "\n".join(transcript)
known_int = bytes_to_long(known.encode())

c, N, e = [int(x.split(b'=')[1]) for x in io.recvlines(3)]

P.<x> = PolynomialRing(Zmod(N))
k = len(FLAG) * 8
f = (known_int * 2^k + x)^e - c

roots = f.small_roots(epsilon=0.04)
assert roots

x0 = roots[0]
print(long_to_bytes(int(x0)).decode())

io.close()

# DawgCTF{h4h4h4h4_s0_funny!!!!!!!!!!!}