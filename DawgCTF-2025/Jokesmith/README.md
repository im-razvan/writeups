# Jokesmith - 350 points

Respect the conditions and get the public RSA values (c, N, e=3), treat m as known prefix plus small flag and build `f = (known_int * 2^k + x)^e - c`. From there use Coppersmith’s lattice attack to recover the flag.

Flag: `DawgCTF{h4h4h4h4_s0_funny!!!!!!!!!!!}`