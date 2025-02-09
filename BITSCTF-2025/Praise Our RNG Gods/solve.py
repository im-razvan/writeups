#!/usr/bin/python3
from pwn import *
from randcrack import RandCrack
import re

C = 195894762 ^ 322420958
D = 2969596945

rc = RandCrack()

r = remote('chals.bitskrieg.in', 7007)

r.recvuntil(b'> ')

for i in range(1, 625):
    # Send '0' as the attempt
    r.sendline(b'0')
    # Receive the response
    response = r.recvuntil(b'> ').decode()
    # Extract the difference using regular expression
    match = re.search(r'You are (\d+) away', response)
    if not match:
        print("Failed to parse difference. Response was:", response)
        r.close()
        exit()
    difference = int(match.group(1))
    # Compute M_i = (i ^ C) * D
    M_i = (i ^ C) * D
    # Compute R_i
    R_i = difference // M_i
    # Check if division was exact
    if R_i * M_i != difference:
        print(f"Error: difference {difference} is not divisible by M_i {M_i} at i={i}")
        r.close()
        exit()
    # Submit R_i to RandCrack
    rc.submit(R_i)
    print(f"Submitted R_{i} = {R_i}")

# Predict R_625
R_625 = rc.predict_getrandbits(32)
print(f"Predicted R_625: {R_625}")

# Compute password for i=625
i_625 = 625
M_625 = (i_625 ^ C) * D
password_625 = R_625 * M_625

r.sendline(str(password_625).encode())

# Profit :))
r.interactive()

# BITSCTF{V4u1t_cr4ck1ng_w45_345y_0384934}