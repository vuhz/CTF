# MSEC NEWBIE CTF

## mikutinhtoan

---

[original file](www.example.com)
[decompiler to asm](www.example.com)
[python script](www.example.com)

---

Check file MikuTinhToan bằng `file`:

```bash
┌──(root㉿sech)-[/mnt/c/Users/sech/S/ctf/real]
└─# file MikuTinhToan
MikuTinhToan: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
```

Bài này mình sẽ sử dụng **IDA64** để reverse.

Hàm hex to string:

```py
def hex2str(hex):
    hex = hex if not hex[:2] == '0x' else hex[2:]
    return ''.join(reversed(''.join(map(chr, [int(hex[i:i+2],16) for i in range(0,len(hex),2)]))))
```

#### Part 1:

Sử dụng remote linux debugger với parameter`aaaa`

![image](https://github.com/vuhz/CTF/assets/90823042/ed9dca98-90a9-4de1-a419-eebeb0b41808)

Đặt breakpoint tại `xor rbx, rax`, được giá trị `2A460D92F5A1F504` tại thanh rbx
vậy những gì ta cần làm chỉ là xor lại `2A460D92F5A1F504` và `4D2878DF96D49D47`

```py
flag = "MSEC{"

part1Hex = hex(0x2a460d92f5a1f504^0x4D2878DF96D49D47)
part1 = hex2str(part1Hex)
flag+=part1+"_" # MSEC{ChucMung_
```

#### Part 2:

Tiếp tục debug bằng param`ChucMung_`

![image](https://github.com/vuhz/CTF/assets/90823042/8287f1c2-ccfe-4d28-a36f-d46a5c1e9591)

Dựa trên code, ta có `(0xFFFFFFFF & rax) + x = 0x151610338`

> `x = 0x151610338 - (0xFFFFFFFF & rax)`

Đặt breakpoint ở `and rax, rcx` được rax = 4F7FB8ADE2F2CEF6

```py
part2Hex = hex(0x151610338 - (0x4F7FB8ADE2F2CEF6 & 0xFFFFFFFF))
part2 = hex2str(part2Hex)
flag+=part2+"_" # MSEC{ChucMung_B4nn_
```

#### Part 3:

![image](https://github.com/vuhz/CTF/assets/90823042/7db0bbbb-68bc-4d6e-b5e3-4791095ad7e5)


Dựa trên code, ta có thể thấy có duy nhất thanh `rbx` có giá trị không đổi sau khi gọi `_GetTData`, `rax` giữ giá trị input
Part này cũng được chia thành hai phần để check kết quả.
Ta có:

```py
rax = 0x2F3D4C4C45485300
rbx = 0xDEB4FA4D998C32FF
rcx = 0xF062C760BB349FAE

rcx = rax
rax = 0x0FFFFFFFFFF
rbx = hex(rbx & rax) # 0x4d998c32ff
```

Trong đó rcx là giá trị input, rbx là giá trị đúng của part nhỏ đầu tiên.
Với part sau `jb _BadFlag`, có thể dịch nó ra là `rcx - rbx = 0x25D4A4FD4B` hay `x - (0xDEB4FA4D998C32FF & 0x0FFFFFFFFFF) = 0x25D4A4FD4B`

```py
part3Hex = hex((0xDEB4FA4D998C32FF & 0x0FFFFFFFFFF) + 0x25D4A4FD4B)
part3 = hex2str(part3Hex)
flag+=part3+"_" # MSEC{ChucMung_B4nn_J01ns_
```

#### Part 4:

![image](https://github.com/vuhz/CTF/assets/90823042/3ac71c14-0e53-43dc-a277-114b8c453f61)

Ta có `rbx` = 0xDEB4FA4D998C32FF
Có một điểm đáng lưu ý là

```asm
mul     rbx
mov     r10, rax
mov     r11, rdx
```

Khi nhân `rax` với `rbx`, kết quả sẽ được lưu trong `rax`, và các 'high-order bits' sẽ được lưu trong `rdx`, sau đó được nhét vào `r10` và `r11`.
Vậy nên ta có kết quả của phép nhân đó là `[r11 << 64 | r10]` (user input)
Ta thấy `r10` và `r11` được so sánh với eax, vậy nên flag của dúng ta sẽ là **`x * rbx = input`**

> hay `x * 0xDEB4FA4D998C32FF = [0x58359C5CE9 << 64 | 0x0AF3ACD7938A1F0AE]`

```python3
part4Hex = hex((0x58359C5CE9 << 64 | 0x0AF3ACD7938A1F0AE) // 0xDEB4FA4D998C32FF)
part4 = hex2str(part4Hex)
flag+=part4+"_" # MSEC{ChucMung_B4nn_J01ns_Reeee_
```
#### Part 5:
![image](https://github.com/vuhz/CTF/assets/90823042/506c6f51-adf1-4c0b-ab6a-69e237e7cc20)


```asm
div     rcx
mov     r10, rax
mov     r11, rdx
```
Tương tự như trên, kết quả sẽ lưu vào `r10`, và phần dư sẽ ở trong `r11`
`rbx` lúc này có giá trị `0x1f6ff5218c40de9c`
Coi giá trị cần tìm là x:
`rbx / x = r10`
`rbx % x = r11`
> => x = (rbx - r11) / r10

```py
part5Hex = hex((0x1f6ff5218c40de9c-0x0DE6125020)//0x45B923)
part5 = hex2str(part5Hex)
flag+=part5+"}" # MSEC{ChucMung_B4nn_J01ns_Reeee_Teams}
```
