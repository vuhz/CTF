def hex2str(hex):
    hex = hex if not hex[:2] == '0x' else hex[2:]
    return ''.join(reversed(''.join(map(chr, [int(hex[i:i+2],16) for i in range(0,len(hex),2)]))))

flag = "MSEC{"

part1Hex = hex(0x2a460d92f5a1f504^0x4D2878DF96D49D47)
part1 = hex2str(part1Hex)
flag+=part1+"_"

part2Hex = hex(0x151610338 - (0x4F7FB8ADE2F2CEF6 & 0xffffffff))
part2 = hex2str(part2Hex)
flag+=part2+"_"

part3Hex = hex((0xDEB4FA4D998C32FF & 0x0FFFFFFFFFF) + 0x25D4A4FD4B)
part3 = hex2str(part3Hex)
flag+=part3+"_"

part4Hex = hex((0x58359C5CE9 << 64 | 0x0AF3ACD7938A1F0AE) // 0xDEB4FA4D998C32FF)
part4 = hex2str(part4Hex)
flag+=part4+"_"

part5Hex = hex((0x1f6ff5218c40de9c-0x0DE6125020)//0x45B923)
part5 = hex2str(part5Hex)
flag+=part5+"}"

print(flag)

