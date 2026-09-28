---
title: "RITSEC CTF 2026: Reverse Engineering Write-up"
published: 2026-04-05
description: "Reverse engineering notes from RITSEC CTF 2026."
tags:
  - CTF
  - Reverse Engineering
category: CTF
author: "Duc Nguyen"
draft: false
---

# ritsecCTF Write up

## T-reasure Chest

### Main function

* Xử lý input: padding và cấp phát bộ nhớ cho input với không gian là độ dài của input modulo cho 8

```c
v8 = strlen(s);                 // Lấy chiều dài chuỗi input
v7 = v8 % 8;                    // Lấy phần dư
dest = malloc(v8 + v8 % 8);     // Cấp phát vùng nhớ mới
memcpy(dest, s, v8);            
memset((char *)dest + v8, 0, v7); // Padding các byte 0
v8 += v7;                       // Cập nhật lại chiều dài
```
* Theo sau khi in ra một vài các thông tin của input thì chương trình đưa vào xử lý với hàm `sub_4012A9`
```c
sub_4012A9(dest, (unsigned int)v8, v5); // Có thể là hàm xử lý input chính
```
* Tiếp đến là check các điều kiện
```c
  if ( v8 == 34 && !memcmp(dest, &unk_404080, 0x22u) )
```

* Bên trong còn có thêm một hàm nữa là và đây là nội dung của nó
```c
__int64 __fastcall maybe_technique(unsigned int *a1, _DWORD *a2)
{
  unsigned int v3; // [rsp+1Ch] [rbp-14h]
  unsigned int v4; // [rsp+20h] [rbp-10h]
  int i; // [rsp+28h] [rbp-8h]
  int v6; // [rsp+2Ch] [rbp-4h]

  v4 = *a1;
  v3 = a1[1];
  v6 = 0;
  for ( i = 0; i <= 31; ++i )
  {
    v6 -= 1640531527;
    v4 += ((v3 >> 5) + a2[1]) ^ (v3 + v6) ^ (16 * v3 + *a2);
    v3 += ((v4 >> 5) + a2[3]) ^ (v4 + v6) ^ (16 * v4 + a2[2]);
  }
  *a1 = v4;
  a1[1] = v3;
  return v3;
}
```
* Đây là mã hóa TEA(Tiny Encrytion Algorithm) và giấu hiệu nhận biết ở đây là phép toán `v6 -= 1640531527` việc này sẽ khiến tràn bit nên phép toán này tương đương cộng với `0x9E3779B9`

### Solution

* Viết một chương trình decrypt đảo ngược vòng for thành 31-> 0 sau đó là thay đổi v6 thành cộng

```python
import struct

def decrypt_tea_block(block, key):
    # Lấy 8 bytes dữ liệu và 16 bytes khóa chia thành các khối 32-bit
    v0, v1 = struct.unpack('<II', block)
    k0, k1, k2, k3 = struct.unpack('<IIII', key)
    
    delta = 0x9E3779B9
    # Vì mã hóa chạy 32 vòng cộng delta, sum lúc giải mã sẽ bắt đầu từ delta * 32
    total_sum = (delta * 32) & 0xFFFFFFFF
    
    for _ in range(32):
        # Trật tự giải mã phải ngược lại mã hóa: giải mã v1 trước, sau đó đến v0
        v1 -= ((v0 >> 5) + k3) ^ (v0 + total_sum) ^ ((v0 << 4) + k2)
        v1 &= 0xFFFFFFFF
        
        v0 -= ((v1 >> 5) + k1) ^ (v1 + total_sum) ^ ((v1 << 4) + k0)
        v0 &= 0xFFFFFFFF
        
        # Cuối cùng mới lùi biến sum
        total_sum -= delta
        total_sum &= 0xFFFFFFFF
        
    return struct.pack('<II', v0, v1)

def decrypt_full(ciphertext, key):
    plaintext = b''
    # TEA xử lý theo từng block 8 bytes
    for i in range(0, len(ciphertext) - (len(ciphertext) % 8), 8):
        block = ciphertext[i:i+8]
        plaintext += decrypt_tea_block(block, key)
        
    # Phần byte dư (nếu có) thường sẽ không được đưa qua hàm TEA block
    remainder = len(ciphertext) % 8
    if remainder:
        plaintext += ciphertext[-remainder:]
        
    return plaintext

if __name__ == '__main__':
    key = b"tiny_encrypt_key"
    
    # Copy 34 bytes hex từ IDA dán vào đây (đây chỉ là dữ liệu mẫu thôi đấy)
    ciphertext = b'\x38\x75\x5B\xCB\x44\xD2\xBE\x5D\x96\x9C\x56\x43\xEA\x98\x06\x75\x4A\x48\x13\xE6\xD4\xE8\x8E\x4F\x72\x70\x8B\xFF\xDC\x99\xF8\x76\xC5\xC9'
    
    # Bắt đầu giải mã
    decrypted = decrypt_full(ciphertext, key)
    print("[*] Raw decrypted:", decrypted)
    
    # Cắt đi 5 byte null padding ở cuối do phép toán v8 + v8 % 8
    flag_length = 29
    print("[+] Flag:", decrypted[:flag_length].decode('utf-8', errors='ignore'))
```
* Recover: `b'RS{oh_its_a_TEAreasure_chest}\x00\x00\x00\xc5\xc9'`
* Flag: `RS{oh_its_a_TEAreasure_chest}`

## Buried_treasure

## not_quite_optimal

* Ngay khi chạy chương trình, bạn phải nói chuyện với chương trình

![](/resources/ritsec-ctf-2026/IMG/Screenshot%202026-04-05%20015342.png)

* Có vẻ như chương trình bắt tôi phải nhập mỗi chuỗi gì đó theo nó và bây giờ ta xét hàm main
### Hàm main

```c
vars0[65] = __readfsqword(0x28u);
  sub_18A0("<\thaiiii what r u doin here?\n\n>\t", 20, a3);
  __isoc99_scanf("%511[^\n]", vars0);
  sub_1950();
  if ( vars0[0] ^ 0x20676E696B6F6F6CLL | vars0[1] ^ 0x2065687420726F66LL
    || LODWORD(vars0[2]) != 1734437990
    || BYTE4(vars0[2]) )
  {
    v3 = 1;
    sub_18A0(
      "\n<\toh okie... not sure i can be much help with that... good luck tho!!!\n",
      20,
      vars0[0] ^ 0x20676E696B6F6F6CLL | vars0[1] ^ 0x2065687420726F66LL);
  }
```

* Ở đây ngay khi nhập input thì server sẽ kiểm tra xâu mà tôi nhập để quyết định response
* Từ điều kiện này thì chuỗi mà tôi cần nhập đó là : `looking for the flag`
```c
vars0[0] ^ 0x20676E696B6F6F6CLL | vars0[1] ^ 0x2065687420726F66LL
    || LODWORD(vars0[2]) != 1734437990
    || BYTE4(vars0[2])
```
* Sau đó chỉ cần trả lời các string có trong main(`please`, `PLEASE MAY I HAVE THE FLAG`) thì sẽ nhận được một flag từ từ hiện ra và nó chỉ đến một chỗ nhất định rồi dừng hẳn nên từ đây tôi phải tự tìm nốt flag

![](/resources/ritsec-ctf-2026/IMG/Screenshot%202026-04-05%20020205.png)

Flag chưa hoàn chỉnh: `RS{4_littl3_bi7_0f_nu`

* Manh mối

```c
 if ( !strcmp((const char *)vars0, "PLEASE MAY I HAVE THE FLAG") )
      {
        memset(vars0, 0, 0x200u);
        v7 = 0;
        sub_18A0("\n<\twaow i thought ud never ask... lemme go get it for you...\n", 20, v6);
        sub_18A0("\t...\n", 100, v8);
        sub_18A0("\t...\n\t", 150, v9);
        do
        {
          v10 = v7++;
          v11 = sub_1800(v10);
          putchar(v11);
          fflush(stdout);
        }
        while ( v7 != 84 );
        v3 = 0;
        sub_18A0("\n\tthat was exhausting, but there u are... mrrp meow", 20, v12);
      }
      else
      {
        sub_18A0(
          "\n"
          "<\tmeowmeow here u go... RITSEC{ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631"
          "EDCF22E8CCC1FB35B501C9C86}\n",
          20,
          v6);
      }
```

* Hàm in flag là hàm `sub_1800` nên chắc hẳn hàm này đang có gì đó

```c
__int64 __fastcall sub_1800(int a1)
{
  unsigned int v1; // r12d
  struct timespec v3; // [rsp+0h] [rbp-58h] BYREF
  struct timespec remaining; // [rsp+10h] [rbp-48h] BYREF
  _BYTE v5[24]; // [rsp+20h] [rbp-38h] BYREF
  unsigned __int64 v6; // [rsp+38h] [rbp-20h]

  v6 = __readfsqword(0x28u);
  v3.tv_sec = 0;
  v3.tv_nsec = 300000000LL * a1; // tăng dần thời gian ngủ lên khiến chương trình chờ lâu mà terminate
  nanosleep(&v3, &remaining);
  __gmpz_init(v5);
  v1 = sub_15F0(v5, qword_22A0[2 * a1], qword_22A0[2 * a1 + 1]);
  __gmpz_clear(v5);
  return v1;
}
```
* Có thể thấy lý do mà nó không nhả ra flag nữa nằm ở `v3.tv_nsec = 300000000LL * a1;` nghĩa là nó đang tự tăng thời gian lên sau mỗi lần in kí tự nhưng dù có cố patching binary thì thứ nhận được vẫn là tốc độ như cũ
* Vậy nên ta cần một giải pháp khác
### Solution 

* Mấu chốt nằm ở đây
```c
unsigned __int64 __fastcall sub_15F0(__int64 a1, __int64 a2, __int64 a3)
{
  _DWORD v5[4]; // [rsp+0h] [rbp-78h] BYREF
  _BYTE v6[16]; // [rsp+10h] [rbp-68h] BYREF
  _BYTE v7[16]; // [rsp+20h] [rbp-58h] BYREF
  _BYTE v8[4]; // [rsp+30h] [rbp-48h] BYREF
  int v9; // [rsp+34h] [rbp-44h]
  _BYTE *v10; // [rsp+38h] [rbp-40h]
  unsigned __int64 v11; // [rsp+48h] [rbp-30h]

  v11 = __readfsqword(0x28u);
  if ( !a3 )
    goto LABEL_14;
  if ( a3 == 1 )
  {
    ((void (*)(void))__gmpz_set_ui)();
    return 0;
  }
  if ( !a2 )
  {
    __gmpz_set_ui(a1, (a3 & 1) == 0);
    return 0;
  }
  if ( a2 == 1 )
  {
LABEL_14:
    __gmpz_set_ui(a1, 1);
    return 0;
  }
  __gmpz_inits(v5, v6, 0);
  sub_15F0(v5, a2, a3 - 1);
  __gmpz_set_ui(v6, a2);
  if ( v5[1] )
  {
    if ( (unsigned int)__gmpz_cmp_ui(v5, 1) )
    {
      __gmpz_inits(v7, v8, 0);
      __gmpz_set(v7, v6);
      __gmpz_set(v8, v5);
      __gmpz_set_ui(a1, 1);
      while ( v9 > 0 )
      {
        if ( (*v10 & 1) != 0 )
          __gmpz_mul(a1, a1, v7);
        __gmpz_fdiv_q_2exp(v8, v8, 1);
        if ( v9 <= 0 )
          break;
        __gmpz_mul(v7, v7, v7);
      }
      __gmpz_clears(v7, v8, 0);
    }
    else
    {
      __gmpz_set(a1, v6);
    }
  }
  else
  {
    __gmpz_set_ui(a1, 1);
  }
  __gmpz_clears(v5, v6, 0);
  return (unsigned __int64)(__gmpz_fdiv_ui(a1, 256) + 1) >> 1;
}
```
* Hàm `sub_15F0` này là một tháp đệ quy khiến cho việc in ra các chữ chậm hơn dù có chuyển các giá trị ở trên về 0 thì nó vẫn sẽ in ra với tốc độ chậm
* Bằng cách sử dụng Lũy thừa nhanh (Exponentiation by Squaring) rồi chạy mộ vòng lặp while để khiến nó tiếp tục tăng thời gian chờ output
* Vậy nên việc cần làm đó là dump toàn bộ byte của `qword_22A0` từ hàm trước và sau đó sử dụng python để giải bài

```.rodata
.rodata:00000000000022A0 qword_22A0      dq 0AC83Bh, 2, 192B75h, 2, 3295C5h, 2, 380B97h, 2, 4B32CDh

.rodata:00000000000022A0                                         ; DATA XREF: sub_1800+59↑o

.rodata:00000000000022E8                 dq 2, 644A27h, 2, 6EA6D1h, 2, 7A2A17h, 2, 8CEA17h, 2, 0A7D527h

.rodata:0000000000002338                 dq 2, 0B9A435h, 2, 0C1FECDh, 2, 0D8701Bh, 2, 0E7BCD1h

.rodata:0000000000002378                 dq 2, 0F8807Dh, 2, 105B8CDh, 2, 119019Fh, 2, 12D65D3h

.rodata:00000000000023B8                 dq 2, 1377FCDh, 2, 14AD443h, 2, 15DC5A9h, 2, 99h, 3, 13Bh

.rodata:0000000000002408                 dq 3, 0F5h, 3, 11Bh, 3, 10Dh, 3, 197h, 3, 12Fh, 3, 0F5h

.rodata:0000000000002468                 dq 3, 19Fh, 3, 11Bh, 3, 1F1h, 3, 20Dh, 3, 1E3h, 3, 1F5h

.rodata:00000000000024C8                 dq 3, 253h, 3, 1F5h, 3, 21Bh, 3, 30Dh, 3, 22Fh, 3, 2A9h

.rodata:0000000000002528                 dq 3, 31Bh, 3, 93BDh, 4, 5C80Dh, 4, 83417h, 4, 0BFE63h

.rodata:0000000000002578                 dq 4, 0ECEF1h, 4, 0FE69Fh, 4, 136563h, 4, 17DBF5h, 4, 18EF0Dh

.rodata:00000000000025C8                 dq 4, 1D4661h, 4, 1F1071h, 4, 2300BBh, 4, 266BF5h, 4, 28E4F5h

.rodata:0000000000002618                 dq 4, 2C2D53h, 4, 2E4A71h, 4, 3170C1h, 4, 34E71Bh, 4, 399929h

.rodata:0000000000002668                 dq 4, 3BA955h, 4, 4000BDh, 4, 0D38Fh, 2475Eh, 13C19Fh

.rodata:00000000000026A8                 dq 93B18h, 250971h, 188B49h, 3F5F29h, 2140B1h, 512453h

.rodata:00000000000026D8                 dq 2257B6h, 597D8Fh, 2CC821h, 6DD271h, 3403C8h, 8258C1h

.rodata:0000000000002708                 dq 4293DEh, 8A3CF5h, 4BC176h, 0A5D78Fh, 4D0988h, 0B286F3h

.rodata:0000000000002738                 dq 57C733h, 0C4808Fh, 608647h, 0D43161h, 6A62C7h, 0E399C1h

.rodata:0000000000002768                 dq 758263h, 0F535C1h, 77E604h, 10BEFF5h, 8485C0h, 11680F3h

.rodata:0000000000002798                 dq 8ED167h, 1274329h, 964D2Fh, 13DFB89h, 9EB989h, 14B5AF5h

.rodata:00000000000027C8                 dq 0A1FEB6h, 154E4B9h, 0AC71A9h

.rodata:00000000000027C8 _rodata         ends
```

* Code giải
```python
import math
import sys

sys.set_int_max_str_digits(1000000)

def phi(n):
    amount = 0
    for k in range(1, n + 1):
        if math.gcd(n, k) == 1:
            amount += 1
    return amount

def power_tower_mod(base, height, mod):
    if mod == 1:
        return 0
    if height == 0:
        return 1
    if height == 1:
        return base % mod
        
    p = phi(mod)
    exp = power_tower_mod(base, height - 1, p)
    return pow(base, exp + p, mod)

data = [
    # a3 = 2
    (0x0AC83B, 2), (0x192B75, 2), (0x3295C5, 2), (0x380B97, 2), (0x4B32CD, 2),
    (0x644A27, 2), (0x6EA6D1, 2), (0x7A2A17, 2), (0x8CEA17, 2), (0x0A7D527, 2),
    (0x0B9A435, 2), (0x0C1FECD, 2), (0x0D8701B, 2), (0x0E7BCD1, 2), (0x0F8807D, 2),
    (0x105B8CD, 2), (0x119019F, 2), (0x12D65D3, 2), (0x1377FCD, 2), (0x14AD443, 2),
    (0x15DC5A9, 2),
    
    # a3 = 3
    (0x99, 3), (0x13B, 3), (0x0F5, 3), (0x11B, 3), (0x10D, 3),
    (0x197, 3), (0x12F, 3), (0x0F5, 3), (0x19F, 3), (0x11B, 3),
    (0x1F1, 3), (0x20D, 3), (0x1E3, 3), (0x1F5, 3), (0x253, 3),
    (0x1F5, 3), (0x21B, 3), (0x30D, 3), (0x22F, 3), (0x2A9, 3),
    (0x31B, 3),
    
    # a3 = 4
    (0x93BD, 4), (0x5C80D, 4), (0x83417, 4), (0x0BFE63, 4), (0x0ECEF1, 4),
    (0x0FE69F, 4), (0x136563, 4), (0x17DBF5, 4), (0x18EF0D, 4), (0x1D4661, 4),
    (0x1F1071, 4), (0x2300BB, 4), (0x266BF5, 4), (0x28E4F5, 4), (0x2C2D53, 4),
    (0x2E4A71, 4), (0x3170C1, 4), (0x34E71B, 4), (0x399929, 4), (0x3BA955, 4),
    (0x4000BD, 4),
    
    # Chaos layer
    (0x0D38F, 0x2475E), (0x13C19F, 0x93B18), (0x250971, 0x188B49), (0x3F5F29, 0x2140B1),
    (0x512453, 0x2257B6), (0x597D8F, 0x2CC821), (0x6DD271, 0x3403C8), (0x8258C1, 0x4293DE),
    (0x8A3CF5, 0x4BC176), (0x0A5D78F, 0x4D0988), (0x0B286F3, 0x57C733), (0x0C4808F, 0x608647),
    (0x0D43161, 0x6A62C7), (0x0E399C1, 0x758263), (0x0F535C1, 0x77E604), (0x10BEFF5, 0x8485C0),
    (0x11680F3, 0x8ED167), (0x1274329, 0x964D2F), (0x13DFB89, 0x9EB989), (0x14B5AF5, 0x0A1FEB6),
    (0x154E4B9, 0x0AC71A9)
] # Các hex byte trong qword_22A0

flag = ""
for a2, a3 in data:
    # Bước shift bit thần thánh để ra flag
    char_val = (power_tower_mod(a2, a3, 256) + 1) >> 1
    flag += chr(char_val)

print("Flag:", flag)
```
Flag: `RS{4_littl3_bi7_0f_numb3r_th30ry_n3v3r_hur7_4ny0n3_19b3369a25c78095689a38f81aa3f5e3}`

## Obfyscated

## Deadwater

### Yapping analysis

* Khi vừa chạy chương trình, chương trình ngay lập tức trả về chuỗi `narrr`
![First encounter](/resources/ritsec-ctf-2026/IMG/Screenshot%202026-04-05%20110034.png)
* Có lẽ không điền gì cả thì nó cũng nhận input là không có gì và đương nhiên trong hàm main có một điều kiện

```c
  if ( a1 == 2 && strlen(a2[1]) == 80 )
  {
    for ( i = 0; i != 40; ++i )
    {
      if ( (unsigned int)__isoc99_sscanf(&a2[1][2 * i], "%02x", v35) != 1 )
      {
        puts("narrrr");
        return 1;
      }
      *((_BYTE *)&v35[6] + i) = v35[0];
    }
  }
```
* Input nhập vào cần có độ dài 80 kí tự rồi được băm bằng `sscanf` để chuyển 80 kí tự thành dữ liệu 40 bytes và nhét vào v35
* Tiếp theo chương trình sẽ khởi tạo một vùng nhớ
```c
qword_4018 = (__int64)mmap(nullptr, 0x18000u, 3, 34, -1, 0);
    v6 = qword_4018;
    v7 = 0;
    v8 = 0;
    v9 = 0;
    v10 = 0;
    v11 = 0x9E7448B1D3CF26ALL;
    addr = (void *)qword_4018;
```
* Đây là quá trình khởi tạo S-box để tạo ra một bảng tra cứu random có giá trị tầm 96KB bằng thuật toán PNGR
![Đọc thêm](https://en.wikipedia.org/wiki/Pseudorandom_number_generator)
* Tiếp theo chương trình sử dụng các technique anti-debug bằng `Intel TSX (Transactional Synchronization Extensions)` với các lệnh dưới đây khiến việc debug không thể thực hiện được
```c
wrgsbase rax
xbegin
xbegin
xtest
xabort
rdgsbase rbp
```
* Tiếp đến là phần logic chính của chương trình này
```c
BYTE1(v18) = v16;
    v20 = (v18 << 24) & 0xFF00000000LL;
    v21 = v35;
    for ( k = 10; k; --k )
      *v21++ = 0;
    v23 = qword_4018;
    v24 = 0;
    v25 = 0x823EAF93561AD964LL;
    v26 = 0x70E71C5389DLL;
    do
    {
      v27 = 0;
      v28 = 0;
      do
      {
        LOBYTE(v29) = 0;
        if ( (unsigned __int8)(v20 ^ HIBYTE(v26)) == (_DWORD)v27 )
          v29 = *(_QWORD *)(v23 + (v24 << 11) + 8 * v27);
        v28 |= v29;
        ++v27;
      }
      while ( v27 != 256 );
      v35[(int)v24 / 8] |= (unsigned __int64)(unsigned __int8)(*((_BYTE *)&v35[6] + v24) ^ v28) << (8
                                                                                                  * (unsigned __int8)((int)v24 % 8));
      v30 = __ROR8__((v25 + v26) ^ v20, 56);
      v31 = v30 + _RBP;
      v32 = __ROR8__(v31 ^ v25, 45);
      v33 = v32 + v25 + v26;
      v20 = __ROR8__(v33 ^ v30, 24);
      _RBP = v20 + v31;
      v26 = __ROR8__(_RBP + v33, 37);
      v25 = v26 ^ (0xAAAAAAAAAAAAAAABLL * v24++) ^ (0xD2A98B26625EEE7BLL * __ROR8__(_RBP ^ v32, 1));
    }
```

* Cuối cùng là bước xác minh

```c
if ( v35[3] == 0xA89E4C1254BA31BLL
      && v35[2] == 0x4F9BDE7A77AE197LL
      && v35[1] == 0x376DDFC434D0F4D4LL
      && v35[0] == 0xF0C553137025AFD6LL
      && v35[4] == 0xB7C0F25B3F70D12BLL )
    {
      puts("yarrr");
      return 0;
    }
```
### Solution

```python
import struct

def ROR8(val, shift):
    """Mô phỏng phép xoay bit vòng phải 64-bit"""
    return ((val >> shift) | (val << (64 - shift))) & 0xFFFFFFFFFFFFFFFF

def solve():
    MASK64 = 0xFFFFFFFFFFFFFFFF
    
    print("[*] Patching...")
    sbox = []
    v7, v8, v9, v10 = 0, 0, 0, 0
    v11 = 0x9E7448B1D3CF26A

    for block in range(40): 
        j = 0
        v13 = 0
        for _ in range(256):
            xor_bit = ((v11 >> 2) & 1) ^ ((v11 >> 3) & 1) ^ (v11 & 1) ^ ((v11 >> 63) & 1)
            v15 = (v10 + v11 + xor_bit) & MASK64
            
            v10 = 1 if v15 < v11 else 0
            v11 = ROR8(v15, 57)
            
            shift_amt = v9 % 64
            if shift_amt == 0:
                j_rot = j
            else:
                j_rot = ((j << shift_amt) | (j >> (64 - shift_amt))) & MASK64
            
            val = (v11 ^ v8 ^ v13 ^ j_rot) & MASK64
            sbox.append(val)
            
            v13 = (v13 + v7) & MASK64
            j = (j + 0x6C62272E07BB0142) & MASK64
            
        v9 += 1
        v8 = (v8 - 0x61C8864680B583EB) & MASK64
        v7 = (v7 - 0x40A7B892E31B1A47) & MASK64

    targets = [
        0xF0C553137025AFD6,
        0x376DDFC434D0F4D4,
        0x04F9BDE7A77AE197,
        0x0A89E4C1254BA31B,
        0xB7C0F25B3F70D12B
    ]
    
    target_bytes = []
    for t in targets:
        target_bytes.extend(t.to_bytes(8, 'little'))

    print("[*] Đang chạy lại máy trạng thái...")
    
    for v16_guess in range(256):
        RBP = 0x70E71C5389D
        v20 = (v16_guess << 32) 
        v25 = 0x823EAF93561AD964
        v26 = 0x70E71C5389D

        flag = bytearray()
        
        for v24 in range(40):
            v27 = (v20 ^ (v26 >> 56)) & 0xFF 
            
            v29 = sbox[v24 * 256 + v27]
            v28 = v29 & 0xFF
            
            flag_byte = target_bytes[v24] ^ v28
            flag.append(flag_byte)
            
            # ĐÃ VÁ LỖI TRÀN SỐ CỦA PYTHON Ở ĐÂY RỒI NHÉ!
            v30 = ROR8(((v25 + v26) & MASK64) ^ v20, 56)
            v31 = (v30 + RBP) & MASK64
            v32 = ROR8(v31 ^ v25, 45)
            v33 = (v32 + v25 + v26) & MASK64
            v20 = ROR8(v33 ^ v30, 24)
            RBP = (v20 + v31) & MASK64
            v26 = ROR8((RBP + v33) & MASK64, 37)
            
            magic1 = (0xAAAAAAAAAAAAAAAB * v24) & MASK64
            magic2 = (0xD2A98B26625EEE7B * ROR8(RBP ^ v32, 1)) & MASK64
            v25 = v26 ^ magic1 ^ magic2

        try:
            decoded = flag.decode('utf-8', errors='ignore')
            # Xóa sạch đống null padding ở cuối
            clean_flag = decoded.rstrip('\x00')
            
            # Đảm bảo flag là ASCII in được và phải chuẩn format
            if "{" in clean_flag and clean_flag.isprintable():
                if clean_flag.startswith("RS{") or "RITSEC" in clean_flag:
                    print(f"\n[+] TÌM THẤY FLAG XỊN RỒI NÀY! (Trạng thái byte v16 = {hex(v16_guess)})")
                    print(f"    --> Flag: {clean_flag}")
                    return
        except:
            pass

if __name__ == '__main__':
    solve()
```

