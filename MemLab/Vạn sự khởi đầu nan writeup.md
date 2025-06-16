---
title: Vạn sự khởi đầu nan writeup

---

Oke thì đây là 1 wu của chall "Vạn sự khởi đầu nan". Challenge này thuộc về mảng meme forensics

![image](https://hackmd.io/_uploads/HyNQRi6tye.png)

Challenge sẽ có 1 file attachment .raw

Bước đầu tiên trong các bài về memory, thường sẽ recon về hđh của máy, để phục vụ cho viện điều tra sâu hơn và cũng như là điều bắt buộc nếu sử dụng vol2

```
╰─ python2 ~/tools/volatility2/vol.py -f Lab1.raw imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/mnt/e/CTF/2025/lmaoCTF/Lab1.raw)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf800028100a0L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002811d00L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2019-12-11 14:38:00 UTC+0000
     Image local date and time : 2019-12-11 20:08:00 +0530
    
```

Thì có thể thấy nó có rất nhiều profile trùng với con máy này, toi sẽ sử dụng **Win7SP1x64** nhé.

Tiếp theo thì xem những tiến trình đang chạy ở thời điểm capture để xem có gì sú sú không.
```
python2 ~/tools/volatility2/vol.py -f Lab1.raw --profile Win7SP1x64 pstree
```

![image](https://hackmd.io/_uploads/SkLkcoaYJl.png)

thì ta có thể thấy có 1 vài process khá bất thường như **cmd.exe**, **mspaint.exe**(thằng này cũng được đề cập trong des "*Khi xảy ra sự cố, tôi nhớ step bro mình đang vẽ một cái gì đấy. Đấy là toàn bộ những gì mình nhớ*").

Bắt đầu tìm hiểu xem thằng **cmd.exe** đang làm gì.


![image](https://hackmd.io/_uploads/SyNmmi6F1x.png)

Nó đang thực hiện việc gọi tới 1 file gì đó tên là **St4G3$1**

toi sẽ lục xem trong toàn hệ thống có file nào với tên **St4G3$1** không.

![image](https://hackmd.io/_uploads/HksSQiaFkg.png)
*(toi đã ghi kết quả của filescan vào file text cho dễ xem lại kết quả)*

thì có 1 file là **\Device\HarddiskVolume2\Windows\System32\St4G3$1.bat** đang nằm ở offset **0x000000003edcfd70**



```
0x000000003edcfc20      1      0 R--rw- \Device\HarddiskVolume2\Windows\System32\St4G3$1.bat
```
Toi sẽ dump để kiểm tra xem trong file đó có gì sú



```
python2 ~/tools/volatility2/vol.py -f Lab1.raw --profile Win7SP1x64 dumpfiles --dump-dir="/mnt/e/CTF/2025/lmaoCTF" -Q 0x000000003edcfc20
```

![image](https://hackmd.io/_uploads/Hk3FSs6Yyx.png)

thì sau khi dump ra và đổi tên file lại, thì toi bỏ nó vào **HxD** để kiểm tra trước, thì thấy nó đang thực hiện việc echo 1 chuỗi base64, decode đoạn base64 này thì ta được flag 1 (thật ra chúng ta có thể decode ngay ở bước kiểm tra console, nhưng để mọi thứ sáng tỏ hơn thì toi đã dump ra luôn cho chắc).


![image](https://hackmd.io/_uploads/HJKRBjTFkg.png)

```
flag1: flag{th1s_1s_th3_1st_st4g3!!}
```


vậy là giải quyết được 1/3 bài rồi, chúng ta tiếp tục nào.

ở flag 2 chúng ta được 1 manh mối trong description là *"Khi xảy ra sự cố, tôi nhớ step bro mình đang vẽ một cái gì đấy"*

Liên kết với mô tả này, chúng ta cũng thấy có 1 thằng process là **mspaint.exe**






![image](https://hackmd.io/_uploads/SkLkcoaYJl.png)


Toi sẽ dump thử tiến trình này xem bên trong nó có gì thú vị không.
```
python2 ~/tools/volatility2/vol.py -f Lab1.raw --profile Win7SP1x64 memdump -p 2424 --dump-dir="/mnt/e/CTF/2025/lmaoCTF"
```


![image](https://hackmd.io/_uploads/rkRLvERY1l.png)

Thì ta được 1 file 2424.dmp

Tới đây toi lại gặp bế tắc, toi éo biết mở cái file này kiểu éo gì. Thử **strings**, **HxD**,... để xem rùa được không thì cũng không ăn thua.

Toi stuck ở đây chắc 3 4 tiếng, thấy mất thời gian quá toi qua đấm thử chall cuối luôn xem sao.


Toi bắt đầu lục lọi xem có manh mối gì cho chall3 không.

Cũng loay hoay một hồi không có gì để xoáy vào, thì toi mới nhớ idol toi có bảo nên sử dụng song song cả vol2 và vol3, nhiều lúc thằng này có mà thằng kia không có.

Toi bắt đầu pstree lại bằng vol3 để xem thử

```
vol -f Lab1.raw windows.pstree > pstreeVol3
```

Thì quả nhiên là có 1 process đang chạy WinRar mà có thể toi đã sót khi dùng vol2(pstree của vol3 cung cấp thông tin chi tiết hơn so với vol2).

![image](https://hackmd.io/_uploads/ryXshjpKJx.png)

Nó đang mở một file có tên là **Important.rar**. Thử qua filescan để xem vị trí file và offset của nó để tiện cho việc dump file.

![image](https://hackmd.io/_uploads/ry-4TjpFyx.png)

oke chúng ta sẽ dump nó ra.

```
python2 ~/tools/volatility2/vol.py -f Lab1.raw --profile Win7SP1x64 dumpfiles --dump-dir="/mnt/e/CTF/2025/lmaoCTF" -Q 0x000000003fa3ebc0
Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x3fa3ebc0   None   \Device\HarddiskVolume2\Users\Alissa Simpson\Documents\Important.rar
```
khi mở **Important.rar** này bằng WinRar thì có 1 dòng description:
*"Password is NTLM hash(in uppercase) of Alissa's account passwd."*

![image](https://hackmd.io/_uploads/SkrjuqpYyl.png)

Dựa vào mô tả trên, toi dùng **hashdump** để trích xuất các hash của các mật khẩu từ bộ nhớ của windows để lấy NTLM hash của user Alissa.




```
python2 ~/tools/volatility2/vol.py -f Lab1.raw --profile Win7SP1x64 hashdump
```

![image](https://hackmd.io/_uploads/ryVOc96YJe.png)

Toi sẽ crack NTLM hash này bằng hashcat

```
hashcat -m 1000 -a 0 test.txt rockyou.txt
```

và đây là kết quả:
```
f4ff64c8baac57d22f22edc681055ba6:goodmorningindia

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: f4ff64c8baac57d22f22edc681055ba6
```

Tôi sử dụng đoạn string đã được crack ở trên để nhập pass cho thằng Important.rar này. Nhưng tđn nó lại sai, wthhhhhhhhhhhhh.

![image](https://hackmd.io/_uploads/r1iwhcpt1g.png)

xong wtf toi mới đọc lại description và nhận ra là éo cần crack, chỉ cần nhập chính xác đoạn NTLM hash đó ở dạng uppercase là được. Mé. Thoi dù gì cũng đã giải *easter egg* của tác giả vậy.

Trong file rar đó của 1 bức ảnh flag.

![image](https://hackmd.io/_uploads/ByUT2qpFke.png)

```
flag3: flag{w3ll_3rd_stage_was_easy}
```


---
Oke thì sau khi xong chall3 toi quầy lại chall2 để làm tiếp thì cũng éo thấy manh mối gì, bí quá toi đành đánh 1 giấc rồi tính :clown_face:.

Sau thời gian research mòn mỏi thì toi cũng đã tìm thấy được 1 writeup của giải Google-CTF-2016, trong đó có để cập việc xử lý raw image data bằng app **GIMP** (Chân ái đây rồi).

https://github.com/h4x0r/ctf-writeups/blob/master/Google-CTF-2016/For1/README.md

Trong writeup này cũng đề cập đến 1 cái blog:
https://w00tsec.blogspot.com/2015/02/extracting-raw-pictures-from-memory.html

Trước khi mở file raw image data này bằng **GIMP** thì chúng ta cần đổi file extension của nó từ .dmp -> .data.


![image](https://hackmd.io/_uploads/BkHsfSCFyg.png)

Lúc đầu khi mở nó chỉ là màu trắng này thoi, chúng ta cần phải điều chỉnh các thông số như offset, width, height của nó.

:shit: quằng kinh khủng.

Sau gần nửa tiếng hơn ngồi chỉnh tới lui thì nó cũng ra giống giống flag hơn rồi đấy.



![image](https://hackmd.io/_uploads/HJpJ-r0K1x.png)


Nhưng nếu để nhưng vậy thì đọc lòi mắt cũng chưa chắc được flag, nên chúng ta cần điều chỉnh thêm về việc xoay(rotate) và lật(flip) bức ảnh. Research cách dùng app này thì nó nằm ở mục tools nhé. 



![image](https://hackmd.io/_uploads/rJHoMERYJx.png)

sau 1 vài điều chỉnh thì chúng ta cũng đã lấy được flag.


```
flag2: flag{G00d_Boy_good_girL}
```


