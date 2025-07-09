# =========================================================================
# SCRIPT GỠ CÀI ĐẶT VÀ DỌN DẸP HOÀN TOÀN AUTODESK - PHIÊN BẢN SỬA LỖI
# Đã sửa lỗi xử lý đường dẫn có dấu cách (C:\Program Files)
# =========================================================================

function Autodesk-Uninstaller-Fixed {
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $apps = Get-ItemProperty -Path $registryPaths -ErrorAction SilentlyContinue
    $apps = $apps | Where-Object { ($_.DisplayName -like "*Autodesk*") -or ($_.Publisher -like "*Autodesk*") -or ($_.DisplayName -like "*AutoCAD*") -or ($_.DisplayName -like "*Inventor*") }
    $apps = $apps | Select-Object DisplayName, Publisher, PSChildName, UninstallString -Unique

    if ($apps) {
        Write-Host "Tìm thấy $($apps.Count) sản phẩm Autodesk. Bắt đầu gỡ cài đặt..." -ForegroundColor Yellow
        foreach ($app in $apps) {
            if ($app.UninstallString) {
                Write-Host "Đang gỡ: $($app.DisplayName)..."
                
                # Tách lệnh và các tham số có sẵn
                $command = $app.UninstallString
                $executable = ""
                $arguments = ""

                # Xử lý đường dẫn có dấu cách được bao trong dấu ngoặc kép
                if ($command.StartsWith('"')) {
                    $executable = ($command -split '"')[1]
                    $arguments = $command.Substring($executable.Length + 2).Trim()
                } else {
                    # Xử lý đường dẫn không có dấu ngoặc kép
                    $parts = $command -split ' ', 2
                    $executable = $parts[0]
                    if ($parts.Length -gt 1) {
                        $arguments = $parts[1]
                    }
                }
                
                # Thêm các tham số để gỡ cài đặt một cách im lặng (silent uninstall)
                # Đây là các tham số phổ biến, có thể không đúng với mọi trình gỡ cài đặt
                $silentArgs = "/S /q /qn --mode unattended"

                # Chạy trình gỡ cài đặt
                if (Test-Path $executable) {
                    try {
                        # Kết hợp các tham số có sẵn và tham số silent
                        $finalArguments = "$arguments $silentArgs"
                        Start-Process -FilePath $executable -ArgumentList $finalArguments -Wait -NoNewWindow -ErrorAction Stop
                    } catch {
                        Write-Host "LỖI khi chạy trình gỡ cài đặt cho '$($app.DisplayName)'." -ForegroundColor Red
                    }
                } else {
                     Write-Host "CẢNH BÁO: Không tìm thấy trình gỡ cài đặt tại '$executable' cho '$($app.DisplayName)'. Có thể nó đã bị xóa." -ForegroundColor Yellow
                }
            }
        }
    } else {
        Write-Host "Không tìm thấy sản phẩm Autodesk nào để gỡ cài đặt." -ForegroundColor Green
    }
}

# --- BƯỚC 1: GỠ CÀI ĐẶT ỨNG DỤNG (Chạy nhiều lần để xử lý dependencies) ---
Write-Host "--- Bắt đầu Bước 1: Gỡ cài đặt ứng dụng (có thể mất vài phút) ---" -ForegroundColor Cyan
foreach ($i in 1..3) {
    Write-Host "`nChạy lần thứ $i..."
    Autodesk-Uninstaller-Fixed
}

# --- BƯỚC 2: DỪNG CÁC DỊCH VỤ CÒN SÓT LẠI ---
Write-Host "`n--- Bắt đầu Bước 2: Dừng các dịch vụ còn sót lại ---" -ForegroundColor Cyan
Get-Service -Name "*Adsk*", "*Autodesk*", "*FlexNet*" | Stop-Service -Force -ErrorAction SilentlyContinue
Write-Host "Đã dừng các dịch vụ liên quan."

# --- BƯỚC 3: DỌN DẸP CÁC THƯ MỤC CÒN SÓT LẠI ---
Write-Host "`n--- Bắt đầu Bước 3: Xóa các thư mục còn sót lại ---" -ForegroundColor Cyan
$foldersToDelete = @(
    "$env:ProgramFiles\Autodesk",
    "$env:ProgramFiles(x86)\Common Files\Autodesk Shared",
    "$env:ProgramFiles(x86)\Autodesk",
    "$env:ProgramData\Autodesk",
    "$env:LOCALAPPDATA\Autodesk",
    "$env:APPDATA\Autodesk"
)
foreach ($folder in $foldersToDelete) {
    if (Test-Path $folder) {
        Write-Host "Đang xóa: $folder" -ForegroundColor Yellow
        Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "Đã hoàn tất dọn dẹp thư mục." -ForegroundColor Green

# --- BƯỚC 4: DỌN DẸP REGISTRY ---
Write-Host "`n--- Bắt đầu Bước 4: Xóa các khóa Registry ---" -ForegroundColor Cyan
try { Remove-Item -Path "HKCU:\Software\Autodesk" -Recurse -Force -ErrorAction Stop; Write-Host "Đã xóa khóa Registry: HKCU:\Software\Autodesk" -ForegroundColor Green } catch {}
try { Remove-Item -Path "HKLM:\SOFTWARE\Autodesk" -Recurse -Force -ErrorAction Stop; Write-Host "Đã xóa khóa Registry: HKLM:\SOFTWARE\Autodesk" -ForegroundColor Green } catch {}

# --- BƯỚC 5: HOÀN TẤT ---
Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "QUÁ TRÌNH DỌN DẸP HOÀN TẤT!" -ForegroundColor Green
Write-Host "Vui lòng KHỞI ĐỘNG LẠI MÁY TÍNH để hoàn tất mọi thay đổi." -ForegroundColor Yellow
