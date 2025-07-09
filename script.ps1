function Autodesk-Uninstaller {
    $apps = @()
    $apps = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $apps += Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $apps = $apps | Where-Object {($_.DisplayName -like "*Autodesk*") -or ($_.Publisher -like "*Autodesk*") -or ($_.DisplayName -like "*AutoCAD*") -or ($_.DisplayName -like "*Inventor*")}
    $apps = $apps | Select-Object DisplayName, Publisher, PSChildName, UninstallString -Unique

    if ($apps.Count -gt 0) {
        Write-Host "Tìm thấy $($apps.Count) sản phẩm Autodesk. Bắt đầu gỡ cài đặt..." -ForegroundColor Yellow
        foreach ($app in $apps) {
            # Xử lý các trường hợp đặc biệt
            if ($app.DisplayName -match "Autodesk Access"){
                Write-Host "Đang gỡ: Autodesk Access..."
                Start-Process -FilePath "C:\Program Files\Autodesk\AdODIS\V1\Installer.exe" -ArgumentList "-q -i uninstall --trigger_point system -m C:\ProgramData\Autodesk\ODIS\metadata\{A3158B3E-5F28-358A-BF1A-9532D8EBC811}\pkg.access.xml -x `"C:\Program Files\Autodesk\AdODIS\V1\SetupRes\manifest.xsd`" --manifest_type package" -NoNewWindow -Wait
            }
            if ($app.DisplayName -match "Autodesk Identity Manager"){
                Write-Host "Đang gỡ: Autodesk Identity Manager..."
                Start-Process -FilePath "C:\Program Files\Autodesk\AdskIdentityManager\uninstall.exe" -ArgumentList "--mode unattended" -NoNewWindow -Wait
            }
            if ($app.DisplayName -match "Autodesk Genuine Service"){
                Write-Host "Đang gỡ: Autodesk Genuine Service..."
                msiexec.exe /x "{21DE6405-91DE-4A69-A8FB-483847F702C6}" /qn
            }

            # Xử lý các trường hợp chung
            if ($app.UninstallString) {
                Write-Host "Đang gỡ: $($app.DisplayName)..."
                $uninstall_string = $app.UninstallString
                if ($uninstall_string -match "msiexec.exe") {
                    $arguments = $uninstall_string.Replace("msiexec.exe /I", "/x").Replace("/i", "/x") + " /qn"
                    Start-Process msiexec.exe -ArgumentList $arguments -Wait
                } else {
                    # Cố gắng thực hiện lệnh gỡ cài đặt với tham số im lặng (silent)
                    cmd.exe /c "$uninstall_string /S /q /qn --mode unattended"
                }
            }
        }
    } else {
        Write-Host "Không tìm thấy sản phẩm Autodesk nào để gỡ cài đặt." -ForegroundColor Green
    }
}

# Chạy trình gỡ cài đặt nhiều lần để xử lý các dependencies
Write-Host "--- Bắt đầu Bước 1: Gỡ cài đặt ứng dụng (có thể mất vài phút) ---" -ForegroundColor Cyan
$i = 0
for ($i = 1; $i -lt 4; $i++) {
    Write-Host "Chạy lần thứ $i..."
    Autodesk-Uninstaller
}


# ------ BƯỚC 2: DỪNG CÁC DỊCH VỤ CÒN SÓT LẠI ------
Write-Host "--- Bắt đầu Bước 2: Dừng các dịch vụ còn sót lại ---" -ForegroundColor Cyan
Get-Service -Name "*Adsk*", "*Autodesk*", "*FlexNet*" | Stop-Service -Force -ErrorAction SilentlyContinue
Write-Host "Đã dừng các dịch vụ liên quan."


# ------ BƯỚC 3: DỌN DẸP CÁC THƯ MỤC CÒN SÓT LẠI ------
Write-Host "--- Bắt đầu Bước 3: Xóa các thư mục còn sót lại ---" -ForegroundColor Cyan
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


# ------ BƯỚC 4: DỌN DẸP REGISTRY (Tùy chọn nhưng khuyến nghị) ------
Write-Host "--- Bắt đầu Bước 4: Xóa các khóa Registry ---" -ForegroundColor Cyan
try {
    Remove-Item -Path "HKCU:\Software\Autodesk" -Recurse -Force -ErrorAction Stop
    Write-Host "Đã xóa khóa Registry: HKCU:\Software\Autodesk" -ForegroundColor Green
} catch { Write-Host "Không tìm thấy khóa HKCU:\Software\Autodesk" -ForegroundColor Gray }
try {
    Remove-Item -Path "HKLM:\SOFTWARE\Autodesk" -Recurse -Force -ErrorAction Stop
    Write-Host "Đã xóa khóa Registry: HKLM:\SOFTWARE\Autodesk" -ForegroundColor Green
} catch { Write-Host "Không tìm thấy khóa HKLM:\SOFTWARE\Autodesk" -ForegroundColor Gray }


# ------ BƯỚC 5: HOÀN TẤT ------
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "QUÁ TRÌNH DỌN DẸP HOÀN TẤT!" -ForegroundColor Green
Write-Host "Vui lòng KHỞI ĐỘNG LẠI MÁY TÍNH để hoàn tất mọi thay đổi." -ForegroundColor Yellow
