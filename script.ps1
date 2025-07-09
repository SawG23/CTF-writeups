function Uninstall-Inventor2024 {

    Clear-Host

    # Lấy tất cả ứng dụng Autodesk đã cài đặt từ Registry
    $apps = @()
    $apps += Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $apps += Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"

    # Lọc riêng Autodesk Inventor 2024
    $inventorApp = $apps | Where-Object {
        ($_.DisplayName -match "Inventor") -and ($_.DisplayName -match "2024")
    } | Select-Object DisplayName, Publisher, PSChildName, UninstallString -Unique

    if ($null -eq $inventorApp) {
        Write-Host "Không tìm thấy Autodesk Inventor 2024 trong hệ thống." -ForegroundColor Red
        return
    }

    Write-Host "Tìm thấy ứng dụng: $($inventorApp.DisplayName)" -ForegroundColor Yellow

    if ($inventorApp.UninstallString -like "*installer.exe*") {
        Write-Host "Gỡ cài đặt bằng ODIS Installer..." -ForegroundColor Yellow
        Start-Process -FilePath "C:\Program Files\Autodesk\AdODIS\V1\Installer.exe" `
            -ArgumentList "-q -i uninstall --trigger_point system -m C:\ProgramData\Autodesk\ODIS\metadata\$($inventorApp.PSChildName)\bundleManifest.xml -x C:\ProgramData\Autodesk\ODIS\metadata\$($inventorApp.PSChildName)\SetupRes\manifest.xsd" `
            -NoNewWindow -Wait
    }
    else {
        Write-Host "Gỡ cài đặt bằng mã sản phẩm MSI..." -ForegroundColor Yellow
        Start-Process -FilePath msiexec.exe `
            -ArgumentList "/x `"$($inventorApp.PSChildName)`" /qn" `
            -NoNewWindow -Wait
    }

    Write-Host "Hoàn tất gỡ cài đặt Autodesk Inventor 2024." -ForegroundColor Green
}

Uninstall-Inventor2024