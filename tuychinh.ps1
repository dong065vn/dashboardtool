# --- CẤU HÌNH MỚI (LINK KHÔNG DẤU CÁCH) ---
$u = "https://github.com/dong065vn/dashboardtool/raw/refs/heads/main/Tuy%20chinh%20Windows/tuychinh.exe"
$f = "$env:TEMP\tuychinh.exe"

Write-Host "Dang tai file tu folder 'tuychinh'..." -ForegroundColor Cyan

try {
    # 1. Tải file về (Link sạch nên tải sẽ rất mượt)
    Invoke-WebRequest -Uri $u -OutFile $f -ErrorAction Stop
    
    # 2. BƯỚC QUAN TRỌNG: Gỡ bỏ nhãn "File lạ từ Internet" để Windows bớt nghi ngờ
    if (Test-Path $f) {
        Unblock-File -Path $f
    }

    # 3. Chạy file
    Write-Host "-> Tai xong! Dang khoi dong..." -ForegroundColor Green
    Start-Process -FilePath $f
}
catch {
    Write-Host "LOI: $_" -ForegroundColor Red
    Write-Host "Luu y: Neu loi la 'contains a virus', anh can tat tam thoi Windows Defender hoac them file vao danh sach loai tru (Exclusion)." -ForegroundColor Yellow
}