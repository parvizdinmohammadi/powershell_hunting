# extract_logs.ps1
# اسکریپت استخراج لاگ‌های ویندوز برای ابزار PowerShell Hunting

param(
    [int]$MaxEvents = 1000,
    [int]$HoursBack = 24,
    [string]$LogName = "Security",
    [string]$OutputPath = "Data\windows_logs.json"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   PowerShell Hunting - Log Extractor" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] شروع استخراج لاگ..." -ForegroundColor Yellow
Write-Host "[*] Log Name: $LogName" -ForegroundColor Gray
Write-Host "[*] Hours Back: $HoursBack" -ForegroundColor Gray
Write-Host "[*] Max Events: $MaxEvents" -ForegroundColor Gray

# محاسبه زمان شروع
$StartTime = (Get-Date).AddHours(-$HoursBack)

Write-Host "[*] از تاریخ: $StartTime" -ForegroundColor Gray

# استخراج رویدادها
try {
    $Events = Get-WinEvent -FilterHashtable @{
        LogName = $LogName
        StartTime = $StartTime
    } -MaxEvents $MaxEvents -ErrorAction Stop
    
    Write-Host "[+] تعداد رویدادهای استخراج شده: $($Events.Count)" -ForegroundColor Green
    
    if ($Events.Count -eq 0) {
        Write-Host "[!] هیچ رویدادی یافت نشد!" -ForegroundColor Red
        exit
    }
    
    # تبدیل به JSON با جزئیات کامل
    $EventsJson = $Events | ConvertTo-Json -Depth 10
    
    # ذخیره در فایل
    $FullPath = Join-Path -Path (Get-Location) -ChildPath $OutputPath
    $EventsJson | Out-File -FilePath $FullPath -Encoding utf8
    
    Write-Host "[+] فایل با موفقیت ذخیره شد: $FullPath" -ForegroundColor Green
    Write-Host "[+] حجم فایل: $([math]::Round((Get-Item $FullPath).Length / 1KB, 2)) KB" -ForegroundColor Gray
    
} catch {
    Write-Host "[!] خطا در استخراج لاگ: $_" -ForegroundColor Red
    Write-Host "[!] ممکن است نیاز به اجرا با دسترسی Administrator داشته باشید." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   فرآیند استخراج کامل شد!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan