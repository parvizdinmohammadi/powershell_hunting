# -*- coding: utf-8 -*-
"""
ابزار شناسایی فعالیت‌های مشکوک PowerShell در لاگ‌ها
با قابلیت خروجی Excel
معادل کوئری KQL در KC7
"""

import json
import os
from datetime import datetime
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

# ============ بخش تنظیمات ============
INPUT_FILE_PATH = r"C:\Users\Lenovo\Desktop\powershell_hunting\data\logs.json"
OUTPUT_FILE_PATH = r"C:\Users\Lenovo\Desktop\powershell_hunting\output\suspicious_logs.json"
EXCEL_FILE_PATH = r"C:\Users\Lenovo\Desktop\powershell_hunting\output\suspicious_logs.xlsx"

START_TIME = "2026-09-01 08:00:00"
END_TIME = "2026-09-01 12:00:00"

SUSPICIOUS_KEYWORDS = [
    "downloadstring",
    "invoke-expression",
    "downloadfile",
    "webclient",
    "iex",
    "invoke-webrequest"
]
# =====================================


# ============ تابع 1: بارگذاری لاگ‌ها ============
def load_logs(file_path):
    """
    لاگ‌ها را از فایل JSON بارگذاری می‌کند.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"❌ فایل {file_path} پیدا نشد!")
    
    with open(file_path, 'r', encoding='utf-8') as file:
        logs = json.load(file)
    
    print(f"✅ تعداد {len(logs)} لاگ از فایل {file_path} بارگذاری شد.")
    return logs


# ============ تابع 2: فیلتر کردن لاگ‌ها ============
def filter_suspicious_powershell(logs, start_time, end_time, keywords):
    """
    لاگ‌های مشکوک PowerShell را پیدا می‌کند.
    """
    start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
    end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
    
    suspicious_logs = []
    
    for log in logs:
        # شرط 1: بازه زمانی
        log_dt = datetime.strptime(log["Timestamp"], "%Y-%m-%d %H:%M:%S")
        if not (start_dt <= log_dt <= end_dt):
            continue
        
        # شرط 2: نام فایل شامل powershell باشد
        if "powershell" not in log["FileName"].lower():
            continue
        
        # شرط 3: دستور شامل کلمات کلیدی باشد
        command_lower = log["ProcessCommandLine"].lower()
        if not any(keyword in command_lower for keyword in keywords):
            continue
        
        suspicious_logs.append(log)
    
    # مرتب‌سازی بر اساس زمان (جدیدترین اول)
    suspicious_logs.sort(key=lambda x: x["Timestamp"], reverse=True)
    
    print(f"🔍 تعداد {len(suspicious_logs)} لاگ مشکوک پیدا شد.")
    return suspicious_logs


# ============ تابع 3: نمایش نتایج در ترمینال ============
def display_results(logs):
    """
    نتایج را در ترمینال نمایش می‌دهد.
    """
    print("\n" + "=" * 80)
    print("🚨 فعالیت‌های مشکوک PowerShell پیدا شد:")
    print("=" * 80)
    
    if not logs:
        print("❌ هیچ لاگ مشکوکی پیدا نشد.")
        return
    
    counter = 1
    for log in logs:
        print(f"\n📌 نتیجه #{counter}")
        print(f"   ⏰ زمان: {log['Timestamp']}")
        print(f"   💻 دستگاه: {log['DeviceName']}")
        print(f"   👤 کاربر: {log['AccountName']}")
        
        command = log['ProcessCommandLine']
        if len(command) > 100:
            command = command[:100] + "..."
        print(f"   📝 دستور: {command}")
        
        print(f"   🌐 IP خارجی: {log['RemoteIP']}")
        print("   " + "-" * 70)
        counter += 1


# ============ تابع 4: ذخیره نتایج در JSON ============
def save_results_json(logs, file_path):
    """
    نتایج را در فایل JSON ذخیره می‌کند.
    """
    output_dir = os.path.dirname(file_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    with open(file_path, 'w', encoding='utf-8') as file:
        json.dump(logs, file, indent=2, ensure_ascii=False)
    
    print(f"💾 نتایج در فایل JSON: {file_path} ذخیره شد.")


# ============ تابع 5: ذخیره نتایج در Excel (نسخه اصلاح شده) ============
def save_results_excel(logs, file_path):
    """
    نتایج را در فایل Excel با قالب‌بندی زیبا ذخیره می‌کند.
    """
    # ایجاد کتاب کار جدید
    wb = Workbook()
    ws = wb.active
    ws.title = "PowerShell Hunting Results"
    
    # ===== تعریف استایل‌ها =====
    # فونت عنوان (Header)
    header_font = Font(name='B Nazanin', size=12, bold=True, color="FFFFFF")
    header_fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
    header_alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    
    # فونت داده‌ها
    data_font = Font(name='B Nazanin', size=10)
    data_alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
    
    # حاشیه
    thin_border = Border(
        left=Side(style='thin'),
        right=Side(style='thin'),
        top=Side(style='thin'),
        bottom=Side(style='thin')
    )
    
    # ===== نوشتن عنوان ستون‌ها =====
    headers = ["ردیف", "زمان", "دستگاه", "کاربر", "دستور کامل", "فرایند والد", "IP خارجی", "وضعیت"]
    for col, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=header)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = header_alignment
        cell.border = thin_border
    
    # ===== نوشتن داده‌ها =====
    for row_idx, log in enumerate(logs, 2):
        # ستون 1: ردیف
        cell = ws.cell(row=row_idx, column=1, value=row_idx - 1)
        cell.font = data_font
        cell.alignment = Alignment(horizontal="center", vertical="center")
        cell.border = thin_border
        
        # ستون 2: زمان
        cell = ws.cell(row=row_idx, column=2, value=log['Timestamp'])
        cell.font = data_font
        cell.alignment = data_alignment
        cell.border = thin_border
        
        # ستون 3: دستگاه
        cell = ws.cell(row=row_idx, column=3, value=log['DeviceName'])
        cell.font = data_font
        cell.alignment = data_alignment
        cell.border = thin_border
        
        # ستون 4: کاربر
        cell = ws.cell(row=row_idx, column=4, value=log['AccountName'])
        cell.font = data_font
        cell.alignment = data_alignment
        cell.border = thin_border
        
        # ستون 5: دستور کامل
        cell = ws.cell(row=row_idx, column=5, value=log['ProcessCommandLine'])
        cell.font = data_font
        cell.alignment = data_alignment
        cell.border = thin_border
        
        # ستون 6: فرایند والد
        cell = ws.cell(row=row_idx, column=6, value=log.get('InitiatingProcessCommandLine', 'نامشخص'))
        cell.font = data_font
        cell.alignment = data_alignment
        cell.border = thin_border
        
        # ستون 7: IP خارجی
        cell = ws.cell(row=row_idx, column=7, value=log['RemoteIP'])
        cell.font = data_font
        cell.alignment = data_alignment
        cell.border = thin_border
        
        # ستون 8: وضعیت (بر اساس IP)
        if log['RemoteIP'] != "-":
            status = "⚠️ مشکوک (IP خارجی)"
            fill = PatternFill(start_color="FFC000", end_color="FFC000", fill_type="solid")
        else:
            status = "✅ نیاز به بررسی بیشتر"
            fill = PatternFill(start_color="92D050", end_color="92D050", fill_type="solid")
        
        cell = ws.cell(row=row_idx, column=8, value=status)
        cell.font = data_font
        cell.alignment = Alignment(horizontal="center", vertical="center")
        cell.fill = fill
        cell.border = thin_border
    
    # ===== تنظیم عرض ستون‌ها =====
    ws.column_dimensions['A'].width = 8   # ردیف
    ws.column_dimensions['B'].width = 22  # زمان
    ws.column_dimensions['C'].width = 18  # دستگاه
    ws.column_dimensions['D'].width = 18  # کاربر
    ws.column_dimensions['E'].width = 80  # دستور کامل
    ws.column_dimensions['F'].width = 40  # فرایند والد
    ws.column_dimensions['G'].width = 18  # IP خارجی
    ws.column_dimensions['H'].width = 25  # وضعیت
    
    # ===== تنظیم ارتفاع ردیف‌ها =====
    ws.row_dimensions[1].height = 30  # ارتفاع سطر عنوان
    
    # ===== اضافه کردن فیلتر =====
    ws.auto_filter.ref = ws.dimensions
    
    # ===== اضافه کردن هدر و فوتر (نسخه اصلاح شده) =====
    try:
        # در نسخه‌های جدید openpyxl، فوتر به این شکل تنظیم می‌شود
        ws.header_footer.center_footer.text = "تولید شده توسط ابزار شناسایی PowerShell"
        ws.header_footer.right_footer.text = "Page &P"
    except AttributeError:
        # اگر نسخه قدیمی است، این روش را امتحان کن
        try:
            ws.footer.center.text = "تولید شده توسط ابزار شناسایی PowerShell"
            ws.footer.right.text = "Page &P"
        except:
            pass  # اگر هیچکدام کار نکرد، نادیده بگیر
    
    # ===== ذخیره فایل =====
    output_dir = os.path.dirname(file_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    wb.save(file_path)
    print(f"📊 نتایج در فایل Excel: {file_path} ذخیره شد.")


# ============ تابع اصلی ============
def main():
    """
    تابع اصلی که همه چیز را اجرا می‌کند.
    """
    print("🛡️  ابزار شناسایی PowerShell مخرب")
    print("=" * 50)
    print(f"📂 فایل ورودی: {INPUT_FILE_PATH}")
    print(f"📂 فایل خروجی JSON: {OUTPUT_FILE_PATH}")
    print(f"📊 فایل خروجی Excel: {EXCEL_FILE_PATH}")
    print(f"⏰ بازه زمانی: {START_TIME} تا {END_TIME}")
    print(f"🔑 کلمات کلیدی: {', '.join(SUSPICIOUS_KEYWORDS)}")
    print("=" * 50 + "\n")
    
    try:
        # مرحله 1: بارگذاری لاگ‌ها
        logs = load_logs(INPUT_FILE_PATH)
        
        # مرحله 2: فیلتر کردن لاگ‌های مشکوک
        suspicious = filter_suspicious_powershell(logs, START_TIME, END_TIME, SUSPICIOUS_KEYWORDS)
        
        # مرحله 3: نمایش نتایج در ترمینال
        display_results(suspicious)
        
        # مرحله 4: ذخیره نتایج در JSON
        save_results_json(suspicious, OUTPUT_FILE_PATH)
        
        # مرحله 5: ذخیره نتایج در Excel
        save_results_excel(suspicious, EXCEL_FILE_PATH)
        
        print("\n" + "=" * 50)
        print("✅ عملیات با موفقیت به پایان رسید!")
        print(f"📊 فایل Excel را در مسیر زیر باز کنید:")
        print(f"   {EXCEL_FILE_PATH}")
        print("=" * 50)
        
    except FileNotFoundError as e:
        print(f"\n❌ خطا: {e}")
    except json.JSONDecodeError as e:
        print(f"\n❌ خطا در فرمت JSON: {e}")
    except KeyError as e:
        print(f"\n❌ خطا: کلید {e} در لاگ‌ها وجود ندارد.")
    except Exception as e:
        print(f"\n❌ خطا: {e}")


# ============================================================
if __name__ == "__main__":
    main()