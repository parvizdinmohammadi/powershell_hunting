import json
import pandas as pd
import re
from datetime import datetime
import os

class PowerShellHunting:
    def __init__(self, json_file_path, output_dir="output", start_date=None, end_date=None):
        self.json_file_path = json_file_path
        self.output_dir = output_dir
        self.start_date = start_date
        self.end_date = end_date
        self.suspicious_keywords = [
            "downloadstring", "invoke-expression", "downloadfile", 
            "webclient", "iex", "invoke-webrequest", "frombase64string", 
            "eval", "exec", "wget", "curl"
        ]
        self.logs = []
        self.suspicious_logs = []
        self.create_output_dir()
    
    def create_output_dir(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def load_logs(self):
        try:
            with open(self.json_file_path, 'r', encoding='utf-8-sig') as f:
                self.logs = json.load(f)
            print(f"✅ تعداد {len(self.logs)} لاگ از فایل {self.json_file_path} بارگذاری شد.")
            return True
        except FileNotFoundError:
            print(f"❌ فایل {self.json_file_path} پیدا نشد!")
            return False
        except json.JSONDecodeError as e:
            print(f"❌ خطا در فرمت JSON: {e}")
            return False
    
    def extract_field_from_properties(self, log, index, default="N/A"):
        """استخراج مقدار از Properties با هندل کردن خطا"""
        try:
            if 'Properties' in log and isinstance(log['Properties'], list):
                if index < len(log['Properties']):
                    prop = log['Properties'][index]
                    if isinstance(prop, dict) and 'Value' in prop:
                        return prop['Value']
            return default
        except:
            return default
    
    def extract_time(self, log):
        """استخراج زمان از لاگ"""
        try:
            # بررسی TimeCreated
            if 'TimeCreated' in log:
                if isinstance(log['TimeCreated'], dict):
                    return log['TimeCreated'].get('SystemTime', '')
                elif isinstance(log['TimeCreated'], str):
                    return log['TimeCreated']
            
            # بررسی مستقیم زمان
            if 'Time' in log:
                return log['Time']
            
            # بررسی در Properties
            if 'Properties' in log and isinstance(log['Properties'], list):
                for prop in log['Properties']:
                    if isinstance(prop, dict) and 'Value' in prop:
                        val = str(prop['Value'])
                        # الگوی زمان ISO
                        if re.match(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', val):
                            return val
            return ''
        except:
            return ''
    
    def extract_command(self, log):
        """استخراج دستور PowerShell از لاگ"""
        try:
            # جستجو در کل لاگ به صورت رشته
            log_str = json.dumps(log, ensure_ascii=False).lower()
            if 'powershell' not in log_str:
                return None
            
            # جستجو در Properties
            if 'Properties' in log and isinstance(log['Properties'], list):
                for prop in log['Properties']:
                    if isinstance(prop, dict) and 'Value' in prop:
                        val = str(prop['Value'])
                        if 'powershell' in val.lower():
                            return val
            
            # جستجو در Message
            if 'Message' in log:
                val = log['Message']
                if 'powershell' in val.lower():
                    return val
            
            return None
        except:
            return None
    
    def extract_computer_name(self, log):
        """استخراج نام کامپیوتر"""
        try:
            if 'ComputerName' in log:
                return log['ComputerName']
            if 'MachineName' in log:
                return log['MachineName']
            if 'Provider' in log and isinstance(log['Provider'], dict):
                return log['Provider'].get('Name', 'N/A')
            return 'N/A'
        except:
            return 'N/A'
    
    def extract_user(self, log):
        """استخراج نام کاربر"""
        try:
            # بررسی مستقیم
            if 'User' in log:
                return log['User']
            if 'UserId' in log:
                return log['UserId']
            
            # بررسی در Properties (TargetUserName معمولاً در index 5 است)
            user = self.extract_field_from_properties(log, 5, None)
            if user and user != 'N/A':
                return user
            
            return 'N/A'
        except:
            return 'N/A'
    
    def extract_ip(self, text):
        """استخراج آی‌پی از متن"""
        if not text:
            return None
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ips = re.findall(ip_pattern, text)
        return ips[0] if ips else None
    
    def extract_event_id(self, log):
        """استخراج Event ID"""
        try:
            if 'Id' in log:
                return log['Id']
            if 'EventID' in log:
                return log['EventID']
            return 'N/A'
        except:
            return 'N/A'
    
    def is_within_time_range(self, time_str):
        if not self.start_date or not self.end_date or not time_str:
            return True
        
        try:
            # پاکسازی زمان
            time_str = time_str.replace('Z', '')
            if 'T' in time_str:
                event_time = datetime.fromisoformat(time_str)
            else:
                event_time = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
            
            start = datetime.strptime(self.start_date, "%Y-%m-%d %H:%M:%S")
            end = datetime.strptime(self.end_date, "%Y-%m-%d %H:%M:%S")
            return start <= event_time <= end
        except:
            return True
    
    def analyze_powershell_command(self, command):
        if not command:
            return False, []
        
        command_lower = command.lower()
        found_keywords = []
        
        for keyword in self.suspicious_keywords:
            if keyword in command_lower:
                found_keywords.append(keyword)
        
        # بررسی الگوهای Base64
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        if re.search(base64_pattern, command):
            found_keywords.append("base64_encoded")
        
        # بررسی الگوهای Download
        download_pattern = r'http[s]?://[^\s"\']+'
        if re.search(download_pattern, command):
            found_keywords.append("url_download")
        
        return len(found_keywords) > 0, found_keywords
    
    def hunt(self):
        print("🔍 در حال تحلیل لاگ‌ها...")
        
        for log in self.logs:
            # استخراج زمان
            time_created = self.extract_time(log)
            
            # بررسی بازه زمانی
            if not self.is_within_time_range(time_created):
                continue
            
            # استخراج دستور
            command = self.extract_command(log)
            if not command:
                continue
            
            # تحلیل دستور
            is_suspicious, keywords = self.analyze_powershell_command(command)
            
            if is_suspicious:
                ip = self.extract_ip(command)
                user = self.extract_user(log)
                device = self.extract_computer_name(log)
                event_id = self.extract_event_id(log)
                
                self.suspicious_logs.append({
                    'time': time_created,
                    'device': device,
                    'user': user,
                    'command': command[:500] + "..." if len(command) > 500 else command,
                    'ip': ip if ip else 'N/A',
                    'keywords': ', '.join(keywords),
                    'event_id': event_id
                })
        
        print(f"🔍 تعداد {len(self.suspicious_logs)} لاگ مشکوک پیدا شد.")
        return self.suspicious_logs
    
    def save_results(self):
        if not self.suspicious_logs:
            print("⚠️ هیچ لاگ مشکوکی پیدا نشد.")
        
        # ذخیره JSON
        json_output = os.path.join(self.output_dir, "suspicious_logs.json")
        with open(json_output, 'w', encoding='utf-8-sig') as f:
            json.dump(self.suspicious_logs, f, indent=2, ensure_ascii=False)
        print(f"💾 نتایج در فایل JSON: {json_output} ذخیره شد.")
        
        # ذخیره Excel
        if self.suspicious_logs:
            df = pd.DataFrame(self.suspicious_logs)
            excel_output = os.path.join(self.output_dir, "suspicious_logs.xlsx")
            df.to_excel(excel_output, index=False, engine='openpyxl')
            print(f"📊 نتایج در فایل Excel: {excel_output} ذخیره شد.")
        else:
            print("⚠️ فایل Excel ایجاد نشد.")
    
    def print_summary(self):
        print("\n" + "="*80)
        print("🚨 فعالیت‌های مشکوک PowerShell پیدا شد:")
        print("="*80)
        
        if not self.suspicious_logs:
            print("✅ هیچ فعالیت مشکوکی پیدا نشد.")
            return
        
        for idx, log in enumerate(self.suspicious_logs, 1):
            print(f"\n📌 نتیجه #{idx}")
            print(f"   ⏰ زمان: {log['time']}")
            print(f"   💻 دستگاه: {log['device']}")
            print(f"   👤 کاربر: {log['user']}")
            print(f"   🏷️ Event ID: {log['event_id']}")
            print(f"   📝 دستور: {log['command']}")
            if log['ip'] != 'N/A':
                print(f"   🌐 IP خارجی: {log['ip']}")
            print(f"   🔑 کلمات کلیدی: {log['keywords']}")
            print("   " + "-"*70)


def main():
    json_file = "Data\\windows_logs.json"
    
    if not os.path.exists(json_file):
        print(f"❌ فایل {json_file} وجود ندارد!")
        print("💡 ابتدا اسکریپت extract_logs.ps1 را اجرا کنید.")
        return
    
    hunter = PowerShellHunting(
        json_file_path=json_file,
        output_dir="output"
    )
    
    if not hunter.load_logs():
        return
    
    hunter.hunt()
    hunter.save_results()
    hunter.print_summary()
    
    print("\n" + "="*50)
    print("✅ عملیات با موفقیت به پایان رسید!")
    print("="*50)


if __name__ == "__main__":
    main()