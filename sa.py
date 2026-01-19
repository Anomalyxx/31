import winreg
import time
import random
import ctypes
import sys
import os
import hashlib
import platform
import subprocess
import uuid
import keyboard
from colorama import Fore, Style, init

init()

PROCESS_PER_MONITOR_DPI_AWARE = 2
VANGUARD_SERVICE_NAME = 'vgc'
VANGUARD_DRIVER_NAME = 'vgk'

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, ' '.join(sys.argv), None, 1)
    sys.exit()

def log(msg, color=Fore.BLUE, prefix="[*]"):
    print(f'{color}{prefix} {msg}{Style.RESET_ALL}')

def safe_reg_operation(func, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except Exception:
        return None

def set_reg_value(key_root, key_path, value_name, value_type, value):
    try:
        key = winreg.CreateKey(key_root, key_path)
        winreg.SetValueEx(key, value_name, 0, value_type, value)
        winreg.CloseKey(key)
        return True
    except:
        return False

def block_vanguard_communication():
    try:
        domains = ['vgc-test.rgp.io', 'vgc.rgp.io', 'riot-anti-cheat.trusteer.riot-games.com', 'valorant-win.secure.dyn.riotcdn.net']
        hosts_path = os.path.join(os.environ['SYSTEMROOT'], 'System32', 'drivers', 'etc', 'hosts')
        
        with open(hosts_path, 'r') as f:
            content = f.read()
            
        new_content = content
        needs_update = False
        
        for domain in domains:
            if domain not in content:
                new_content += f'\n127.0.0.1 {domain}'
                needs_update = True
                
        if needs_update:
            with open(hosts_path, 'w') as f:
                f.write(new_content)
    except:
        pass

def fix_vanguard_services():
    try:
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\vgk', 'Start', winreg.REG_DWORD, 1)
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\vgk', 'ErrorControl', winreg.REG_DWORD, 1)
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\vgk', 'Type', winreg.REG_DWORD, 1) # SERVICE_KERNEL_DRIVER
        
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\vgc', 'Start', winreg.REG_DWORD, 2)
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\vgc', 'ErrorControl', winreg.REG_DWORD, 1)
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\vgc', 'Type', winreg.REG_DWORD, 16) # SERVICE_WIN32_OWN_PROCESS
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\vgc', 'DependOnService', winreg.REG_MULTI_SZ, ['vgk'])
        
        subprocess.run(['sc', 'stop', 'vgk'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['sc', 'stop', 'vgc'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        subprocess.run(['sc', 'start', 'vgk'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        subprocess.run(['sc', 'start', 'vgc'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except:
        pass

def repair_vanguard_files():
    try:
        vng_path = r'C:\Program Files\Riot Vanguard'
        if os.path.exists(vng_path):
            subprocess.run(['icacls', vng_path, '/grant', 'SYSTEM:(OI)(CI)F', '/T'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['icacls', vng_path, '/grant', 'Administrators:(OI)(CI)F', '/T'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
        cmds = [
            f'netsh advfirewall firewall add rule name="VanguardService" dir=in action=allow program="{vng_path}\\vgc.exe" enable=yes',
            f'netsh advfirewall firewall add rule name="VanguardKernel" dir=in action=allow program="{vng_path}\\vgk.sys" enable=yes'
        ]
        for cmd in cmds:
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Riot Games\Valorant', 'AntiCheatEnabled', winreg.REG_DWORD, 1)
    except:
        pass

def spoof_hardware_ids():
    try:
        paths = [r'SYSTEM\CurrentControlSet\Enum\PCI', r'SYSTEM\CurrentControlSet\Enum\USB']
        for path in paths:
            try:
                base_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ)
                for i in range(winreg.QueryInfoKey(base_key)[0]):
                    subkey_name = winreg.EnumKey(base_key, i)
                    try:
                        subkey = winreg.OpenKey(base_key, subkey_name, 0, winreg.KEY_READ)
                        for j in range(winreg.QueryInfoKey(subkey)[0]):
                            device_id = winreg.EnumKey(subkey, j)
                            device_path = f'{path}\\{subkey_name}\\{device_id}'
                            
                            try:
                                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, device_path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as dev_key:
                                    hwid = winreg.QueryValueEx(dev_key, 'HardwareID')[0]
                                    if not isinstance(hwid, list): hwid = [hwid]
                                    
                                    orig_hwid = hwid[0] if hwid else ''
                                    if ('VID_' in orig_hwid or 'VEN_' in orig_hwid) and random.random() < 0.2:
                                        new_hwid_list = hwid.copy()
                                        if '&REV' in orig_hwid:
                                            # Simple REV increment
                                            parts = orig_hwid.split('&REV')
                                            if len(parts) > 1:
                                                rev_val = parts[1].split('&')[0]
                                                new_rev = hex(int(rev_val, 16) + random.randint(1, 4))[2:].upper()
                                                new_hwid = f"{parts[0]}&REV{new_rev}&{(parts[1].split('&', 1)[1] if '&' in parts[1] else '')}"
                                                new_hwid_list.insert(0, new_hwid)
                                                
                                        winreg.SetValueEx(dev_key, 'HardwareID', 0, winreg.REG_MULTI_SZ, new_hwid_list)
                            except:
                                continue
                    except:
                        continue
            except:
                continue
    except:
        pass

def spoof_smbios_data():
    try:
        log('Anakart bilgileri guncelleniyor...', Fore.YELLOW)
        key_path = r'SYSTEM\CurrentControlSet\Services\mssmbios\Data'
        
        uuid_bytes = bytearray(os.urandom(16))
        uuid_bytes[6] = uuid_bytes[6] & 0x0f | 0x40 
        uuid_bytes[8] = uuid_bytes[8] & 0x3f | 0x80
        
        manufacturers = ['ASUSTeK COMPUTER INC.', 'MICRO-STAR INTERNATIONAL CO., LTD', 'GIGABYTE TECHNOLOGY CO., LTD.', 'ASRock Inc.', 'Dell Inc.']
        models = ['ROG STRIX B550-F GAMING', 'MPG B550 GAMING PLUS', 'B550 AORUS ELITE', 'PRO Z690-A']
        
        new_uuid = str(uuid.UUID(bytes=bytes(uuid_bytes)))
        
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, key_path, 'SMBiosData', winreg.REG_BINARY, bytes(uuid_bytes))
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, key_path, 'SystemManufacturer', winreg.REG_SZ, random.choice(manufacturers))
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, key_path, 'SystemProductName', winreg.REG_SZ, random.choice(models))
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, key_path, 'SystemSerialNumber', winreg.REG_SZ, ''.join(random.choices('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=12)))
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, key_path, 'SystemUUID', winreg.REG_SZ, new_uuid)
        
        subprocess.run(['wmic', 'csproduct', 'set', f'UUID={new_uuid}'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        log(f'Anakart hatasi: {e}', Fore.RED)

def spoof_tpm_presence():
    try:
        log('TPM simulator calistiriliyor...', Fore.YELLOW)
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\IntegrityServices', 'TPMEnabled', winreg.REG_DWORD, 1)
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\IntegrityServices', 'TPMReady', winreg.REG_DWORD, 1)
        
        tpm_keys = [r'SYSTEM\CurrentControlSet\Control\Tpm\12', r'SYSTEM\CurrentControlSet\Control\Tpm\20']
        for key in tpm_keys:
            set_reg_value(winreg.HKEY_LOCAL_MACHINE, key, 'Active', winreg.REG_DWORD, 1)
            set_reg_value(winreg.HKEY_LOCAL_MACHINE, key, 'Enabled', winreg.REG_DWORD, 1)
            set_reg_value(winreg.HKEY_LOCAL_MACHINE, key, 'Owned', winreg.REG_DWORD, 1)
            
        tpm_device_path = r'SYSTEM\CurrentControlSet\Enum\ACPI\TPM2.0\0'
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, tpm_device_path, 'DeviceDesc', winreg.REG_SZ, 'Trusted Platform Module 2.0')
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, tpm_device_path, 'Mfg', winreg.REG_SZ, 'Microsoft')
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, tpm_device_path, 'HardwareID', winreg.REG_MULTI_SZ, ['ACPI\\TPM2.0'])
    except:
        pass

def fix_riot_mcp_connection():
    try:
        tasks = subprocess.check_output('tasklist', shell=True).decode('utf-8', errors='ignore')
        if 'RiotClientServices.exe' in tasks:
            os.system('taskkill /f /im RiotClientServices.exe >nul 2>&1')
            time.sleep(1)
            
        mcp_key = r'SOFTWARE\Riot Games\Valorant\MCP'
        subprocess.run(f'reg delete "HKLM\\{mcp_key}" /f', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        
        ver_id = str(uuid.uuid4()).upper()
        salt = os.urandom(16).hex().upper()
        hwid = hashlib.md5(os.urandom(32)).hexdigest().upper()
        
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, mcp_key, 'VerificationId', winreg.REG_SZ, ver_id)
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, mcp_key, 'Salt', winreg.REG_SZ, salt)
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, mcp_key, 'HardwareId', winreg.REG_SZ, hwid)
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, mcp_key, 'VerificationStatus', winreg.REG_DWORD, 1)
        
        return True
    except:
        return False

def disable_hvci():
    try:
        log('HVCI kontrolleri devre disi birakiliyor...', Fore.CYAN)
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Riot Games\Vanguard', 'HVCIEnforcement', winreg.REG_DWORD, 0)
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\DeviceGuard', 'EnableVirtualizationBasedSecurity', winreg.REG_DWORD, 0)
        set_reg_value(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity', 'Enabled', winreg.REG_DWORD, 0)
    except:
        pass

def clean_traces():
    try:
        log('Gecici dosyalar temizleniyor...', Fore.YELLOW)
        temp = os.environ.get('TEMP')
        if temp and os.path.exists(temp):
            for f in os.listdir(temp):
                if f.endswith('.tmp') or f.startswith('~'):
                    try: os.remove(os.path.join(temp, f))
                    except: pass
                    
        paths = [
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'VALORANT'),
            os.path.join(os.environ.get('PROGRAMDATA', ''), 'Riot Games'),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Riot Games')
        ]
        
        for p in paths:
            if os.path.exists(p):
                for root, dirs, files in os.walk(p):
                    for file in files:
                        if file.endswith('.log'):
                            try:
                                with open(os.path.join(root, file), 'w') as f: f.write('')
                            except: pass
    except:
        pass

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f'{Fore.CYAN}{"="*60}{Style.RESET_ALL}')
    print(f'{Fore.CYAN}{Style.BRIGHT}{Fore.WHITE}                 VALORANT OPTIMIZED BYPASS                 {Style.RESET_ALL}{Fore.CYAN}{Style.RESET_ALL}')
    print(f'{Fore.CYAN}{"="*60}{Style.RESET_ALL}')
    print(f'{Fore.WHITE}>> {Fore.YELLOW}Version: {Fore.GREEN}2.2.0-Optimized{Style.RESET_ALL}')
    print(f'{Fore.WHITE}>> {Fore.YELLOW}System: {Fore.GREEN}{platform.system()}{Style.RESET_ALL}\n')
    
    print(f'{Fore.YELLOW}[*] Islem baslatiliyor...{Style.RESET_ALL}')
    
    steps = [
        ('Hosts Dosyasi Duzenleniyor', block_vanguard_communication),
        ('Servisler Onariliyor', fix_vanguard_services),
        ('Dosya Izinleri Onariliyor', repair_vanguard_files),
        ('HWID Spoof Islemi', spoof_hardware_ids),
        ('Anakart (SMBIOS) Spoof', spoof_smbios_data),
        ('TPM Bypass', spoof_tpm_presence),
        ('MCP Baglantisi Onarimi', fix_riot_mcp_connection),
        ('HVCI Kapatiliyor', disable_hvci),
        ('Izler Temizleniyor', clean_traces)
    ]
    
    for desc, func in steps:
        print(f'\n{Fore.BLUE}[*] {desc}...{Style.RESET_ALL}')
        func()
        time.sleep(0.2)
        
    print(f'\n{Fore.CYAN}{"="*60}{Style.RESET_ALL}')
    print(f'{Fore.GREEN}[OK] Tum islemler basariyla tamamlandi.{Style.RESET_ALL}')
    print(f'{Fore.YELLOW}[!] Degisikliklerin aktif olmasi icin bilgisayari yeniden baslatin.{Style.RESET_ALL}')
    
    while True:
        print(f'\n{Fore.CYAN}[1] Yeniden Baslat')
        print(f'[2] Cikis{Style.RESET_ALL}')
        choice = input(f'{Fore.GREEN}Seciminiz: {Style.RESET_ALL}')
        
        if choice == '1':
            os.system('shutdown /r /t 5')
            break
        elif choice == '2':
            break

if __name__ == '__main__':
    main()