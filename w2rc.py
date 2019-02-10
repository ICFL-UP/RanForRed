import tkinter
from tkinter import messagebox
import tkinter.filedialog as fd
import signal
import subprocess
import hashlib
import os
import sys
import ctypes
import winreg
import psutil
import datetime
import pickle
import logging
import datetime as dt

import json
import requests
import getpass

import threading
import time
from tkinter import *
from tkinter import ttk


# Winlogbear
CMD                   = r"C:\Windows\System32\cmd.exe"
FOD_HELPER            = r'C:\Windows\System32\fodhelper.exe'
PYTHON_CMD            = "F:\DigiForS\\venv\Scripts\python.exe"
REG_PATH              = 'Software\Classes\ms-settings\shell\open\command'
DELEGATE_EXEC_REG_KEY = 'DelegateExecute'
CWD                   = r'F:\UP_2017_CS_M_Y1\DF-Research\M\Tool\W2RC\\'
WHITELIST_DB_PATH     = r'F:\UP_2017_CS_M_Y1\DF-Research\M\Tool\W2RC\whitelist.db'
WHITELIST_DB          = []
SEEN_DB_PATH          = r'F:\UP_2017_CS_M_Y1\DF-Research\M\Tool\W2RC\seen.db'
SEEN_DB               = []
FAILED_DB_PATH        = r'F:\UP_2017_CS_M_Y1\DF-Research\M\Tool\W2RC\failed.db'
FAILED_DB             = []
BLACKLIST_DB_PATH     = r'F:\UP_2017_CS_M_Y1\DF-Research\M\Tool\W2RC\blacklist.db'
BLACKLIST_DB          = []
OWNER_ID              = "ASINGH"
HEADERS               = {"Authorization": "Bearer S4MPL3"}
# IP                    = "http://192.168.1.127:8090"
IP                    = "http://192.168.137.181:8090"
CONFIG                = {"user": getpass.getuser(), "ip": "192.168.1.122"}


date = dt.datetime.now()
logfile = str(date)[0:10]
logging.basicConfig(filename=CWD+'log\\' + logfile + '.log', level=logging.DEBUG)

log = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(ip)s - %(user)-8s [%(levelname)s] --> %(message)s',
                              datefmt='%d/%m/%Y %I:%M:%S')
handler.setFormatter(formatter)
log.addHandler(handler)
log.setLevel(logging.INFO)
log = logging.LoggerAdapter(log, CONFIG)

log.info('W2RC Started', extra=CONFIG)
w2rc = ""


def welcome():
    global w2rc
    w2rc = "\n\n=======================================================\n" + \
            "\t  ██╗    ██╗██████╗ ██████╗  ██████╗\n" + \
            "\t  ██║    ██║╚════██╗██╔══██╗██╔════╝\n" + \
            "\t  ██║ █╗ ██║ █████╔╝██████╔╝██║\n" + \
            "\t  ██║███╗██║██╔═══╝ ██╔══██╗██║\n" + \
            "\t  ╚███╔███╔╝███████╗██║  ██║╚██████╗\n" + \
            "\t   ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝\n" + \
            "\n\t  Windows Registry and RAM Collector\n\t\t\t\t     -BY AVINASH SINGH" + \
            "\n=======================================================\n"
    print(w2rc)
    print("\nMonitor now running press <CTRL> C twice to stop monitoring safely.\n\n")

    # log.error('[RegSmart] An error occurred', exc_info=True, extra=CONFIG)


def is_running_as_admin():
    '''
    Checks if the script is running with administrative privileges.
    Returns True if is running as admin, False otherwise.
    '''
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def create_reg_key(key, value):
    '''
    Creates a reg key
    '''
    try:
        winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_PATH)
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(registry_key, key, 0, winreg.REG_SZ, value)
        winreg.CloseKey(registry_key)
    except WindowsError:
        raise


def bypass_uac(cmd):
    '''
    Tries to bypass the UAC
    '''
    try:
        create_reg_key(DELEGATE_EXEC_REG_KEY, '')
        create_reg_key(None, cmd)
    except WindowsError:
        raise


def gen_safe_db():
    procList = psutil.pids()
    failed = 0
    global WHITELIST_DB
    WHITELIST_DB = []

    for ps in procList:
        try:
            p = psutil.Process(ps)
            entry = {'pid': ps, 'name': p.name(), 'md5': md5(p.exe()), 'time': str(datetime.datetime.now()),
                     'exe': p.exe()}
            WHITELIST_DB.append(entry)
        except Exception as e:
            failed += 1
    with open(WHITELIST_DB_PATH, 'wb') as f:
        pickle.dump(WHITELIST_DB, f, pickle.HIGHEST_PROTOCOL)

    log.info("Successfully created whitelist database", extra=CONFIG)
    log.info(str(len(WHITELIST_DB)) + " entries were added successfully.", extra=CONFIG)


def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def load_safe_db():
    global WHITELIST_DB
    global FAILED_DB
    global SEEN_DB
    global BLACKLIST_DB
    global HASHLIST

    dblist = ["WHITELIST", "FAILED", "BLACKLIST", "SEEN"]

    if os.path.exists(WHITELIST_DB_PATH) and os.path.getsize(WHITELIST_DB_PATH) > 0:
        HASHLIST["WHITELIST"].set(md5(WHITELIST_DB_PATH))
        with open(WHITELIST_DB_PATH, 'rb') as f:
            WHITELIST_DB = pickle.load(f)
    else:
        with open(WHITELIST_DB_PATH, 'wb') as f:
            pickle.dump(WHITELIST_DB, f, pickle.HIGHEST_PROTOCOL)
        HASHLIST["WHITELIST"].set(md5(WHITELIST_DB_PATH))

    if os.path.exists(FAILED_DB_PATH):
        HASHLIST["FAILED"].set(md5(FAILED_DB_PATH))
        with open(FAILED_DB_PATH, 'rb') as f:
            FAILED_DB = pickle.load(f)
    else:
        with open(FAILED_DB_PATH, 'wb') as f:
            pickle.dump(FAILED_DB, f, pickle.HIGHEST_PROTOCOL)
        HASHLIST["FAILED"].set(md5(FAILED_DB_PATH))

    if os.path.exists(BLACKLIST_DB_PATH):
        HASHLIST["BLACKLIST"].set(md5(BLACKLIST_DB_PATH))
        with open(BLACKLIST_DB_PATH, 'rb') as f:
            BLACKLIST_DB = pickle.load(f)
    else:
        with open(BLACKLIST_DB_PATH, 'wb') as f:
            pickle.dump(BLACKLIST_DB, f, pickle.HIGHEST_PROTOCOL)
        HASHLIST["BLACKLIST"].set(md5(BLACKLIST_DB_PATH))

    if os.path.exists(SEEN_DB_PATH):
        HASHLIST["SEEN"].set(md5(SEEN_DB_PATH))
        with open(SEEN_DB_PATH, 'rb') as f:
            SEEN_DB = pickle.load(f)
    else:
        with open(SEEN_DB_PATH, 'wb') as f:
            pickle.dump(SEEN_DB, f, pickle.HIGHEST_PROTOCOL)
        HASHLIST["SEEN"].set(md5(SEEN_DB_PATH))

    print("Successfully loaded WHITELIST_DB database (" + WHITELIST_DB_PATH + ") with (" + str(
        len(WHITELIST_DB)) + ") entries and MD5 hash ["+HASHLIST["WHITELIST"].get()+"].")
    print("Successfully loaded FAILED_DB database (" + FAILED_DB_PATH + ") with (" + str(
        len(FAILED_DB)) + ") entries and MD5 hash ["+HASHLIST["FAILED"].get()+"].")
    print("Successfully loaded BLACKLIST_DB database (" + BLACKLIST_DB_PATH + ") with (" + str(
        len(BLACKLIST_DB)) + ") entries and MD5 hash ["+HASHLIST["BLACKLIST"].get()+"].")
    print("Successfully loaded SEEN_DB database (" + SEEN_DB_PATH + ") with (" + str(
        len(SEEN_DB)) + ") entries and MD5 hash ["+HASHLIST["SEEN"].get()+"].")

    log.debug(dblist, extra=CONFIG)
    log.debug(HASHLIST, extra=CONFIG)
    log.info("Successfully loaded databases", extra=CONFIG)


def update_state():
    global BLACKLIST_DB, SEEN_DB, FAILED_DB, HASHLIST

    with open(BLACKLIST_DB_PATH, 'wb') as f:
        pickle.dump(BLACKLIST_DB, f, pickle.HIGHEST_PROTOCOL)
    with open(SEEN_DB_PATH, 'wb') as f:
        pickle.dump(SEEN_DB, f, pickle.HIGHEST_PROTOCOL)
    with open(FAILED_DB_PATH, 'wb') as f:
        pickle.dump(FAILED_DB, f, pickle.HIGHEST_PROTOCOL)
    with open(WHITELIST_DB_PATH, 'wb') as f:
        pickle.dump(WHITELIST_DB, f, pickle.HIGHEST_PROTOCOL)

    HASHLIST["BLACKLIST"].set(md5(BLACKLIST_DB_PATH))
    HASHLIST["WHITELIST"].set(md5(WHITELIST_DB_PATH))
    HASHLIST["SEEN"].set(md5(SEEN_DB_PATH))
    HASHLIST["FAILED"].set(md5(FAILED_DB_PATH))


def monitor():
    failed = 0
    path_list = []

    global WHITELIST_DB
    global FAILED_DB
    global SEEN_DB
    global BLACKLIST_DB

    while True:
        for p in psutil.process_iter():
            try:
                if not any(d['name'] == p.name() for d in FAILED_DB):
                    entry = {'pid': p.pid, 'name': p.name(), 'hash': p.__hash__(), 'time': datetime.datetime.now(),
                             'exe': p.exe()}

                    if any(d['hash'] == entry['hash'] for d in BLACKLIST_DB) or \
                            any(d['exe'] == entry['exe'] for d in BLACKLIST_DB):
                        log.warning("DANGER !!!!!! " + p.name() +
                                    " has been blacklisted and the process has been killed.",  extra=CONFIG)
                        p.suspend()
                        # p.kill()
                        break

                    if not any(d['hash'] == entry['hash'] for d in WHITELIST_DB) or not \
                            any(d['exe'] == entry['exe'] for d in WHITELIST_DB):
                        if not any(d['hash'] == entry['hash'] for d in FAILED_DB) or not \
                                any(d['exe'] == entry['exe'] for d in FAILED_DB):
                            if p.exe() not in SEEN_DB:
                                if p.exe() not in BLACKLIST_DB:
                                    log.debug(entry, extra=CONFIG)
                                    log.debug(p.cmdline(), extra=CONFIG)

                                    data = {}
                                    cmdline = p.cmdline()
                                    files = []
                                    for c in cmdline:
                                        if "\\" in c:
                                            try:
                                                files.append(("files", open(c, "rb")))
                                            except Exception:
                                                continue
                                    data['files'] = files
                                    data['args'] = cmdline[1:]
                                    # if p.name() == "WINWORD.EXE" or p.name() == "sublime_text.exe":
                                    log.info("Sending to cuckoo", extra=CONFIG)
                                    path_list.append(p.exe())
                                    entry = {'pid': ps, 'name': p.name(), 'md5': md5(p.exe()),
                                             'time': str(datetime.datetime.now()),
                                             'exe': p.exe()}
                                    SEEN_DB.append(entry)

                                    update_state()
                                    threading.Thread(target=send_cuckoo, args=(p, data,)).start()

            except Exception as e:
                try:
                    FAILED_DB.append({'pid': p.pid, 'name': p.name(), 'time': str(datetime.datetime.now())})
                    failed += 1
                    log.info("Trying to add entry to failed list, " + p.name(), extra=CONFIG)

                except Exception as e:
                    log.error("",  exc_info=True, extra=CONFIG)
                    continue


def send_cuckoo(proc, data):
    global SEEN_DB, WHITELIST_DB, BLACKLIST_DB
    log.debug(data, extra=CONFIG)

    # messagebox.showinfo("W3RC", "We are currently analysing " + proc.name() + " please wait. We will not take long")
    log.info("")
    proc.suspend()

    log.info("\n\n\nSuspended -> " + proc.name() + " [" + str(proc.__hash__()) + "]", extra=CONFIG)
    log.info("Sending data to cuckoo analysis machine", extra=CONFIG)

    try:
        r = requests.head(IP + "/cuckoo/status")
        if r.status_code != 200:
            log.error("ERROR!!! \t Analysis machine is not configured properly", extra=CONFIG)
    except Exception as e:
        log.error("ERROR!!! \t Analysis machine is not online", extra=CONFIG)
        log.error("Resume the process at your own risk.", extra=CONFIG)
        # if input("Analysis will not continue, Do you want to leave the process suspended ? (Y/N)").lower() == "N":
        res = messagebox.askokcancel("W2RC", "Analysis will not continue.\n Do you want to leave "+proc.name()+" process suspended ?")
        print(res)
        if not res:
            proc.resume()
            log.info("Process " + proc.name() + " has now been resumed.", extra=CONFIG)

    try:
        r = requests.post(IP+"/tasks/create/submit", files=data['files'],
                      headers=HEADERS, data={"timeout": 15, "owner": OWNER_ID, "unique": True,
                                             "options": {"arguments": data["args"]}})
    except Exception as e:
        log.error("ERROR!!! \t Analysis machine is not online", extra=CONFIG)
        log.error("Resume the process at your own risk.", extra=CONFIG)
        if input("Analysis will not continue, Do you want to leave the process suspended ? (Y/N)").lower() == "N":
            proc.resume()
            log.info("Process " + proc.name() + " has now been resumed.", extra=CONFIG)

    if r.status_code != 200:
        log.error("FAILED to send to cuckoo for analysis", extra=CONFIG)
        log.error("Resume the process at your own risk.", extra=CONFIG)
        if input("Analysis will not continue, Do you want to leave the process suspended ? (Y/N)").lower() == "N":
            proc.resume()
            log.info("Process " + proc.name() + " has now been resumed.", extra=CONFIG)

    task_id = r.json()["task_ids"][0]
    log.debug(r.json(), extra=CONFIG)

    log.info(proc.name() + " job started with task ID: " + str(task_id))

    poll = True
    while poll:
        r = requests.get(IP+"/tasks/report/" + str(task_id))
        if "message" in r.json().keys():
            time.sleep(5)
        else:
            poll = False
            d = json.loads(r.content.decode('utf-8'))
            cklfil = ["crypt", "kernel", "wow", "shell", "advapi", "msvc"]

            if "static" not in d.keys():
                log.error("Failed to perform analysis", extra=CONFIG)
                log.error("Resume the process at your own risk.", extra=CONFIG)
                res = messagebox.askokcancel("W2RC",
                                             "Analysis failed.\n Do you want to leave " + proc.name() + " process suspended ?")
                print(res)
                if not res:
                    proc.resume()
                    log.info("Process " + proc.name() + " has now been resumed.", extra=CONFIG)
                break

            if "behaviour" not in d.keys():
                log.error("Failed to calculate CAT", extra=CONFIG)
                log.error("Resume the process at your own risk.", extra=CONFIG)
                res = messagebox.askokcancel("W2RC",
                                             "Analysis failed.\n Do you want to leave " + proc.name() + " process suspended ?")
                print(res)
                if not res:
                    proc.resume()
                    log.info("Process " + proc.name() + " has now been resumed.", extra=CONFIG)
                break

            static = d["static"]
            data = d["behavior"]["processes"]
            summary = d["behavior"]

            x = 0
            p = {"reg": 0, "reps": 0, "kd": 0, "kr": 0, "kq": 0, "kc": 0, "ko": 0, "regtime": 0.0,
                 "nf": 0, "deltac": 0.0, "ckl": 0.0, "N": x, "DM": 0.0, "AM": 0.0, "RM": 0.0, "EM": 0.0, "CAT": 0.0,
                 "pes": 0, "Npes": 0, "CATN": 4.0}
            tmpr = 0
            tmpa = 0

            flag = False
            first = True

            try:
                if "summary" in summary.keys():
                    if summary["summary"]["dll_loaded"]:
                        x = len(summary["summary"]["dll_loaded"])
                        p["N"] = x

                        for dll in summary["summary"]["dll_loaded"]:
                                if dll.lower() in cklfil:
                                    p["ckl"] += 1
                                    break
                    else:
                        p["N"] = static["imported_dll_count"]

                        if static["pe_imports"]:
                            for dll in static["pe_imports"]:
                                if dll["dll"].lower() in cklfil:
                                   p["ckl"] += 1
                                   break

                for dat in data:
                    for d in dat["calls"]:
                        if d["category"] == "registry":
                            if not flag:
                                tmpr = d["time"]
                                flag = True
                            p["reg"] = p["reg"] + 1
                            p["regtime"] = d["time"] - tmpr

                            if d["time"] - tmpr < 1.00:
                                p["reps"] += 1

                            if d["api"] == "RegCreateKeyExW" or d["api"] == "RegCreateKeyExA" or d["api"] == "RegCreateKeyA":
                                p["kr"] += 1

                            if d["api"] == "RegCloseKey":
                                p["kc"] += 1

                            if d["api"] == "RegOpenKeyExW" or d["api"] == "RegOpenKeyExA" or d["api"] == "RegOpenKeyA":
                                p["ko"] += 1

                            if d["api"] == "RegDeleteKeyExA" or d["api"] == "RegDeleteKeyExW" or d["api"] == "RegDeleteKeyA":
                                p["kd"] += 1

                            if d["api"] == "RegQueryInfoKeyW" or d["api"] == "RegQueryInfoKeyA":
                                p["kq"] += 1

                            if d["api"] == "RegOpenKeyExW":
                                p["ko"] += 1

                        else:
                            if first:
                                tmpa = d["time"]
                                first = False
                            p["nf"] = p["nf"] + 1
                            p["deltac"] = d["time"] - tmpa

                        p["DM"] = ((p["ckl"]) / (1+p["N"]))
                        if p["deltac"] == 0:
                            p["deltac"] = 1
                        p["AM"] = (p["nf"] / (p["deltac"] * p["N"]))
                        p["RM"] = (p["reps"] * ((1+p["kd"]) / (1+p["kr"])) + (p["kq"]) * (1+p["kc"] / (1+p["ko"])))

                        if static["pe_sections"]:
                            for s in static["pe_sections"]:
                                p["Npes"] += 1
                                p["pes"] += s["entropy"]
                                p["EM"] = p["pes"] / p["Npes"]
                        p["CAT"] = float(p["EM"])+float(p["DM"])+float(p["AM"])+float(p["RM"])
                        p["CAT"] = (p["CAT"] / p["CATN"])
            except Exception:
                log.error("Failed to calculate CAT", extra=CONFIG)
                log.error("Resume the process at your own risk.", extra=CONFIG)
                # if input(
                #         "Analysis will not continue, Do you want to leave the process suspended ? (Y/N)").lower() == "N":
                #     proc.resume()
                #     log.info("Process " + proc.name() + " has now been resumed.", extra=CONFIG)
                res = messagebox.askokcancel("W2RC",
                                             "Analysis failed.\n Do you want to leave " + proc.name() + " process suspended ?")
                if not res:
                    proc.resume()
                    log.info("Process " + proc.name() + " has now been resumed.", extra=CONFIG)

            log.info(proc.name() + " = CAT = [" + str(p["CAT"]) + "]", extra=CONFIG)
            log.debug(p, extra=CONFIG)
            entry = {'pid': ps, 'name': proc.name(), 'md5': md5(proc.exe()), 'time': str(datetime.datetime.now()),
                     'exe': proc.exe(), "CAT": p["CAT"]}
            if p["CAT"] > 50:
                BLACKLIST_DB.append(entry)

            for d in SEEN_DB:
                for k, v in d.items():
                    if k == "pid":
                        if v == ps:
                            d['CAT'] = p["CAT"]
    proc.resume()
    log.info("Resumed -> " + proc.name(), extra=CONFIG)


def remove_failed():
    # global failed_tv
    selected = failed_tv.selection()
    print(selected)
    tmp = 0
    for s in selected:
        FAILED_DB.pop(int(s)-1-tmp)
        tmp += 1
    update_state()
    for c in failed_tv.get_children():
        failed_tv.delete(c)
    i = 0
    for d in FAILED_DB:
        i += 1
        failed_tv.insert('', 'end', i, text=i, values=(d["name"], d["time"]),
                         tags=('failed', 'simple'))


def whitelist_gui():
    add_gui = Toplevel()
    add_gui.title("W2RC: Whitelist Add")
    add_gui.iconbitmap("data/icon.ico")

    Label(add_gui, font="Arial 16 bold", fg="black", bg="orange",
          text="Add Process ID (PID): ") \
        .grid(row=0, column=0, columnspan=1, sticky="nsew")
    add_pid = Entry(add_gui, textvariable=whitelist_pid)
    add_pid.grid(row=0, column=1)
    image = PhotoImage(file="data/add.png", height=30, width=30)
    image.zoom(50, 50)
    b = Button(add_gui, image=image, compound=TOP, command=add_whitelist_pid)
    b.image = image
    b.grid(row=0, column=3, sticky="nsew")

    Label(add_gui, font="Arial 16 bold", fg="black", bg="cyan",
          text="Add executable: ") \
        .grid(row=1, column=0, columnspan=1, sticky="nsew")
    image = PhotoImage(file="data/exe.png", height=30, width=30)
    image.zoom(50, 50)
    b = Button(add_gui, image=image, compound=TOP, command=add_whitelist_path)
    b.image = image
    b.grid(row=1, column=1, columnspan=3, sticky="news")

    Button(add_gui, compound=TOP, text="Browse", command=add_whitelist_path).grid(row=1, column=1, columnspan=3)


def add_whitelist_path():
    try:
        filename = fd.askopenfilename(title="Open Executable", filetypes=[("Executable file", "*.exe")])

        sp = subprocess.Popen(filename)
        time.sleep(10)
        p = psutil.Process(sp.pid)
        entry = {'pid': sp.pid, 'name': p.name(), 'md5': md5(p.exe()), 'time': str(datetime.datetime.now()),
                 'exe': p.exe()}
        WHITELIST_DB.append(entry)
        update_state()

        for c in whitelist_tv.get_children():
            whitelist_tv.delete(c)
        i = 0
        for d in WHITELIST_DB:
            i += 1
            whitelist_tv.insert('', 'end', i, text=i, values=(d["exe"], d["time"], d["md5"]),
                                tags=('success', 'simple'))
        messagebox.showinfo('W2RC', 'Successfully added ' + p.name())
    except Exception:
        messagebox.showerror('W2RC', 'Failed to add process with ID: ' + whitelist_pid.get())


def add_whitelist_pid():
    try:
        if int(whitelist_pid.get()) > 0:
            p = psutil.Process(int(whitelist_pid.get()))
            entry = {'pid': ps, 'name': p.name(), 'md5': md5(p.exe()), 'time': str(datetime.datetime.now()), 'exe': p.exe()}
            WHITELIST_DB.append(entry)
            update_state()
            for c in whitelist_tv.get_children():
                whitelist_tv.delete(c)
            i = 0
            for d in WHITELIST_DB:
                i += 1
                whitelist_tv.insert('', 'end', i, text=i, values=(d["exe"], d["time"], d["md5"]),
                                    tags=('success', 'simple'))
            messagebox.showinfo('W2RC', 'Successfully added ' + p.name())
            whitelist_pid.set("")
    except Exception:
        messagebox.showerror('W2RC', 'Failed to add process with ID: ' + whitelist_pid.get())


def remove_whitelist():
    selected = whitelist_tv.selection()
    print(selected)
    tmp = 0
    for s in selected:
        WHITELIST_DB.pop(int(s) - 1 - tmp)
        tmp += 1
    update_state()
    for c in whitelist_tv.get_children():
        whitelist_tv.delete(c)
    i = 0
    for d in WHITELIST_DB:
        i += 1
        whitelist_tv.insert('', 'end', i, text=i, values=(d["exe"], d["time"], d["md5"]),
                            tags=('success', 'simple'))


def safe_quit(sig, frame):
    log.info("Shutting down the monitor. Please wait...", extra=CONFIG)
    update_state()
    sys.exit(0)


def execute():
    if not is_running_as_admin():
        print('[!] W2RC is NOT running with administrative privileges')
        print('[+] Trying to bypass the UAC')
        try:
            # current_dir = os.path.dirname(os.path.realpath(__file__))
            cmd = '{} /k {} {}'.format(CMD, PYTHON_CMD, __file__)
            bypass_uac(cmd)
            os.system(FOD_HELPER)
            sys.exit(0)
        except WindowsError:
            sys.exit(1)
    else:
        print('[+] W2RC is running with administrative privileges!')

    welcome()

    load_safe_db()
    # gen_safe_db()

    # gen_safe_db()
    # print_db(BLACKLIST_DB_PATH, BLACKLIST_DB)
    # load_safe_db()
    # rm_safe_db()
    # add_safe_process(4872)
    # print_safe_db()
    # rm_safe_process(1020)
    # print_safe_db()

    # t = threading.Thread(target=monitor)
    # t.setDaemon(True)
    # t.start()
    signal.signal(signal.SIGINT, safe_quit)
    while True:
        monitor()


if __name__ == '__main__':

    welcome()

    main = Tk()
    main.title('W2RC - Windows Registry and RAM collector')
    main.geometry('465x550')
    main.iconbitmap("data/icon.ico")
    rows = 0
    main_frame = Frame(main, width=600, height=200, bg="white")
    main_frame.grid(row=0, column=0, sticky="nsew")
    HASHLIST = {"SEEN": StringVar(), "WHITELIST": StringVar(), "BLACKLIST": StringVar(), "FAILED": StringVar()}
    whitelist_pid = StringVar()
    load_safe_db()
    photo = PhotoImage(file="data/logo.png")
    photo.zoom(80, 80)
    label = Label(main_frame, image=photo, bg="white")
    label.image = photo
    label.grid(row=0, column=0, columnspan=3, sticky="nesw")
    # Label(main_frame, text="W2RC", font="Algerian 14 bold").grid(row=0, column=0, sticky="nesw")

    Label(main_frame, text="Enter Analysis Machine IP: ",  font="Arial 10 bold")\
        .grid(row=1, column=0, sticky="w")
    ip = Entry(main_frame, text="192.168.1.120:8090", bd=3)
    ip.grid(row=1, column=1, sticky="w", ipadx=10)
    ip.insert(0, "192.168.1.120:8090")

    # image = PhotoImage(file="data/img/system.png", height=50, width=50)
    # image.zoom(50, 50)
    b = Button(main_frame, text="Start / Stop Monitoring",  command=monitor)
    b.grid(row=1, column=2, sticky="nsew")

    while rows < 50:
        main.rowconfigure(rows, weight=1)
        main.columnconfigure(rows, weight=1)
        rows += 1

    # Defines and places the notebook widget

    nb = ttk.Notebook(main)
    nb.grid(row=2, column=0, columnspan=50, rowspan=49, sticky='NESW')

    # Monitor GUI
    mon = ttk.Frame(nb)
    nb.add(mon, text='Monitor')
    txt_frm = Frame(mon, width=450, height=200)
    txt_frm.grid(row=0, column=1, sticky="nsew")
    txt_frm.grid_propagate(False)
    txt_frm.grid_rowconfigure(0, weight=1)
    txt_frm.grid_columnconfigure(0, weight=1)
    mon_tv = ttk.Treeview(txt_frm)
    mon_tv['columns'] = ('NAME', 'TASK', 'STATUS')
    mon_tv.heading("#0", text='PID')
    mon_tv.column('#0', minwidth=10, width=50, stretch=False)
    mon_tv.heading('NAME', text='Name')
    mon_tv.column('NAME', minwidth=10, width=240, stretch=False)
    mon_tv.heading('TASK', text='Task ID')
    mon_tv.column('TASK', minwidth=10, width=50, stretch=False)
    mon_tv.heading('STATUS', text='Status')
    mon_tv.column('STATUS', minwidth=10, width=100, stretch=False)

    mon_tv.grid(row=0, column=0, sticky="nsew")
    scrollb = Scrollbar(txt_frm, command=mon_tv.yview)
    scrollb.grid(row=0, column=1, sticky='nsew')
    mon_tv['yscrollcommand'] = scrollb.set
    scrollbx = Scrollbar(txt_frm, command=mon_tv.xview, orient=HORIZONTAL)
    scrollbx.grid(row=1, column=0, sticky='nsew')
    mon_tv['xscrollcommand'] = scrollbx.set
    mon_tv.tag_configure('submitted', background='yellow')
    mon_tv.tag_configure('success', background='green')
    mon_tv.tag_configure('failed', background='red')

    ps = [1, 1]
    for i in range(0, len(ps)):
        mon_tv.insert('', 'end', i, text=1213, values=("p.exe", 24, "Submitted"), tags=('submitted', 'simple'))
    # ==================================================================================================

    # Seen
    seen = ttk.Frame(nb)
    nb.add(seen, text='Seen List')
    txt_frm = Frame(seen, width=450, height=200)
    txt_frm.grid(row=0, column=1, sticky="nsew")
    txt_frm.grid_propagate(False)
    txt_frm.grid_rowconfigure(0, weight=1)
    txt_frm.grid_columnconfigure(0, weight=1)
    seen_tv = ttk.Treeview(txt_frm)
    seen_tv['columns'] = ('PATH', 'CAT', 'TIME', 'MD5')
    seen_tv.heading("#0", text='ID')
    seen_tv.column('#0', minwidth=10, width=50, stretch=False)
    seen_tv.heading('PATH', text='Path')
    seen_tv.column('PATH', minwidth=10, width=280, stretch=True)
    seen_tv.heading('CAT', text='CAT')
    seen_tv.column('CAT', minwidth=10, width=50, stretch=True)
    seen_tv.heading('TIME', text='Timestamp')
    seen_tv.column('TIME', minwidth=10, width=100, stretch=False)
    seen_tv.heading('MD5', text='MD5 Hash')
    seen_tv.column('MD5', minwidth=10, width=200, stretch=True)

    seen_tv.grid(row=0, column=0, sticky="nsew")
    scrollb = Scrollbar(txt_frm, command=seen_tv.yview)
    scrollb.grid(row=0, column=1, sticky='nsew')
    seen_tv['yscrollcommand'] = scrollb.set
    scrollbx = Scrollbar(txt_frm, command=seen_tv.xview, orient=HORIZONTAL)
    scrollbx.grid(row=1, column=0, sticky='nsew')
    seen_tv['xscrollcommand'] = scrollbx.set
    seen_tv.tag_configure('submitted', background='yellow')
    seen_tv.tag_configure('success', background='lightgreen')
    seen_tv.tag_configure('failed', background='red')

    i = 0
    for d in SEEN_DB:
        i += 1
        seen_tv.insert('', 'end', i, text=i, values=(d["exe"], d["CAT"] if "CAT" in d.keys() else "N/A", d["time"], d["md5"]),
                       tags=('success', 'simple'))
    options = Frame(seen, width=550, height=200)
    options.grid(row=1, column=1, sticky="news")
    Label(options, text="MD5 HASH: ").grid(row=0, column=0)
    Entry(options, textvariable=HASHLIST['SEEN'], bg='cyan', state="readonly").grid(row=0, column=1, ipadx=100,
                                                                                      sticky="news")
    # =========================================================================================================

    # Whitelist
    whitelist = ttk.Frame(nb)
    nb.add(whitelist, text='Whitelist')
    txt_frm = Frame(whitelist, width=450, height=200)
    txt_frm.grid(row=0, column=1, sticky="nsew")
    txt_frm.grid_propagate(False)
    txt_frm.grid_rowconfigure(0, weight=1)
    txt_frm.grid_columnconfigure(0, weight=1)
    whitelist_tv = ttk.Treeview(txt_frm)
    whitelist_tv['columns'] = ('PATH', 'TIME', 'MD5')
    whitelist_tv.heading("#0", text='ID')
    whitelist_tv.column('#0', minwidth=10, width=50, stretch=False)
    whitelist_tv.heading('PATH', text='Path')
    whitelist_tv.column('PATH', minwidth=10, width=280, stretch=True)
    whitelist_tv.heading('TIME', text='Timestamp')
    whitelist_tv.column('TIME', minwidth=10, width=100, stretch=False)
    whitelist_tv.heading('MD5', text='MD5 Hash')
    whitelist_tv.column('MD5', minwidth=10, width=200, stretch=True)

    whitelist_tv.grid(row=0, column=0, sticky="nsew")
    scrollb = Scrollbar(txt_frm, command=whitelist_tv.yview)
    scrollb.grid(row=0, column=1, sticky='nsew')
    whitelist_tv['yscrollcommand'] = scrollb.set
    scrollbx = Scrollbar(txt_frm, command=whitelist_tv.xview, orient=HORIZONTAL)
    scrollbx.grid(row=1, column=0, sticky='nsew')
    whitelist_tv['xscrollcommand'] = scrollbx.set

    i = 0
    for d in WHITELIST_DB:
        i += 1
        whitelist_tv.insert('', 'end', i, text=i, values=(d["exe"], d["time"], d["md5"]),
                       tags=('success', 'simple'))
    options = Frame(whitelist, width=550, height=200)
    options.grid(row=1, column=1, sticky="news")
    Label(options, text="MD5 HASH: ").grid(row=0, column=0)
    Entry(options, textvariable=HASHLIST['WHITELIST'], bg='cyan', state="readonly").grid(row=0, column=1, ipadx=100,
                                                                                      sticky="news")
    options = Frame(whitelist, width=550, height=200)
    options.grid(row=1, column=1, sticky="news")
    Label(options, text="MD5 HASH: ").grid(row=0, column=0)
    Entry(options, textvariable=HASHLIST['WHITELIST'], bg='cyan', state="readonly").grid(row=0, column=1, ipadx=70,
                                                                                      sticky="w")
    image = PhotoImage(file="data/add.png", height=30, width=30)
    image.zoom(50, 50)
    b = Button(options, image=image, compound=TOP, command=whitelist_gui)
    b.image = image
    b.grid(row=0, column=2, sticky="nsew")

    image = PhotoImage(file="data/remove.png", height=30, width=30)
    image.zoom(50, 50)
    b = Button(options, image=image, compound=TOP, command=remove_whitelist)
    b.image = image
    b.grid(row=0, column=3, sticky="nsew")
    # =========================================================================================================

    # Blacklist
    blacklist = ttk.Frame(nb)
    nb.add(blacklist, text='Blacklist')
    txt_frm = Frame(blacklist, width=450, height=200)
    txt_frm.grid(row=0, column=1, sticky="nsew")
    txt_frm.grid_propagate(False)
    txt_frm.grid_rowconfigure(0, weight=1)
    txt_frm.grid_columnconfigure(0, weight=1)
    blacklist_tv = ttk.Treeview(txt_frm)
    blacklist_tv['columns'] = ('PATH', 'CAT', 'TIME', 'MD5')
    blacklist_tv.heading("#0", text='ID')
    blacklist_tv.column('#0', minwidth=10, width=50, stretch=False)
    blacklist_tv.heading('PATH', text='Path')
    blacklist_tv.column('PATH', minwidth=10, width=280, stretch=True)
    blacklist_tv.heading('CAT', text='CAT')
    blacklist_tv.column('CAT', minwidth=10, width=50, stretch=True)
    blacklist_tv.heading('TIME', text='Timestamp')
    blacklist_tv.column('TIME', minwidth=10, width=100, stretch=False)
    blacklist_tv.heading('MD5', text='MD5 Hash')
    blacklist_tv.column('MD5', minwidth=10, width=200, stretch=True)

    blacklist_tv.grid(row=0, column=0, sticky="nsew")
    scrollb = Scrollbar(txt_frm, command=blacklist_tv.yview)
    scrollb.grid(row=0, column=1, sticky='nsew')
    blacklist_tv['yscrollcommand'] = scrollb.set
    scrollbx = Scrollbar(txt_frm, command=blacklist_tv.xview, orient=HORIZONTAL)
    scrollbx.grid(row=1, column=0, sticky='nsew')
    blacklist_tv['xscrollcommand'] = scrollbx.set
    blacklist_tv.tag_configure('black', background='red')
    i = 0
    for d in BLACKLIST_DB:
        i += 1
        blacklist_tv.insert('', 'end', i, text=i, values=(d["exe"], d['CAT'] if 'CAT' in d.keys() else "N/A", d["time"], d["md5"]),
                            tags=('black', 'simple'))
    options = Frame(blacklist, width=550, height=200)
    options.grid(row=1, column=1, sticky="news")
    Label(options, text="MD5 HASH: ").grid(row=0, column=0)
    Entry(options, textvariable=HASHLIST['BLACKLIST'], bg='cyan', state="readonly").grid(row=0, column=1, ipadx=100,
                                                                                      sticky="news")
    # =========================================================================================================

    # Failed
    failed = ttk.Frame(nb)
    nb.add(failed, text='Failed List')
    txt_frm = Frame(failed, width=450, height=200)
    txt_frm.grid(row=0, column=1, sticky="nsew")
    txt_frm.grid_propagate(False)
    txt_frm.grid_rowconfigure(0, weight=1)
    txt_frm.grid_columnconfigure(0, weight=1)
    failed_tv = ttk.Treeview(txt_frm)
    failed_tv['columns'] = ('NAME', 'TIME')
    failed_tv.heading("#0", text='ID')
    failed_tv.column('#0', minwidth=10, width=50, stretch=False)
    failed_tv.heading('NAME', text='NAME')
    failed_tv.column('NAME', minwidth=10, width=200, stretch=True)
    failed_tv.heading('TIME', text='Timestamp')
    failed_tv.column('TIME', minwidth=10, width=200, stretch=True)

    failed_tv.grid(row=0, column=0, sticky="nsew")
    scrollb = Scrollbar(txt_frm, command=failed_tv.yview)
    scrollb.grid(row=0, column=1, sticky='nsew')
    failed_tv['yscrollcommand'] = scrollb.set
    scrollbx = Scrollbar(txt_frm, command=failed_tv.xview, orient=HORIZONTAL)
    scrollbx.grid(row=1, column=0, sticky='nsew')
    failed_tv['xscrollcommand'] = scrollbx.set
    failed_tv.tag_configure('failed', background='orange')
    i = 0
    for d in FAILED_DB:
        i += 1
        failed_tv.insert('', 'end', i,text=i, values=(d["name"], d["time"]),
                            tags=('failed', 'simple'))

    options = Frame(failed, width=550, height=200)
    options.grid(row=1, column=1, sticky="news")
    Label(options, text="MD5 HASH: ").grid(row=0, column=0)
    Entry(options, textvariable=HASHLIST['FAILED'], bg='cyan', state="readonly").grid(row=0, column=1, ipadx=70, sticky="w")
    image = PhotoImage(file="data/remove.png", height=30, width=30)
    image.zoom(50, 50)
    b = Button(options, text="Remove Selected", image=image, compound=TOP, command=remove_failed)
    b.image = image
    b.grid(row=0, column=2, sticky="nsew")

    # =========================================================================================================




    main.mainloop()
    # root = tkinter.Tk()
    # root.withdraw()
    # from ctypes import windll, byref
    # from ctypes.wintypes import SMALL_RECT
    # STDOUT = -11
    # hdl = windll.kernel32.GetStdHandle(STDOUT)
    # rect = SMALL_RECT(0, 50, 65, 180)  # (left, top, right, bottom)
    # windll.kernel32.SetConsoleWindowInfo(hdl, True, byref(rect))
    # windll.kernel32.SetConsoleCursorPosition(hdl, 0)
    # execute()









    #
    # p = None
    # if platform.architecture()[0] == '64bit':
    #     print("64bit")
    #     p = subprocess.Popen(os.path.dirname(os.path.realpath(__file__))+'\\pd64.exe', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    # else:
    #     p = subprocess.Popen(os.path.dirname(os.path.realpath(__file__))+'\\pd.exe', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    #
    # data = p.stdout.read()
    # # print(data)
    #
    # procList = psutil.pids()
    # print(procList)
    # print(len(procList))
    # failed = 0
    # whitelist = []
    # for ps in procList:
    #     try:
    #         # print("Hooking PID: " + str(ps))
    #         p = psutil.Process(ps)
    #         whitelist.append(p.name() + " -> " + str(p.__hash__()))
    #         print(p.__hash__())
    #
    #         # print(p.name() + "->\t" + p.exe())
    #     except Exception as e:
    #         print("Failed on PID: " + str(ps))
    #         print(e)
    #         failed += 1
    #
    # print(failed)
    # print(whitelist)
    # print(len(whitelist))
