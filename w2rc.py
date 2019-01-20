import tkinter
from tkinter import messagebox
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
import struct
import multiprocessing


# Winlogbear
CMD                   = r"C:\Windows\System32\cmd.exe"
FOD_HELPER            = r'C:\Windows\System32\fodhelper.exe'
PYTHON_CMD            = "F:\DigiForS\\venv\Scripts\python.exe"
REG_PATH              = 'Software\Classes\ms-settings\shell\open\command'
DELEGATE_EXEC_REG_KEY = 'DelegateExecute'
CWD                   = r'F:\UP_2017_CS_M_Y1\DF-Research\M\Tool\W2RC\\'
WHITELIST_DB_PATH     = r'F:\UP_2017_CS_M_Y1\DF-Research\M\Tool\W2RC\whitelist.hash'
WHITELIST_DB          = []
SEEN_DB_PATH          = r'F:\UP_2017_CS_M_Y1\DF-Research\M\Tool\W2RC\seen.hash'
SEEN_DB               = []
FAILED_DB_PATH        = r'F:\UP_2017_CS_M_Y1\DF-Research\M\Tool\W2RC\failed.hash'
FAILED_DB             = []
BLACKLIST_DB_PATH     = r'F:\UP_2017_CS_M_Y1\DF-Research\M\Tool\W2RC\blacklist.hash'
BLACKLIST_DB          = []
OWNER_ID              = "ASINGH"
HEADERS               = {"Authorization": "Bearer S4MPL3"}
IP                    = "http://192.168.1.124:8090"
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


def welcome():
    print("\n\n=======================================================\n")
    print("\t  ██╗    ██╗██████╗ ██████╗  ██████╗")
    print("\t  ██║    ██║╚════██╗██╔══██╗██╔════╝")
    print("\t  ██║ █╗ ██║ █████╔╝██████╔╝██║")
    print("\t  ██║███╗██║██╔═══╝ ██╔══██╗██║")
    print("\t  ╚███╔███╔╝███████╗██║  ██║╚██████╗")
    print("\t   ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝")
    print("\n\t  Windows Registry and RAM Collector\n\t\t\t\t     -BY AVINASH SINGH")
    print("\n=======================================================\n")
    print("\nMonitor now running press <CTRL> C  to stop monitoring.")

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
            entry = {'pid': ps, 'name': p.name(), 'hash': p.__hash__(), 'time': datetime.datetime.now()}
            WHITELIST_DB.append(entry)
        except Exception as e:
            failed += 1
    with open(WHITELIST_DB_PATH, 'wb') as f:
        pickle.dump(WHITELIST_DB, f, pickle.HIGHEST_PROTOCOL)

    log.info("Successfully created whitelist database", extra=CONFIG)
    log.info(str(len(WHITELIST_DB)) + " entries were added successfully.", extra=CONFIG)


def rm_safe_db():
    global WHITELIST_DB
    log.info("You are about to remove the whitelisted database.\n", extra=CONFIG)
    choice = input("Are you sure (yes/no)?")
    if choice == 'yes':
        if os.path.exists(WHITELIST_DB):
            os.remove(WHITELIST_DB_PATH)
            log.info("Successfully deleted whitelist database.", extra=CONFIG)


def load_safe_db():
    global WHITELIST_DB
    global FAILED_DB
    global SEEN_DB
    global BLACKLIST_DB

    hashdig = []
    dblist = ["WHITELIST", "FAILED", "BLACKLIST", "SEEN"]

    if os.path.exists(WHITELIST_DB_PATH) and os.path.getsize(WHITELIST_DB_PATH) > 0:
        hashdig.append(md5(WHITELIST_DB_PATH))
        with open(WHITELIST_DB_PATH, 'rb') as f:
            WHITELIST_DB = pickle.load(f)
    else:
        with open(WHITELIST_DB_PATH, 'wb') as f:
            pickle.dump(WHITELIST_DB, f, pickle.HIGHEST_PROTOCOL)
        hashdig.append(md5(WHITELIST_DB_PATH))

    if os.path.exists(FAILED_DB_PATH):
        hashdig.append(md5(FAILED_DB_PATH))
        with open(FAILED_DB_PATH, 'rb') as f:
            FAILED_DB = pickle.load(f)
    else:
        with open(FAILED_DB_PATH, 'wb') as f:
            pickle.dump(FAILED_DB, f, pickle.HIGHEST_PROTOCOL)
        hashdig.append(md5(FAILED_DB_PATH))

    if os.path.exists(BLACKLIST_DB_PATH):
        hashdig.append(md5(BLACKLIST_DB_PATH))
        with open(BLACKLIST_DB_PATH, 'rb') as f:
            BLACKLIST_DB = pickle.load(f)
    else:
        with open(BLACKLIST_DB_PATH, 'wb') as f:
            pickle.dump(BLACKLIST_DB, f, pickle.HIGHEST_PROTOCOL)
        hashdig.append(md5(BLACKLIST_DB_PATH))

    if os.path.exists(SEEN_DB_PATH):
        hashdig.append(md5(SEEN_DB_PATH))
        with open(SEEN_DB_PATH, 'rb') as f:
            SEEN_DB = pickle.load(f)
    else:
        with open(SEEN_DB_PATH, 'wb') as f:
            pickle.dump(SEEN_DB, f, pickle.HIGHEST_PROTOCOL)
        hashdig.append(md5(SEEN_DB_PATH))

    print("Successfully loaded WHITELIST_DB database (" + WHITELIST_DB_PATH + ") with (" + str(
        len(WHITELIST_DB)) + ") entries and MD5 hash ["+hashdig[0]+"].")
    print("Successfully loaded FAILED_DB database (" + FAILED_DB_PATH + ") with (" + str(
        len(FAILED_DB)) + ") entries and MD5 hash ["+hashdig[1]+"].")
    print("Successfully loaded BLACKLIST_DB database (" + BLACKLIST_DB_PATH + ") with (" + str(
        len(BLACKLIST_DB)) + ") entries and MD5 hash ["+hashdig[2]+"].")
    print("Successfully loaded SEEN_DB database (" + SEEN_DB_PATH + ") with (" + str(
        len(SEEN_DB)) + ") entries and MD5 hash ["+hashdig[3]+"].")

    log.debug(dblist, extra=CONFIG)
    log.debug(hashdig, extra=CONFIG)
    log.info("Successfully loaded databases", extra=CONFIG)


def update_db():
    with open(WHITELIST_DB_PATH, 'wb') as f:
        # Pickle the 'data' dictionary using the highest protocol available.
        pickle.dump(WHITELIST_DB, f, pickle.HIGHEST_PROTOCOL)

    print("Successfully updated whitelist database")
    print("Whitelist database now has: "+str(len(WHITELIST_DB)) + " entries.")


def update_state():
    global BLACKLIST_DB, SEEN_DB, FAILED_DB

    with open(BLACKLIST_DB_PATH, 'wb') as f:
        pickle.dump(BLACKLIST_DB, f, pickle.HIGHEST_PROTOCOL)
    with open(SEEN_DB_PATH, 'wb') as f:
        pickle.dump(SEEN_DB, f, pickle.HIGHEST_PROTOCOL)
    with open(FAILED_DB_PATH, 'wb') as f:
        pickle.dump(FAILED_DB, f, pickle.HIGHEST_PROTOCOL)


def print_safe_db():
    print("\n\n===========================================")
    print("========   Whitelist Database   ===========")
    print("===========================================")
    i = 1
    for e in WHITELIST_DB:
        print(str(i) + ") ")
        print(e)
        i += 1
    print("===========================================")


def print_db(path, db):
    print("\n\n===========================================")
    print(path)
    print("\n===========================================")
    i = 1
    for e in db:
        print(str(i) + ") " + str(e))
        i += 1
    print("===========================================")


def add_safe_process(pid):
    try:
        p = psutil.Process(pid)
        entry = {'pid': pid, 'name': p.name(), 'hash': p.__hash__(), 'time': datetime.datetime.now()}
        WHITELIST_DB.append(entry)
        print("Successfully added PID: " + str(pid) + "\n"+p.name() + " -> " + str(p.__hash__()))
        update_db()
    except Exception:
        print("Failed to add entry.")


def rm_safe_process(pid):
    try:
        p = psutil.Process(pid)
        global WHITELIST_DB
        WHITELIST_DB = [x for x in WHITELIST_DB if not (p.__hash__() == x.get('hash'))]
        print("Successfully removed PID: " + str(pid) + "\n" + p.name() + " -> " + str(p.__hash__()))
        update_db()
    except Exception:
        print("Failed to remove entry.")


def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


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

                entry = {'pid': p.pid, 'name': p.name(), 'hash': p.__hash__(), 'time': datetime.datetime.now()}

                if any(d['hash'] == entry['hash'] for d in BLACKLIST_DB):
                    log.warning("DANGER !!!!!! " + p.name() + " has been blacklisted and "
                                                                  "the process has been killed.",  extra=CONFIG)
                    p.suspend()
                    # p.kill()

                if not any(d['hash'] == entry['hash'] for d in WHITELIST_DB):
                    if not any(d['hash'] == entry['hash'] for d in FAILED_DB):
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
                                SEEN_DB.append(p.exe())
                                update_state()
                                threading.Thread(target=send_cuckoo, args=(p, data,)).start()

            except Exception as e:
                try:
                    FAILED_DB.append({'pid': p.pid, 'name': p.name(), 'hash': p.__hash__(), 'time': datetime.datetime.now()})
                    failed += 1
                    log.info("Trying to add entry to failed list, " + p.name(), extra=CONFIG)

                except Exception as e:
                    log.error("",  exc_info=True, extra=CONFIG)
                    continue


def send_cuckoo(proc, data):
    log.debug(data, extra=CONFIG)
    # proc.suspend()
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
                      headers=HEADERS, data={"timeout": 15, "owner": OWNER_ID, "options": {"arguments": data["args"]}})
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

    poll = True
    while poll:
        r = requests.get(IP+"/tasks/report/" + str(task_id))
        if "message" in r.json().keys():
            time.sleep(5)
        else:
            poll = False
            cklfil = ["crypt", "kernel", "wow", "shell", "advapi", "msvc"]
            static = r.json()["static"]
            data = r.json()["behavior"]["processes"]
            summary = r.json()["behavior"]

            x = 0
            p = {"reg": 0, "reps": 0, "kd": 0, "kr": 0, "kq": 0, "kc": 0, "ko": 0, "regtime": 0.0,
                 "nf": 0, "deltac": 0.0, "ckl": 0.0, "N": x, "DM": 0.0, "AM": 0.0, "RM": 0.0, "EM": 0.0, "CAT": 0.0,
                 "pes": 0, "Npes": 0}
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
                        p["CAT"] = (p["CAT"] / 4.0)
            except Exception:
                log.error("Failed to calculate CAT", extra=CONFIG)
                log.error("Resume the process at your own risk.", extra=CONFIG)
                if input(
                        "Analysis will not continue, Do you want to leave the process suspended ? (Y/N)").lower() == "N":
                    proc.resume()
                    log.info("Process " + proc.name() + " has now been resumed.", extra=CONFIG)

            log.info(p["CAT"], extra=CONFIG)
            log.debug(p, extra=CONFIG)
            if p["CAT"] > 50:
                global BLACKLIST_DB
                BLACKLIST_DB.append(proc.exe())
                update_state()
    # proc.resume()
    log.info("Resumed -> " + proc.name(), extra=CONFIG)


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

    while True:
        # gen_safe_db()
        # print_db(BLACKLIST_DB_PATH, BLACKLIST_DB)
        # load_safe_db()
        # rm_safe_db()
        # add_safe_process(4872)
        # print_safe_db()
        # rm_safe_process(1020)
        # print_safe_db()
        t = threading.Thread(target=monitor)
        t.setDaemon(True)
        t.start()

        signal.signal(signal.SIGINT, safe_quit)


if __name__ == '__main__':
    execute()









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
