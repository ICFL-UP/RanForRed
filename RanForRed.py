import tkinter
from tkinter import messagebox
import tkinter.filedialog as fd
import signal
import subprocess
import hashlib
import os
import sys
import ctypes
import psutil
import datetime
import pickle
import logging
import datetime as dt

import json
import requests
import getpass
import socket

import threading
import time
from tkinter import *
from tkinter import ttk


# Winlogbear
# CMD                   = r"C:\Windows\System32\cmd.exe"
# FOD_HELPER            = r'C:\Windows\System32\fodhelper.exe'
# PYTHON_CMD            = "F:\DigiForS\\venv\Scripts\python.exe"
# REG_PATH              = 'Software\Classes\ms-settings\shell\open\command'
# DELEGATE_EXEC_REG_KEY = 'DelegateExecute'
CWD                   = os.getcwd()
LOCAL_FAILED          = []
WHITELIST_DB_PATH     = CWD + r'\db\WHITELIST.db'
WHITELIST_DB          = []
SEEN_DB_PATH          = CWD + r'\db\SEEN.db'
SEEN_DB               = []
FAILED_DB_PATH        = CWD + r'\db\FAILED.db'
FAILED_DB             = []
BLACKLIST_DB_PATH     = CWD + r'\db\BLACKLIST.db'
BLACKLIST_DB          = []
HEADERS               = {"Authorization": "Bearer oMACdSqsxpjHx55H1ukQ8e"}
MONITOR               = True
# IP                    = "http://192.168.1.127:8090"
IP                    = "https://digifors.cs.up.ac.za/api"
IPS                   = "https://localhost:8443"
API_KEY               = "2oKKcr5Ktbcaki4hEhh0nPeIWuCKMmbR"
API_SECRET            = "bFF6vOYn"
CONFIG                = {"user": getpass.getuser(), "longuser": getpass.getuser() + " ("+socket.gethostname() + ")", 'machine': socket.gethostname(),
                         "ip": socket.gethostbyname_ex(socket.gethostname())[2][-1]}
                                  # if not ip.startswith("127.")] or [[(s.connect(("8.8.8.8", 53)),
                                  #             s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET,
                                  #                            socket.SOCK_DGRAM)]][0][1]]) + ["no IP found"])[0]}


def is_running_as_admin():
    '''
    Checks if the script is running with administrative privileges.
    Returns True if is running as admin, False otherwise.
    '''
    return True
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if not is_running_as_admin():
    messagebox.showerror('RanForRed', 'Please run as administrator')
    sys.exit(1)

OWNER_ID = getpass.getuser()

date = dt.datetime.now()
logfile = str(date)[0:10]
# logging.basicConfig(filename=CWD+'log\\' + logfile + '.log', level=logging.NOTSET)

log = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
if not os.path.exists("log"):
    os.mkdir("log")
fh = logging.FileHandler('log\\' + logfile + '.log')
fh.setLevel(logging.NOTSET)
formatter = logging.Formatter('%(asctime)s - %(ip)s - %(longuser)-8s [%(levelname)s] --> %(message)s',
                              datefmt='%d/%m/%Y %I:%M:%S')
handler.setFormatter(formatter)
fh.setFormatter(formatter)
log.addHandler(handler)
log.addHandler(fh)
log.setLevel(logging.INFO)
log = logging.LoggerAdapter(log, CONFIG)


log.info('RanForRed Started', extra=CONFIG)
RanForRed = ""
rlock = threading.RLock()


def welcome():
    global RanForRed
    RanForRed = "\n\n===========================================================================================================\n" + \
    "\n\t8888888b.                    8888888888               8888888b.               888 " + \
    "\n\t888   Y88b                   888                      888   Y88b              888 " + \
    "\n\t888    888                   888                      888    888              888 " + \
    "\n\t888   d88P  8888b.  88888b.  8888888  .d88b.  888d888 888   d88P .d88b.   .d88888 " + \
    "\n\t8888888P        88b 888  88b 888     d88  88b 888P    8888888P  d8P  Y8b d88  888 " + \
    "\n\t888 T88b   .d888888 888  888 888     888  888 888     888 T88b  88888888 888  888 " + \
    "\n\t888  T88b  888  888 888  888 888     Y88..88P 888     888  T88b Y8b.     Y88b 888 " + \
    "\n\t888   T88b  Y888888 888  888 888       Y88P   888     888   T88b  Y8888    Y88888 " + \
    "\n" + \
    "\n\t\t\t  Ransomware Forensic Readiness Agent\n\t\t\t\t\t\t\t     -BY AVINASH SINGH" + \
    "\n===========================================================================================================\n"
    print(RanForRed)
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


def gen_safe_db():
    procList = psutil.pids()
    failed = 0
    global WHITELIST_DB
    WHITELIST_DB = []

    for ps in procList:
        try:
            p = psutil.Process(ps)
            entry = {'pid': ps, 'name': p.name(), 'md5': md5(p.exe()), 'time': str(datetime.datetime.now()),
                     'exe': p.exe(), 'CAT': "N/A"}
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
    global CWD
    dblist = ["WHITELIST", "FAILED", "BLACKLIST", "SEEN"]
    if not os.path.exists(WHITELIST_DB_PATH):
        os.makedirs(CWD + 'db')

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


def refresh_db():
    load_safe_db()
    update_state()
    messagebox.showinfo('RanForRed', 'Successfully reloaded all databases.')


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


    for c in failed_tv.get_children():
        failed_tv.delete(c)
    i = 0
    for d in FAILED_DB:
        i += 1
        failed_tv.insert('', 'end', i, text=i, values=(d["name"], d["time"]),
                         tags=('failed', 'simple'))


    for c in whitelist_tv.get_children():
        whitelist_tv.delete(c)
    i = 0
    for d in WHITELIST_DB:
        i += 1
        whitelist_tv.insert('', 'end', i, text=i, values=(d["exe"], d["time"], d["md5"]),
                            tags=('success', 'simple'))


    for c in seen_tv.get_children():
        seen_tv.delete(c)
    i = 0
    for d in SEEN_DB:
        i += 1
        seen_tv.insert('', 'end', i, text=i,
                       values=(d["exe"], d["CAT"] if "CAT" in d.keys() else "N/A", d["time"], d["md5"]),
                       tags=('success', 'simple'))


    for c in blacklist_tv.get_children():
        blacklist_tv.delete(c)
    i = 0
    for d in BLACKLIST_DB:
        i += 1
        blacklist_tv.insert('', 'end', i, text=i,
                            values=(d["exe"], d['CAT'] if 'CAT' in d.keys() else "N/A", d["time"], d["md5"]),
                            tags=('black', 'simple'))

    HASHLIST["BLACKLIST"].set(md5(BLACKLIST_DB_PATH))
    HASHLIST["WHITELIST"].set(md5(WHITELIST_DB_PATH))
    HASHLIST["SEEN"].set(md5(SEEN_DB_PATH))
    HASHLIST["FAILED"].set(md5(FAILED_DB_PATH))
    mon_tv.yview_moveto(1)
    blacklist_tv.yview_moveto(1)
    whitelist_tv.yview_moveto(1)
    seen_tv.yview_moveto(1)
    failed_tv.yview_moveto(1)


def monitor():
    failed = 0
    path_list = []

    global WHITELIST_DB
    global FAILED_DB
    global SEEN_DB
    global BLACKLIST_DB, MONITOR
    log.info("Monitoring has been started: " + IP, extra=CONFIG)
    iter = 0
    while MONITOR:
        # log.info("Entering new iteration "+ str(iter), extra=CONFIG)
        iter += 1
        for p in psutil.process_iter():

            if p.pid != os.getpid():
                try:
                    entry = {'pid': p.pid, 'name': p.name(), 'md5': "", 'time': str(datetime.datetime.now()),
                             'exe': "", 'CAT': "N/A"}

                    try:
                        # log.info('RanForRed', 'Quickly computing md5 for {}'.format(entry['name']), extra=CONFIG)
                        p.suspend()
                        # if "sublime" in p.exe():
                        #     log.debug(p.name() + " suspend...", extra=CONFIG)
                        entry['md5'] = ""
                        # entry['md5'] = md5(p.exe()) // TODO
                        # entry['exe'] = p.exe()

                    except Exception:
                        p.resume()
                        # if "sublime" in p.name():
                        #     log.debug(p.name() + " resumed Exception ...", extra=CONFIG)
                        pass

                    if any(d['md5'] == entry['md5'] for d in BLACKLIST_DB):
                        if any(d['name'] == entry['name'] for d in BLACKLIST_DB):
                            log.warning("DANGER !!!!!! " + p.name() +
                                        " has been blacklisted and the process has been killed.",  extra=CONFIG)

                            p.suspend()
                            p.kill()
                            messagebox.showerror('RanForRed ALERT', 'Suspicious executable ' + entry['name'] +
                                                 ' that is blacklisted has been detected and killed.')
                            break

                    p.resume()

                    # if "sublime" in p.exe():
                    #     log.info("Found Sublime after blacklist", extra=CONFIG)

                    if not any(d['name'] == p.name() for d in FAILED_DB):
                        entry['md5'] = ""
                        entry['exe'] = p.exe()

                        if not any(d['name'] == entry['name'] for d in FAILED_DB) or not \
                                any(d['exe'] == entry['exe'] for d in FAILED_DB):
                            if not any(d['exe'] == entry['exe'] for d in SEEN_DB):
                                if not any(d['exe'] == entry['exe'] for d in LOCAL_FAILED):
                                    if not any(d['name'] == entry['name'] for d in WHITELIST_DB) or not \
                                            any(d['exe'] == entry['exe'] for d in WHITELIST_DB):
                                        if not MONITOR:
                                            return
                                        log.debug(entry, extra=CONFIG)
                                        log.debug(p.cmdline(), extra=CONFIG)
                                        if "sublime" in p.exe():
                                            log.info("Found Sublime after all searches", extra=CONFIG)
                                        data = {}
                                        cmdline = p.cmdline()
                                        log.info(cmdline, extra=CONFIG)
                                        files = []
                                        for c in cmdline:
                                            if "\\" in c:
                                                try:
                                                    files.append(("files", open(c, "rb")))
                                                except Exception:
                                                    continue
                                        if len(files) == 0:
                                            try:
                                                files.append(("files", open(os.path.join("C:/Windows/System32/", entry['exe']), "rb")))
                                            except Exception:
                                                continue

                                        data['files'] = files
                                        data['args'] = cmdline[1:]
                                        print(files)
                                        # if p.name() == "WINWORD.EXE" or p.name() == "sublime_text.exe":

                                        path_list.append(p.exe())
                                        entry = {'pid': p.pid, 'name': p.name(), 'md5': md5(p.exe()),
                                                 'time': str(datetime.datetime.now()),
                                                 'exe': p.exe(), 'CAT': "N/A"}
                                        with rlock:
                                            log.info("Sending to cuckoo", extra=CONFIG)
                                            SEEN_DB.append(entry)
                                            mon_tv.insert('', 'end', entry['pid'], text=entry['pid'], values=(entry['name'], entry['time'], "N/A", "Submitting"),
                                                      tags=('submitted', 'simple'))

                                        update_state()
                                        if "sublime" in p.exe():
                                            log.info("Found Sublime and now sending to cuckoo", extra=CONFIG)
                                        cuckoo = threading.Thread(target=send_cuckoo, args=(p, data, entry,))
                                        cuckoo.daemon = True
                                        cuckoo.start()

                except Exception as e:
                    try:

                        if not any(d['name'] == p.name() for d in FAILED_DB):
                            FAILED_DB.append({'pid': p.pid, 'name': p.name(), 'time': str(datetime.datetime.now())})
                            failed += 1
                            log.info("Trying to add entry to failed list, " + p.name(), extra=CONFIG)
                            # failed_tv.insert('', 'end', i, text=i, values=(p.name(), str(datetime.datetime.now())),
                            #                  tags=('failed', 'simple'))
                            update_state()
                            print(e)

                    except Exception as e:
                        log.error("Error at Monitor",  exc_info=True, extra=CONFIG)
                        continue


def check_online():
    global IP, IPS, MONITOR, t, API_KEY, API_SECRET
    MONITOR = False
    IP = ip.get()
    IPS = ips.get()
    API_KEY = key.get()
    API_SECRET = secret.get()
    print(IP)
    print(IPS)
    if "http" not in IP:
        IP = "http://"+IP
    if "http" not in IPS:
        IPS = "https://"+IPS
    log.info('Checking if ' + IP + " analysis machine is online.", extra=CONFIG)
    messagebox.showinfo('RanForRed', 'Trying to see if ' + IP + " analysis and storage machines are online. This should take a few seconds.")
    try:
        s = None
        r = requests.get(IP + "/cuckoo/status", stream=True, timeout=2, headers=HEADERS,)
        s = requests.get(IPS + "/", stream=False, timeout=5, verify=False)
        # s = ['status_code': 200, 'text': 'no idea why it does not work'})
        # s.status_code = 200
        # s.text = "No Idea why it doesn't work"
        # log.debug("cuckoo: " + str(r.status_code) + "  W3RS: " + str(s.status_code), extra=CONFIG)
        log.error("cuckoo: " + str(r.text) + "  W3RS: " + str(s.text), extra=CONFIG)
        if r.status_code != 200:
            log.error("ERROR!!! \t Analysis machine is not configured properly", extra=CONFIG)
            messagebox.showerror('RanForRed', "Analysis machine is not configured properly")
        elif r.status_code == 200:
            if s.status_code != 404:

                MONITOR = True
                t = threading.Thread(target=monitor, args=())
                t.daemon = True
                t.start()
                mon_btn.config(state="disabled")
                messagebox.showinfo('RanForRed', "Monitor started successfully.")
            else:
                log.error("ERROR!!! \t Storage machine is not online or configured properly", extra=CONFIG)
                messagebox.showerror('RanForRed', "Storage machine is not online or configured properly")
    except Exception as e:
        log.error("ERROR!!! \t Analysis machine is not online" + str(e), extra=CONFIG)
        log.error(e, extra=CONFIG)
        messagebox.showerror('RanForRed', "Analysis machine is not online. Monitoring will not continue.")

    # t.start()


def send_cuckoo(proc, data, entry):
    global SEEN_DB, WHITELIST_DB, BLACKLIST_DB
    log.debug(data, extra=CONFIG)
    try:
        proc.suspend()
        messagebox.showinfo("W3RC", "We are currently analysing " + proc.name() + " please wait. We will not take long")


        log.info("\n\n\nSuspended -> " + proc.name() + " [" + str(proc.__hash__()) + "]", extra=CONFIG)
        log.info("Sending data to cuckoo analysis machine", extra=CONFIG)

        r = requests.post(IP+"/tasks/create/submit", files=data['files'],
                      headers=HEADERS, data={"timeout": 10, "owner": OWNER_ID, "unique": False,
                                             "options": {"arguments": data["args"]}})
    except Exception as e:
        log.error("ERROR!!! \t Analysis machine is not online " + str(e), extra=CONFIG)
        log.error("Resume the process at your own risk: " + proc.name(), extra=CONFIG)
        res = messagebox.askyesno('RanForRed', "Analysis machine is not online. Do you want to leave process "+proc.name()+" suspended.")
        if not res:
            proc.resume()

            log.info("Process " + proc.name() + " has now been resumed.", extra=CONFIG)
        LOCAL_FAILED.append(entry)
        mon_tv.delete(proc.pid)
        return

    if r.status_code != 200:
        log.error("FAILED to send to cuckoo for analysis: "  + proc.name() + " status: " + str(r.status_code), extra=CONFIG)
        log.error(r.text, extra=CONFIG)
        log.error("Resume the process at your own risk.", extra=CONFIG)
        res = messagebox.askyesno('RanForRed',
                                  "Analysis machine did not respond successfully. Resume at own risk. \n"
                                  "Do you want to leave process " + proc.name() + " suspended.")
        if not res:
            proc.resume()
            log.info("Process " + proc.name() + " has now been resumed.", extra=CONFIG)
        mon_tv.delete(proc.pid)
        LOCAL_FAILED.append(entry)
        return

    task_id = r.json()["task_ids"][0]
    log.debug(r.json(), extra=CONFIG)

    mon_tv.set(proc.pid, 'TASK', task_id)
    mon_tv.set(proc.pid, 'STATUS', "Submitted")

    log.info(proc.name() + " job started with task ID: " + str(task_id), extra=CONFIG)

    poll = True
    while poll:
        r = requests.get(IP+"/tasks/report/" + str(task_id), headers=HEADERS)
        if "message" in json.loads(r.content.decode('utf-8')).keys():
            time.sleep(5)
        else:
            poll = False
            mon_tv.set(proc.pid, 'STATUS', "Analysing ...")

            log.info("Found report " + str(task_id), extra=CONFIG)
            d = json.loads(r.content.decode('utf-8'))
            cklfil = ["crypt", "kernel", "wow", "shell", "advapi", "msvc"]
            meta = analyse(d)
            if "static" not in d.keys():
                log.error("Failed to perform analysis", extra=CONFIG)
                log.error("Resume the process at your own risk: " + proc.name(), extra=CONFIG)
                res = messagebox.askyesno("RanForRed",
                                     "Analysis failed, could not perform static analysis."
                                     "\n Do you want to leave " + proc.name() + " process suspended ?")

                if not res:
                    proc.resume()
                    log.info("Process " + proc.name() + " has now been resumed.", extra=CONFIG)
                log.info("Removed from SEEN_DB: " + str(entry), extra=CONFIG)
                with rlock:
                    SEEN_DB.remove(entry)
                mon_tv.delete(proc.pid)
                LOCAL_FAILED.append(entry)
                break

            if "behavior" not in d.keys():
                log.error("No behaviour detected for " + proc.name(), extra=CONFIG)
                log.error("Resume the process at your own risk: " + proc.name(), extra=CONFIG)
                # res = messagebox.askyesno("RanForRed",
                #                      "Analysis failed, could not perform behavioural analysis."
                #                      "\n Do you want to leave " + proc.name() + " process suspended ?")
                # log.info("Removed from SEEN_DB: " + str(entry), extra=CONFIG)
                # with rlock:
                #     SEEN_DB.remove(entry)
                # mon_tv.delete(proc.pid)
                # if not res:
                #     try:
                #         proc.resume()
                #         log.info("Process " + proc.name() + " has now been resumed.", extra=CONFIG)
                #     except psutil._exceptions.NoSuchProcess as e:
                #         log.info("Process " + proc.name() + " not found.", extra=CONFIG)
                LOCAL_FAILED.append(entry)
                # break
            log.info("Found behaviour and static going to calculate CAT for " + str(task_id), extra=CONFIG)
            static = d["static"]


            x = 0
            p = {"reg": 0, "reps": 0, "kd": 0, "kr": 0, "kq": 0, "kc": 0, "ko": 0, "regtime": 0.0,
                 "nf": 0, "deltac": 0.0, "ckl": 0.0, "N": x, "DM": 0.0, "AM": 0.0, "RM": 0.0, "EM": 0.0, "CAT": 0.0,
                 "pes": 0, "Npes": 0, "CATN": 4.0}
            tmpr = 0
            tmpa = 0

            flag = False
            first = True

            try:
                if "behavior" in d.keys():
                    data = d["behavior"]["processes"]
                    summary = d["behavior"]
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
                    log.info("Looping through events  " + str(task_id), extra=CONFIG)
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
                p["CAT"] = round(p["CAT"], 2)
                entry["CAT"] = p["CAT"]
            except Exception as e:
                log.error(e, extra=CONFIG)
                log.error("Failed to calculate CAT: " + proc.name(), extra=CONFIG)
                log.error("Error: " + str(e), extra=CONFIG)
                log.error("Resume the process at your own risk: " + proc.name(), extra=CONFIG)
                res = messagebox.askyesno("RanForRed",
                                     "Analysis failed, could not calculate CAT value."
                                     "\n Do you want to leave " + proc.name() + " process suspended ?")
                if not res:
                    proc.resume()
                    log.info("Process " + proc.name() + " has now been resumed.", extra=CONFIG)

            log.info(proc.name() + " = CAT = [" + str(p["CAT"]) + "]", extra=CONFIG)
            entry = {'pid': proc.pid, 'name': proc.name(), 'md5': md5(proc.exe()), 'time': str(datetime.datetime.now()),
                     'exe': proc.exe(), "CAT": p["CAT"]}
            mon_tv.set(proc.pid, 'STATUS', "Storing ...")
            mon_tv.item(proc.pid, tags=('success'))
            if not os.path.exists("Reports"):
                os.mkdir("Reports")
            
            f = open(str(task_id)+".json", "w")
            f.write(r.text)
            f.close()
            securers = threading.Thread(target=securers_store, args=(task_id, entry, str(task_id)+".json", meta))
            securers.start()

            log.debug(p, extra=CONFIG)

            if p["CAT"] > 50:
                proc.kill()
                BLACKLIST_DB.append(entry)
                log.info("BLACKLIST: " + str(entry), extra=CONFIG)
                messagebox.showerror('RanForRed ALERT', 'ALERT!!! Suspicious executable '+entry['name'] +
                                     ' found and blacklisted.')
                update_state()
                break

            try:
                proc.resume()
            except Exception as e:
                continue
            messagebox.showinfo('RanForRed', entry['exe'] + " has been analysed successfully and appears safe with CAT ["
                                + str(entry['CAT']) + "]")
            mon_tv.delete(proc.pid)
            update_state()


    log.info("Finish -> " + proc.name(), extra=CONFIG)


def remove_failed():
    # global failed_tv
    selected = failed_tv.selection()
    print(selected)
    tmp = 0
    for s in selected:
        log.info("Removed from FAILED_DB: " + str(FAILED_DB[int(s)-1-tmp]), extra=CONFIG)
        FAILED_DB.pop(int(s)-1-tmp)
        tmp += 1
    update_state()


def unsuspend():
    # global failed_tv
    main.update()
    selected = mon_tv.selection()
    print(selected)
    for i in selected:
        p = psutil.Process(int(i))
        p.resume()
        mon_tv.item(i, tags=('resumed'))


def remove_seen():
    # global failed_tv
    main.update()
    selected = seen_tv.selection()
    print(selected)
    tmp = 0
    for s in selected:
        log.info("Removed from SEEN_DB: " + str(SEEN_DB[int(s) - 1 - tmp]), extra=CONFIG)
        SEEN_DB.pop(int(s)-1-tmp)
        tmp += 1
    update_state()


def test():
    global IP
    IP = "http://" + IP
    # r = requests.get(IP + "/tasks/report/150")


def securers_store(task_id, entry, filename, meta):
    log.info('Sending to SecureRS storage', extra=CONFIG)
    global IPS

    data = {
        'ip': CONFIG['ip'],
        'machine': CONFIG['machine'],
        'user': CONFIG['user'],
        'rank': entry['rank'],
        'filename': filename,
        'meta': meta,
        'md5sum': entry['md5sum'],

        # 'task_id': task_id,
        # 'pde': open(str(task_id) + ".json", 'rb')
    }
    
    files = {'pde': open(filename, 'rb')}
    # headers = { 'Api-Secret-Key': 'Zm4QsmdXsobX', 'Api-Token': 'f8000c5bb202edd77e994658f02949a2'} #old
    global API_KEY, API_SECRET

    headers = { 'Api-Secret-Key': API_SECRET, 'Api-Token': API_KEY, 'MD5SUM': entry['md5sum'],
                'X-Api-Key': API_SECRET + "." + API_KEY, 'Authorization': 'Token ' + API_SECRET + "." + API_KEY}
    # 'content-type': 'multipart/form-data',
    if "http" not in IPS:
        IPS = "https://" + IPS
    r = requests.post(IPS+"/pde/add/", data=data, headers=headers, files=files, verify=False)
    # r = requests.post("https://localhost:8000/pde/add/", data=data, headers=headers, files=files, verify=False)
    print(r.text)
    if "Success" not in r.text:
        messagebox.showerror('SecureRS', "Failed to store result on the storage server.")
    log.info('Message from SecureRS: ' + r.text, extra=CONFIG)


def whitelist_gui():
    add_gui = Toplevel()
    add_gui.title("RanForRed: Whitelist Add")
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
    image = PhotoImage(file="data/exe.png", height=50, width=50)
    image.zoom(50, 50)
    b = Button(add_gui, image=image, compound=TOP, text="Browse", command=add_whitelist_path)
    b.image = image
    b.grid(row=1, column=1, columnspan=3, rowspan=2, sticky="news")

    Label(add_gui, font="Arial 10 bold", fg="black", bg="cyan",
          text="Note: This will run the executable and collect information. \n"
               "The executable will be run for about 10 seconds before it will be terminated.") \
        .grid(row=2, column=0, columnspan=1, sticky="nsew")


def add_whitelist_path():
    try:
        filename = fd.askopenfilename(title="Open Executable", filetypes=[("Executable file", "*.exe")])

        sp = subprocess.Popen(filename)
        time.sleep(10)
        p = psutil.Process(sp.pid)
        entry = {'pid': sp.pid, 'name': p.name(), 'md5': md5(p.exe()), 'time': str(datetime.datetime.now()),
                 'exe': p.exe()}
        WHITELIST_DB.append(entry)
        log.info("Whitelist Path Add: " + str(entry), extra=CONFIG)
        update_state()
        #
        # for c in whitelist_tv.get_children():
        #     whitelist_tv.delete(c)
        # i = 0
        # for d in WHITELIST_DB:
        #     i += 1
        #     whitelist_tv.insert('', 'end', i, text=i, values=(d["exe"], d["time"], d["md5"]),
        #                         tags=('success', 'simple'))
        messagebox.showinfo('RanForRed', 'Successfully added ' + p.name())
    except Exception:
        messagebox.showerror('RanForRed', 'Failed to add executable. ')


def add_whitelist_pid():
    try:
        if int(whitelist_pid.get()) > 0:
            p = psutil.Process(int(whitelist_pid.get()))
            entry = {'pid': p.pid, 'name': p.name(), 'md5': md5(p.exe()), 'time': str(datetime.datetime.now()), 'exe': p.exe()}
            WHITELIST_DB.append(entry)
            log.info("Whitelist PID Add: " + str(entry), extra=CONFIG)
            update_state()
            # for c in whitelist_tv.get_children():
            #     whitelist_tv.delete
            # i = 0
            # for d in WHITELIST_DB:
            #     i += 1
            #     whitelist_tv.insert('', 'end', i, text=i, values=(d["exe"], d["time"], d["md5"]),
            #                         tags=('success', 'simple'))
            messagebox.showinfo('RanForRed', 'Successfully added ' + p.name())
            whitelist_pid.set("")
    except Exception:
        messagebox.showerror('RanForRed', 'Failed to add process with ID: ' + whitelist_pid.get())


def remove_whitelist():
    selected = whitelist_tv.selection()
    print(selected)
    tmp = 0
    for s in selected:
        log.info("Removed from WHITELIST_DB: " + str(WHITELIST_DB[int(s) - 1 - tmp]), extra=CONFIG)
        WHITELIST_DB.pop(int(s) - 1 - tmp)
        tmp += 1
    update_state()


def safe_quit():
    if messagebox.askyesno('RanForRed', 'Are you sure you want to quit?'):
        global MONITOR
        MONITOR = False
        
        log.info("Shutting down the monitor. Please wait...", extra=CONFIG)
        update_state()
        main.withdraw()
        main.destroy()
        sys.exit(0)


def stop_monitoring():
    main.update()
    global MONITOR
    MONITOR = False
    update_state()
    mon_btn.config(state="active")
    log.info('Monitoring has stopped by user ', extra=CONFIG)


def execute():
    if not is_running_as_admin():
        print('[!] RanForRed is NOT running with administrative privileges')
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
        print('[+] RanForRed is running with administrative privileges!')

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


def send_test_cuckoo():
    r = requests.post("http://"+IP + "/tasks/create/submit", files=[("files", open("C:\Program Files\SSD\Sublime Text 3\sublime_text.exe", "rb"))],
                      headers=HEADERS, data={"timeout": 60, "owner": OWNER_ID, "unique": True})
    log.info(r.status_code, extra=CONFIG)
    log.info(r.text, extra=CONFIG)


def alert(title, message):
    box = Tk()
    box.title(title)
    Message(box, text=message, bg='red',
      fg='ivory').pack(padx=1, pady=1) #, relief=GROOVE
    Button(box, text="Close", command=box.destroy).pack(side=BOTTOM)
    box.geometry('300x150')

    box.mainloop()


def analyse(data=None):
    import classification
    import json
    from tabulate import tabulate
    
    global RESULT
    if not data:
        filename = fd.askopenfilename(title="Open Cuckoo Report", filetypes=[("JSON File", "*.json")])
        # messagebox.showinfo('RanForRed', 'Selected file: ' + filename)
        f = open(filename, 'r')
        data = json.loads(f.read())
        f.close()
        del f
    res, classification = classification.classify(data)
    print(res, classification)
    r = tabulate(res, headers="firstrow",  tablefmt="psql", numalign="center", stralign="center", floatfmt=".2f")

    RESULT.set("File: " + filename.split("/")[-1] + "\n" + r.replace(" ", '   '))
    if classification == 1:
        messagebox.showerror('ATTENTION!!!!', filename + "\nHas been flagged as MALICIOUS")
    else:
        messagebox.showinfo('RanForRed', filename + "\nHas been classified as Benign")

#   @TODO REMOVE ONLY for testing
    entry = {'pid': 5457, 'name': filename.split("/")[-1], 'md5sum': md5(filename), 'time': str(datetime.datetime.now()),
                    'exe': "TEST", "rank": 10 if classification == 1 else 5}
    
    securers_store(entry=entry, task_id=454, filename=filename, meta=str(r))
    print(entry)
            
    return res

# ======================================================================================================================
# ======================================================================================================================
#                                                    MAIN
# ======================================================================================================================
# ======================================================================================================================


if __name__ == '__main__':
    # if not is_running_as_admin():
    #    messagebox.showerror('RanForRed', 'Please run as administrator')
    #    sys.exit(1)
    # test()
    welcome()

    main = Tk()
    main.withdraw()  # hide the window
    main.title('RanForRed - Ransomware Forensic Readiness')
    main.geometry('620x765')
    main.iconbitmap("data/icon.ico")

    main.after(0, main.deiconify)  # as soon as possible (after app starts) show again
    # send_test_cuckoo()
    #
    # # TODO REMOVE not
    # # if is_running_as_admin():
    #     # Get User
    #     # answer = simpledialog.askstring("RanForRed", "What is your full name?",
    #     #                                 parent=main)
    #     # if answer is not None:
    #     #     print("Your first name is ", answer)
    #     #     CONFIG[""]
    #     # else:
    #     #     print("You don't have a first name?")
    #
    # rows = 0
    main_frame = Frame(main, width=800, height=200, bg="white")
    main_frame.grid(row=0, column=0, sticky="nsew")
    HASHLIST = {"SEEN": StringVar(), "WHITELIST": StringVar(), "BLACKLIST": StringVar(), "FAILED": StringVar()}
    RESULT = StringVar()
    whitelist_pid = StringVar()
    load_safe_db()
    photo = PhotoImage(master=main_frame, file="data/logo.png")
    # photo.zoom(80, 80)
    label = Label(main_frame, image=photo, bg="white")
    label.image = photo
    label.grid(row=0, column=1, sticky="ew")
    # Label(main_frame, text="RanForRed", font="Algerian 14 bold").grid(row=0, column=0, sticky="nesw")

    Label(main_frame, text="Enter Analysis Machine IP: ",  font="Arial 10 bold")\
        .grid(row=1, column=0, sticky="w")
    ip = Entry(main_frame, text="", bd=3, width=45)
    ip.grid(row=1, column=1, sticky="w", ipadx=10)
    ip.insert(0, IP)

    Label(main_frame, text="Enter Storage Machine IP: ", font="Arial 10 bold") \
        .grid(row=2, column=0, sticky="w")
    ips = Entry(main_frame, text="", bd=3, width=45)
    ips.grid(row=2, column=1, sticky="w", ipadx=10)
    ips.insert(0, IPS)

    Label(main_frame, text="Enter API-SECRET: ", font="Arial 10 bold") \
        .grid(row=3, column=0, sticky="w")
    secret = Entry(main_frame, text="", bd=3, width=45)
    secret.grid(row=3, column=1, sticky="w", ipadx=10)
    secret.insert(0, API_SECRET)

    Label(main_frame, text="Enter API-KEY/TOKEN: ", font="Arial 10 bold") \
        .grid(row=4, column=0, sticky="w")
    key = Entry(main_frame, text="", bd=3, width=45)
    key.grid(row=4, column=1, sticky="w", ipadx=10)
    key.insert(0, API_KEY)

    # image = PhotoImage(file="data/system.png", height=50, width=50)
    # image.zoom(50, 50)
    mon_btn = Button(main_frame, text="Start Monitoring",  command=check_online)
    mon_btn.grid(row=1, column=2, sticky="nsew", pady=10, padx=10)
    q_btn = Button(main_frame, text="Stop", command=stop_monitoring)
    q_btn.grid(row=3, column=2, sticky="nsew", pady=10, padx=10)

    # while rows < 50:
    #     main.rowconfigure(rows, weight=1)
    #     main.columnconfigure(rows, weight=1)
    #     rows += 1

    # Defines and places the notebook widget

    image = PhotoImage(file="data/refresh.png", height=50, width=50)
    image.zoom(50, 50)
    b = Button(main, image=image, bg='grey', compound=LEFT, text="Reload databases", command=refresh_db)
    b.image = image
    b.grid(row=51, columnspan=50, sticky="nsew")
    Label(main, text="Disclaimer: Once the monitor has started the GUI may take some time to respond. \n" +
                     "Since this is a prototype tool please run in a VM when testing against malicious samples",
          font="Arial 7 bold") \
        .grid(row=52, column=0, sticky="w")

    manual = Frame(main, width=620, height=200)
    manual.grid(row=53, column=0, sticky="se")
    Label(manual, textvariable=RESULT, anchor="e", justify=LEFT).grid(row=0, column=0, sticky="w")
    
    image = PhotoImage(file="data/exe.png", height=30, width=30)
    image.zoom(50, 50)
    b = Button(manual, text="Analyse Cuckoo Report", image=image, compound=TOP, command=analyse)
    b.image = image
    b.grid(row=0, column=2, sticky="se", padx=10, pady=10)


    # Notebook
    nb = ttk.Notebook(main)
    nb.grid(row=3, column=0, columnspan=50, rowspan=49, sticky='NESW')


    # Monitor GUI
    mon = ttk.Frame(nb)
    nb.add(mon, text='Monitor')
    txt_frm = Frame(mon, width=620, height=200)
    txt_frm.grid(row=0, column=1, sticky="nsew")
    txt_frm.grid_propagate(False)
    txt_frm.grid_rowconfigure(0, weight=1)
    txt_frm.grid_columnconfigure(0, weight=1)
    mon_tv = ttk.Treeview(txt_frm)
    mon_tv['columns'] = ('NAME', 'TIME', 'TASK', 'STATUS')
    mon_tv.heading("#0", text='PID')
    mon_tv.column('#0', minwidth=10, width=60, stretch=True)
    mon_tv.heading('NAME', text='Name')
    mon_tv.column('NAME', minwidth=10, width=120, stretch=False)
    mon_tv.heading('TIME', text='Timestamp')
    mon_tv.column('TIME', minwidth=10, width=120, stretch=False)
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
    mon_tv.tag_configure('resumed', background='orange')

    options = Frame(mon,  width=620, height=200)
    options.grid(row=1, column=1, sticky="news")
    Label(options, text="MD5 HASH: ").grid(row=0, column=0)
    Entry(options, textvariable=HASHLIST['SEEN'], bg='cyan', state="readonly").grid(row=0, column=1, ipadx=80,
                                                                                      sticky="news")
    image = PhotoImage(file="data/resume.png", height=30, width=30)
    image.zoom(50, 50)
    b = Button(options, text="Resume Selected", image=image, compound=TOP, command=unsuspend)
    b.image = image
    b.grid(row=0, column=2, sticky="e")


    # ==================================================================================================

    # Seen
    seen = ttk.Frame(nb)
    nb.add(seen, text='Seen List')
    txt_frm = Frame(seen, width=620, height=200)
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
    options = Frame(seen, width=620, height=200)
    options.grid(row=1, column=1, sticky="news")
    Label(options, text="MD5 HASH: ").grid(row=0, column=0)
    Entry(options, textvariable=HASHLIST['SEEN'], bg='cyan', state="readonly").grid(row=0, column=1, ipadx=80,
                                                                                      sticky="news")
    image = PhotoImage(file="data/remove.png", height=30, width=30)
    image.zoom(50, 50)
    b = Button(options, text="Remove Selected", image=image, compound=TOP, command=remove_seen)
    b.image = image
    b.grid(row=0, column=2, sticky="nsew")
    seen_tv.yview_moveto(0)
    # =========================================================================================================

    # Whitelist
    whitelist = ttk.Frame(nb)
    nb.add(whitelist, text='Whitelist')
    txt_frm = Frame(whitelist, width=620, height=200)
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
    options = Frame(whitelist, width=620, height=200)
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
    txt_frm = Frame(blacklist, width=620, height=200)
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
    options = Frame(blacklist, width=620, height=200)
    options.grid(row=1, column=1, sticky="news")
    Label(options, text="MD5 HASH: ").grid(row=0, column=0)
    Entry(options, textvariable=HASHLIST['BLACKLIST'], bg='cyan', state="readonly").grid(row=0, column=1, ipadx=100,
                                                                                      sticky="news")
    # =========================================================================================================

    # Failed
    failed = ttk.Frame(nb)
    nb.add(failed, text='Failed List')
    txt_frm = Frame(failed, width=620, height=200)
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

    options = Frame(failed, width=620, height=200)
    options.grid(row=1, column=1, sticky="news")
    Label(options, text="MD5 HASH: ").grid(row=0, column=0)
    Entry(options, textvariable=HASHLIST['FAILED'], bg='cyan', state="readonly").grid(row=0, column=1, ipadx=70, sticky="w")
    image = PhotoImage(file="data/remove.png", height=30, width=30)
    image.zoom(50, 50)
    b = Button(options, text="Remove Selected", image=image, compound=TOP, command=remove_failed)
    b.image = image
    b.grid(row=0, column=2, sticky="nsew")

    # =========================================================================================================

    t = threading.Thread(target=monitor, args=())
    t.daemon = True
    mon_tv.yview_moveto(1)
    blacklist_tv.yview_moveto(1)
    whitelist_tv.yview_moveto(1)
    seen_tv.yview_moveto(1)
    failed_tv.yview_moveto(1)

    main.protocol("WM_DELETE_WINDOW", safe_quit)
    main.mainloop()
# messagebox.showerror('RanForRed', 'Please run as administrator.')
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


