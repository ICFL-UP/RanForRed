import os
import pickle
import hashlib
import psutil
import datetime
import subprocess
import time
import signal
import sys
import ctypes

dblist = ["db\WHITELIST", "db\BLACKLIST", "db\SEEN", "db\FAILED"]


def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def is_running_as_admin():
    '''
    Checks if the script is running with administrative privileges.
    Returns True if is running as admin, False otherwise.
    '''
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def view_db(name):

    db = []
    if os.path.exists(name):
        hash_md5 = md5(name)
        with open(name, 'rb') as f:
            db = pickle.load(f)
    else:
        with open(name, 'wb') as f:
            pickle.dump(db, f, pickle.HIGHEST_PROTOCOL)
        hash_md5 = md5(name)

    print("\n\n===========================================")
    print("\t"+name)
    print("===========================================")
    i = 1
    for e in db:
        print(str(i) + ") " + str(e)+"\n")
        i += 1
    print("===========================================")
    print("Total: " + str(len(db)) + " entries.")
    print("MD5 HASH: " + hash_md5)


def add_db(name):
    print("Please select the type of entry: ")
    print("1) Process ID (PID)")
    print("2) Executable Path - (NOTE: This will execute and collect info of the executable)")
    choice = int(input("Please choose a number: "))
    if 0 < choice < 3:
        if choice == 1:
            ps = int(input("Please enter a PID: "))
            p = psutil.Process(ps)
            entry = {'pid': ps, 'name': p.name(), 'md5': md5(p.exe()), 'time': str(datetime.datetime.now()), 'exe': p.exe()}
            db = []
            if os.path.exists(name) and os.path.getsize(name) > 0:
                with open(name, 'rb') as f:
                    db = pickle.load(f)
            else:
                with open(name, 'wb') as f:
                    pickle.dump(db, f, pickle.HIGHEST_PROTOCOL)
            db.append(entry)
            with open(name, 'wb') as f:
                pickle.dump(db, f, pickle.HIGHEST_PROTOCOL)
            print("Successfully added " + p.name() + " to " + name + " database.")
            print("Total: " + str(len(db)))
            print("MD5 HASH: " + md5(name))

        if choice == 2:
            path = input("Please enter the absolute path of the executable: ")
            if os.path.exists(path):
                sp = subprocess.Popen(path)
                time.sleep(10)
                p = psutil.Process(sp.pid)
                entry = {'pid': sp.pid, 'name': p.name(), 'md5': md5(p.exe()), 'time': str(datetime.datetime.now()),
                         'exe': p.exe()}
                db = []
                if os.path.exists(name) and os.path.getsize(name) > 0:
                    with open(name, 'rb') as f:
                        db = pickle.load(f)
                else:
                    with open(name, 'wb') as f:
                        pickle.dump(db, f, pickle.HIGHEST_PROTOCOL)
                db.append(entry)
                with open(name, 'wb') as f:
                    pickle.dump(db, f, pickle.HIGHEST_PROTOCOL)
                print("Successfully added " + p.name() + " to " + name + " database.")
                print("Total: " + str(len(db)))
                print("MD5 HASH: " + md5(name))

                print("Closing application ...")
                p.kill()

            else:
                print("Invalid path, please try again.")


def rm_db(name):
    view_db(name)
    choice = int(input("Please enter the number of the entry you want to delete: "))
    db = []
    if os.path.exists(name) and os.path.getsize(name) > 0:
        with open(name, 'rb') as f:
            db = pickle.load(f)
    else:
        with open(name, 'wb') as f:
            pickle.dump(db, f, pickle.HIGHEST_PROTOCOL)

    if 0 < choice < len(db)+1:
        print(db[choice-1])
        if input("Are you sure you want to delete this entry above (Y/N): ").lower() == "y":
            db.remove(db[choice-1])
            with open(name, 'wb') as f:
                pickle.dump(db, f, pickle.HIGHEST_PROTOCOL)
            print("Successfully removed entry")
            print("Total: " + str(len(db)))
            print("MD5 HASH: " + md5(name))


def gen_db(name):
    procList = psutil.pids()
    failed = 0
    db = []
    failed_db = []
    for ps in procList:
        try:
            p = psutil.Process(ps)
            entry = {'pid': ps, 'name': p.name(), 'md5': md5(p.exe()), 'time': str(datetime.datetime.now()),
                     'exe': p.exe()}
            db.append(entry)
            print("\rAdding " + p.name(), end="                \t\t\t\t\t\t\t            ")
        except Exception as e:
            p = psutil.Process(ps)
            failed_db.append({'pid': p.pid, 'name': p.name(), 'time': str(datetime.datetime.now())})
            failed += 1
    with open(name, 'wb') as f:
        pickle.dump(db, f, pickle.HIGHEST_PROTOCOL)
    with open("FAILED.DB", 'wb') as f:
        pickle.dump(failed_db, f, pickle.HIGHEST_PROTOCOL)

    print("\n\nTotal: " + str(len(db)))
    print("MD5 HASH: " + md5(name))
    print("Failed to add " + str(failed) + " entries. These can be seen in the FAILED database.")


def welcome():
    if not is_running_as_admin():
        print("Please run as Administrator...\nExiting ....")
        sys.exit(1)
    print("\n\n=======================================================\n")
    print("\t  ██╗    ██╗██████╗ ██████╗  ██████╗")
    print("\t  ██║    ██║╚════██╗██╔══██╗██╔════╝")
    print("\t  ██║ █╗ ██║ █████╔╝██████╔╝██║")
    print("\t  ██║███╗██║██╔═══╝ ██╔══██╗██║")
    print("\t  ╚███╔███╔╝███████╗██║  ██║╚██████╗")
    print("\t   ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝")
    print("\n\t  Windows Registry and RAM Collector\n\tDatabase Manager\n"
          "\t\t\t     -BY AVINASH SINGH")
    print("\n=======================================================\n")
    print("\nDatabase management system.\n\n")
    options()


def options():
    print("\nYou have the following options: ")
    i = 1
    for d in dblist:
        print(str(i) + ") " + d + " database.")
        i += 1
    print(str(i)+") Quit")


def safe_quit(sig, frame):
    print("\n\nExisting the database manager ...")
    sys.exit(0)


def execute():
    try:
        welcome()
        signal.signal(signal.SIGINT, safe_quit)
        while True:
            choice = int(input("\n\nPlease enter a number: "))
            if 0 < choice < len(dblist)+1:
                print("1) View")
                print("2) Add")
                print("3) Delete")
                if choice == 1:
                    print("4) Generate Whitelist from running processes")
                action = int(input("\n\nPlease enter a number: "))

                if 0 < action < 5:
                    if action == 1:
                        view_db(dblist[choice-1]+".db")
                    elif action == 2:
                        add_db(dblist[choice-1]+".db")
                    elif action == 3:
                        rm_db(dblist[choice-1]+".db")
                    elif action == 4:
                        gen_db(dblist[choice-1]+".db")
                    else:
                        print("Invalid option selected, please try again.")
            elif choice == len(dblist)+1:
                print("Exiting the manger ...")
                break
            else:
                print("Please select a valid option.")
            options()
    except Exception:
        print("An error occurred please try again.")


if __name__ == '__main__':
    os.system('cls' if os.name == 'nt' else 'clear')
    from ctypes import windll, byref
    from ctypes.wintypes import SMALL_RECT
    STDOUT = -11
    hdl = windll.kernel32.GetStdHandle(STDOUT)
    rect = SMALL_RECT(0, 50, 65, 90)  # (left, top, right, bottom)
    windll.kernel32.SetConsoleWindowInfo(hdl, True, byref(rect))
    windll.kernel32.SetConsoleCursorPosition(hdl, 0)
    print("RanForRed database manager starting ...")

    execute()
