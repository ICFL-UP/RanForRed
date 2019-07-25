import sys
import os
from cx_Freeze import *

os.environ['TCL_LIBRARY'] = "C:\\Program Files\\Python37\\tcl\\tcl8.6"
os.environ['TK_LIBRARY'] = "C:\\Program Files\\Python37\\tcl\\tk8.6"

base = None

if sys.platform == 'win32':
    base = "Win32GUI"

if 'bdist_msi' in sys.argv:
    sys.argv += ['--initial-target-dir', "C:\\Program Files\\W2RC"]

executables = [Executable(script="w2rc.py", base=base, shortcutName="W2RC", shortcutDir="DesktopFolder", icon='icon.ico')]
# executables = [Executable("w2rc.py", base=base, icon="icon.ico", shortcutName="W2RC",shortcutDir="DesktopFolder")]

packages = ["os", "six", "tkinter", "datetime", "logging", "subprocess", "pickle",
            "hashlib", "psutil", "json", "requests", "getpass", "socket", "threading", "idna", "cryptography"]
options = {
    'build_exe': {
        'packages': packages,
        'include_files': ["data", "tcl86t.dll", "tk86t.dll", "icon.ico", "db", "log", "dbmanage.py"], #
        'include_msvcr': True,

        "excludes": ["PyQt4.QtSql", "sqlite3",
                                  "scipy.lib.lapack.flapack",
                                  "PyQt4.QtNetwork",
                                  "PyQt4.QtScript",
                                  "numpy.core._dotblas",
                                  "PyQt5"],
    },

}

setup(
    name="W2RC",
    options=options,
    version="1.3",
    author="Avinash Singh",
    description='Windows Registry and RAM Collector',
    executables=executables
)
