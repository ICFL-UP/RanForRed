import joblib
import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime
import traceback
import numpy as np
import time
from concurrent.futures import ThreadPoolExecutor
from sklearn.ensemble import (
    GradientBoostingClassifier,
)
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from tabulate import tabulate

MODEL_LIST = ["GBT", "GBT", "GBT", "GBT", "KNN", "NN", "RF"]
PREFIX = ["ACFM", "PEEM", "PEIM", "PSMTFIDF", "PMM", "ROM", "FOM"]

results = {"ACFM": [], "PEEM": [], "PEIM": [], "PSMTFIDF": [], "PMM": [], "ROM": [], "FOM": []}
table = [["Model", "B (%)", "M (%)", "Time (ms)", "Classification"]]
failed = ""
decision = []
res = ""
lat = ""


def classify(report):
    global res, decision, failed, lat, results, table
    results = {"ACFM": [], "PEEM": [], "PEIM": [], "PSMTFIDF": [], "PMM": [], "ROM": [], "FOM": []}
    failed = ""
    decision = []
    res = ""
    lat = ""
    table = [["Model", "B (%)", "M (%)", "Time (ms)", "Classification"]]

    with ThreadPoolExecutor(max_workers=7) as executor:
        executor.map(lambda x: process_model(x, report), range(0, len(MODEL_LIST)))
        # for x in range(0, len(MODEL_LIST)):
        #     executor.submit(process_model, x, report)
        
    print(results)
    print(lat)
    print(decision)
    res += "\n\n" + lat
    print("\n\n____FAILED___\nn" + failed)
    return table, decision.count("Malicious") > decision.count("Benign")


def process_model(x, report):
    global res, decision, failed, lat, results, table
    start = time.time()
    try: 
        print(MODEL_LIST[x], PREFIX[x])
        model = joblib.load(
            "Models/{}_{}_model.pkl".format(MODEL_LIST[x], PREFIX[x])
        )
        preds = model.predict_proba(getFeatures(PREFIX[x], report))
        results[PREFIX[x]] = preds
        print('{:f} \t {:f}'.format(preds[0][0], preds[0][1]))
        tmp = [0, 0]
        if len(preds) > 1:
            for p in preds:
                tmp[0] += p[0]
                tmp[1] += p[1]
            tmp[0] = tmp[0] / len(preds) if tmp[0] != 0 else 0
            tmp[1] = tmp[1] / len(preds) if tmp[1] != 0 else 0
            des = "Malicious" if tmp.index(max(tmp)) == 1 else "Benign"
            b = str(round(tmp[0] * 100, 2))
            m = str(round(tmp[1] * 100, 2))
            t = str(round((time.time() - start) * 1000, 4))
            res += "\n" + PREFIX[x] + ": \tB:" + b + "%\t M:" + m + "%\t Result: " + des
            decision.append(des)
            table.append([PREFIX[x], b, m, t, des])
        else:
            des = "Malicious" if np.argmax(preds) == 1 else "Benign"
            b = str(np.round(preds[0][0] * 100, 2))
            m = str(np.round(preds[0][1] * 100, 2))
            t = str(round((time.time() - start) * 1000, 4))
            res += "\n" + PREFIX[x] + ": \tB:" + b + "%\t M:" + m + "%\tTime: \t"+ t + " ms\t Result: " + des
            decision.append(des)
            table.append([PREFIX[x], b, m, t, des])
    except Exception as e:
        failed += PREFIX[x] + "\n"
        res += "\n" + PREFIX[x] + ": Could not compute \tTime: \t"+ str(round((time.time() - start) * 1000, 4)) + " ms"
        table.append([PREFIX[x], "-", "-", str(round((time.time() - start) * 1000, 4)), "-"])
        print(traceback.print_exc())



def getFeatures(pre, data):
    if pre == "ACFM":
        features_labels = ["GetUserNameExW", "NtDuplicateObject", "NtOpenSection", "GetVolumePathNameW", "RegCloseKey", "GetNativeSystemInfo", "GetSystemInfo", "MoveFileWithProgressW", "CoUninitialize", "GetSystemWindowsDirectoryW", "NtQueryValueKey", "NtOpenProcess", "GetForegroundWindow", "GetFileAttributesW", "RegQueryValueExW", "NtFreeVirtualMemory", "GetVolumePathNamesForVolumeNameW", "NtMapViewOfSection", "NtCreateThreadEx", "RegEnumKeyW", "RegOpenKeyExW", "GetVolumeNameForVolumeMountPointW", "SetErrorMode", "NtResumeThread", "NtAllocateVirtualMemory", "RegOpenKeyExA", "DeleteFileW", "LdrGetDllHandle", "LdrUnloadDll", "ShellExecuteExW", "CoCreateInstance", "NtReadFile", "NtOpenFile", "GetFileSizeEx", "NtUnmapViewOfSection", "RegQueryInfoKeyW", "SetFilePointer", "GetSystemDirectoryW", "NtQueryDirectoryFile", "SHGetFolderPathW", "RegEnumKeyExW", "SetUnhandledExceptionFilter", "NtCreateFile", "GetFileAttributesExW", "GetSystemTimeAsFileTime", "FindFirstFileExW", "NtCreateMutant", "CoInitializeEx", "GetFileInformationByHandleEx", "NtCreateSection", "LoadStringW", "RegDeleteValueW", "NtOpenKey", "RegSetValueExW", "LdrGetProcedureAddress", "NtOpenThread", "CreateDirectoryW", "NtOpenDirectoryObject", "GetFileType", "LdrLoadDll", "NtTerminateProcess", "OleInitialize", "NtQueryInformationFile", "CreateProcessInternalW", "WriteConsoleW", "NtClose", "RegCreateKeyExW", "NtQueryKey", "RegQueryValueExA", "GetFileVersionInfoSizeW", "GetSystemMetrics", "RegEnumKeyExA", "CreateActCtxW", "GetFileSize", "CoGetClassObject", "CryptAcquireContextA", "CreateThread", "GlobalMemoryStatus", "GetSystemDirectoryA", "RegEnumValueW", "CoInitializeSecurity", "GetFileVersionInfoW", "GetBestInterfaceEx", "InternetOpenA", "WSAStartup", "RegCreateKeyExA", "GetAdaptersAddresses", "CopyFileW", "WriteProcessMemory", "InternetCloseHandle", "NtDelayExecution", "NtDeviceIoControlFile", "NtWriteFile", "CreateRemoteThread", "LoadStringA", "InternetReadFile", "__exception__", "NtQueryAttributesFile", "closesocket", "NtProtectVirtualMemory", "GetAddrInfoW", "setsockopt", "InternetOpenUrlA", "socket", "RegSetValueExA", "LookupPrivilegeValueW", "CoCreateInstanceEx", "IsDebuggerPresent", "IWbemServices_ExecQuery", "GetComputerNameW", "WriteConsoleA", "InternetCrackUrlW", "LookupAccountSidW", "GetComputerNameA", "EnumWindows", "FindWindowExW", "UuidCreate", "DrawTextExW", "FindResourceW", "SizeofResource", "FindResourceExW", "GetTempPathW", "GetTimeZoneInformation", "NtOpenMutant", "LoadResource", "SHGetSpecialFolderLocation", "SetFileTime", "SetFileAttributesW", "CryptProtectMemory", "NtQuerySystemInformation", "CryptAcquireContextW", "GlobalMemoryStatusEx", "SetEndOfFile", "CryptUnprotectMemory", "HttpOpenRequestA", "NtSetInformationFile", "NetShareEnum", "OpenServiceW", "InternetConnectA", "HttpSendRequestA", "OpenSCManagerW", "DeviceIoControl", "GetShortPathNameW", "RtlAddVectoredContinueHandler", "RtlAddVectoredExceptionHandler", "NtOpenKeyEx", "NtCreateKey", "MessageBoxTimeoutW", "NtEnumerateValueKey", "NtSetValueKey", "SearchPathW", "CryptEncrypt", "WSAConnect", "WSASocketW", "FindResourceA", "SendNotifyMessageW", "SetFilePointerEx", "FindWindowW", "RegDeleteKeyW", "GetKeyState", "GetCursorPos", "CreateToolhelp32Snapshot", "Process32NextW", "Process32FirstW", "GetUserNameA", "GetDiskFreeSpaceExW", "NtEnumerateKey", "OpenServiceA", "OpenSCManagerA", "NtQueryMultipleValueKey", "CryptExportKey", "HttpOpenRequestW", "InternetConnectW", "CryptGenKey", "GetUserNameW", "GetDiskFreeSpaceW", "HttpSendRequestW", "InternetOpenW", "getaddrinfo", "select", "send", "connect", "bind", "OutputDebugStringA", "FindWindowA", "GetFileInformationByHandle", "recv", "ioctlsocket", "gethostbyname", "CopyFileA", "NtReadVirtualMemory", "CryptCreateHash", "CryptHashData", "NtLoadDriver", "CopyFileExW", "ReadProcessMemory", "NtDeleteValueKey", "Module32FirstW", "Module32NextW", "NtGetContextThread", "SetWindowsHookExW", "GetAdaptersInfo", "MessageBoxTimeoutA", "FindWindowExA", "SetWindowsHookExA", "RemoveDirectoryW", "NtDeleteFile", "CryptDecodeObjectEx", "StartServiceW", "GetUserNameExA", "GetFileVersionInfoExW", "InternetGetConnectedState", "GetFileVersionInfoSizeExW", "InternetQueryOptionA", "CryptDecrypt", "timeGetTime", "DrawTextExA", "NtSetContextThread", "NtSuspendThread", "ControlService", "SetStdHandle", "RegisterHotKey", "CreateServiceW", "InternetSetOptionA", "InternetCrackUrlA", "GetAsyncKeyState", "NtDeleteKey", "FindResourceExA", "RegEnumValueA", "NetGetJoinInformation", "getsockname", "NtQueueApcThread", "listen", "accept", "NtTerminateThread", "Thread32Next", "Thread32First", "SetFileInformationByHandle", "EnumServicesStatusA", "__anomaly__", "UnhookWindowsHookEx", "ObtainUserAgentString", "StartServiceA", "IWbemServices_ExecMethod", "CryptProtectData", "EnumServicesStatusW", "sendto", "RtlDecompressBuffer", "CreateJobObjectW", "NetUserGetInfo", "DeleteService", "InternetSetStatusCallback", "CreateServiceA", "CertOpenStore", "CertControlStore", "SendNotifyMessageA", "RegQueryInfoKeyA", "SetInformationJobObject", "GetKeyboardState", "RemoveDirectoryA", "URLDownloadToFileW", "RegDeleteKeyA", "HttpQueryInfoA", "JsGlobalObjectDefaultEvalHelper", "CertOpenSystemStoreW", "RtlRemoveVectoredExceptionHandler", "NtWriteVirtualMemory", "DecryptMessage", "EncryptMessage", "shutdown", "DnsQuery_A", "DeleteUrlCacheEntryA", "CreateRemoteThreadEx", "RegDeleteValueA", "InternetOpenUrlW", "CryptUnprotectData", "system", "CertCreateCertificateContext", "AssignProcessToJobObject"]
        features = []

        if "behavior" in data:
            if "apistats" in data["behavior"]:
                for proc in data["behavior"]["apistats"]:
                    tmp = [0] * len(features_labels)
                    for key in data["behavior"]["apistats"][str(proc)].keys():
                        tmp[features_labels.index(key)] = data["behavior"]["apistats"][
                            str(proc)
                        ][key]

                    features.append(tmp)

        return pd.DataFrame(features)

    if pre == "PEIM":
        features_labels = ["ave_functions_utilised_from_dlls_imported", "bogus_functions",
                           "num_blacklisted_functions", "num_whitelisted_functions", "persistent_reg_key",
                           "num_native_functions"]
        features = []
        
        # ## Array for Feature 3 (the blacklisted functions - functions prevalent in ransomware)
        blacklisted_functions = ["WriteConsoleW", "Process32NextW", "Process32FirstW", "CreateToolhelp32Snapshot",
                                 "CoInitializeSecurity", "MoveFileWithProgressW", "CryptEncrypt", "CryptExportKey",
                                 "CryptGenKey", "CryptDeriveKey", "CryptDecodeObject", "CryptImportPublicKeyInfo",
                                 "socket", "DrawTextExW", "GetForegroundWindow"]

        # ## Array for Feature 4 (the functions that are most likely to be invoked in good-ware than in ransomware)
        whitelisted_functions = ["DeviceIoControl", "SetFileTime", "SHGetFolderPathW"]

        ratio_functions_total = 0
        ave_functions_utilised_from_dlls_imported = 0
        bogus_functions = 0
        num_blacklisted_functions = 0
        num_whitelisted_functions = 0

        persistent_reg_key = 0
        num_opened_reg_key = 0
        num_closed_reg_key = 0

        num_native_functions = 0

        if "static" in data:
            if "pe_imports" in data["static"]:

                num_imported_dlls = 0
                if "imported_dll_count" in data["static"]:
                    num_imported_dlls = data["static"]["imported_dll_count"]

                for pe_import in data["static"]["pe_imports"]:
                    # ## Feature 1
                    if num_imported_dlls > 0:
                        ratio_functions_total = ratio_functions_total + len(pe_import["imports"]) / num_imported_dlls
                    for i in pe_import["imports"]:

                        if "name" in i:
                            function_name = str(i["name"])
                            # ## Feature 2
                            if not function_name.isalpha():
                                bogus_functions = bogus_functions + 1
                            # ## Feature 3
                            if function_name.lower() in (func_name.lower() for func_name in blacklisted_functions):
                                num_blacklisted_functions = num_blacklisted_functions + 1
                            # ## Feature 4
                            if function_name.lower() in (func_name.lower() for func_name in whitelisted_functions):
                                num_whitelisted_functions = num_whitelisted_functions + 1
                            # ## Feature 5
                            if function_name.lower().startswith("regcreate"):
                                num_opened_reg_key = num_opened_reg_key + 1
                            if function_name.lower().startswith("regdelete"):
                                num_closed_reg_key = num_closed_reg_key + 1
                            # ## Feature 6
                            if function_name.lower().startswith("nt") or function_name.lower().startswith("zw"):
                                num_native_functions = num_native_functions + 1

                # ## for Feature 1
                if num_imported_dlls > 0:
                    ave_functions_utilised_from_dlls_imported = float(ratio_functions_total / num_imported_dlls)

                # ## for Feature 5
                persistent_reg_key = num_opened_reg_key - num_closed_reg_key

            features.append([float(ave_functions_utilised_from_dlls_imported), bogus_functions,
                             num_blacklisted_functions, num_whitelisted_functions, persistent_reg_key,
                             num_native_functions])                 
        return pd.DataFrame(features)

    if pre == "PEEM":
        features_labels = ["name", "entropy"]
        features = []
        
        if "static" in data:
            if "pe_sections" in data["static"]:
                for pe in data["static"]["pe_sections"]:
                    features.append([pe["name"], pe["entropy"]])    

        df = pd.DataFrame(features, columns=features_labels)
        le = joblib.load("Models/{}_{}_model.pkl".format(pre, "name"))
        df['name'] = le.transform(df['name'])

        return df
    
    if pre == "PMM":
        features_labels = ["r", "rw", "rx", "rwc", "rwx", "rwxc"]
        features = []
        
        if "procmemory" in data:
            for pm in data["procmemory"]:
                feat = {'r': 0, 'rw': 0, 'rx': 0, 'rwc': 0, 'rwx': 0, 'rwxc': 0}
                for regions in pm["regions"]:  
                    feat[regions["protect"]] = feat[regions["protect"]] + 1
                
                features.append(list(feat.values())) 
                del feat
        del data
        return pd.DataFrame(features)
    
    if pre == "ROM":
        features_labels = ["Persistant", "Backup", "PercentageKeyOpen", "PercentageKeyClosed", "PercentageCreated", "PercentageKeyUnique"]    
        
        features = []
        
        stats = {
            "open": [],
            "close": [],
            "count": 1,
            "keys": [],
            "create": []
        }
        
        if "behavior" in data:
            if "processes" in data["behavior"]:
                for proc in data["behavior"]["processes"]:
                    for call in proc["calls"]: 
                        if call["category"] == "registry":
                            try:
                                stats["count"] = stats["count"] + 1
                                if "open" in call["api"].lower():
                                    stats["open"].append(call["arguments"]["regkey"])
                                if "close" in call["api"].lower():
                                    stats["close"].append(call["arguments"]["regkey"])
                                if "create" in call["api"].lower():
                                    stats["create"].append(call["arguments"]["regkey"])
                                try:
                                    stats["keys"].append(call["arguments"]["regkey"])
                                except:
                                    continue
                            except:
                                continue
            persistant = 0
            backup = 0
            ko = 0
            kc = 0
            ku = 0
            kcc = 0

            for k in stats["keys"]:
                if "run" in k.lower():
                    persistant = persistant + 1
                if "service" in k.lower():
                    persistant = persistant + 1
                if "restore" in k.lower():
                    backup = backup + 1

            ko = round((len(stats["open"]) / stats["count"])*100)
            kc = round((len(stats["close"]) / stats["count"])*100)
            kcc = round((len(stats["create"]) / stats["count"])*100)
            ku = round((len(list(set(stats["keys"]))) / stats["count"])*100)

            features.append([persistant, backup, ko, kc, kcc, ku])
        return pd.DataFrame(features)

    if pre == "FOM":
        analysis_dictionary = {}
        analysis_dictionary["stats"] = {}
        analysis_dictionary["summary"] = {}

        if "behavior" in data:

            if "summary" in data["behavior"]:

                if "file_deleted" in data["behavior"]["summary"]:
                    analysis_dictionary["summary"]["file_deleted"] = {}
                    analysis_dictionary["summary"]["file_deleted"]["data"] = data["behavior"]["summary"]["file_deleted"]
                    analysis_dictionary["summary"]["file_deleted"]["total"] = len(data["behavior"]["summary"]["file_deleted"])
                    analysis_dictionary["summary"]["file_deleted"]["uniqueTotal"] = len(list(set(data["behavior"]["summary"]["file_deleted"])))
                if "file_created" in data["behavior"]["summary"]:
                    analysis_dictionary["summary"]["file_created"] = {}
                    analysis_dictionary["summary"]["file_created"]["data"] = data["behavior"]["summary"]["file_created"]
                    analysis_dictionary["summary"]["file_created"]["total"] = len(data["behavior"]["summary"]["file_created"])
                    analysis_dictionary["summary"]["file_created"]["uniqueTotal"] = len(list(set(data["behavior"]["summary"]["file_created"])))
                if "file_recreated" in data["behavior"]["summary"]:
                    analysis_dictionary["summary"]["file_recreated"] = {}
                    analysis_dictionary["summary"]["file_recreated"]["data"] = data["behavior"]["summary"]["file_recreated"]
                    analysis_dictionary["summary"]["file_recreated"]["total"] = len(data["behavior"]["summary"]["file_recreated"])
                    analysis_dictionary["summary"]["file_recreated"]["uniqueTotal"] = len(list(set(data["behavior"]["summary"]["file_recreated"])))
                if "directory_created" in data["behavior"]["summary"]:
                    analysis_dictionary["summary"]["directory_created"] = {}
                    analysis_dictionary["summary"]["directory_created"]["data"] = data["behavior"]["summary"]["directory_created"]
                    analysis_dictionary["summary"]["directory_created"]["total"] = len(data["behavior"]["summary"]["directory_created"])
                    analysis_dictionary["summary"]["directory_created"]["uniqueTotal"] = len(list(set(data["behavior"]["summary"]["directory_created"])))
                if "file_opened" in data["behavior"]["summary"]:
                    analysis_dictionary["summary"]["file_opened"] = {}
                    analysis_dictionary["summary"]["file_opened"]["data"] = data["behavior"]["summary"]["file_opened"]
                    analysis_dictionary["summary"]["file_opened"]["total"] = len(data["behavior"]["summary"]["file_opened"])
                    analysis_dictionary["summary"]["file_opened"]["uniqueTotal"] = len(list(set(data["behavior"]["summary"]["file_opened"])))
                if "file_copied" in data["behavior"]["summary"]:
                    analysis_dictionary["summary"]["file_copied"] = {}
                    analysis_dictionary["summary"]["file_copied"]["data"] = data["behavior"]["summary"]["file_copied"]
                    analysis_dictionary["summary"]["file_copied"]["total"] = len(data["behavior"]["summary"]["file_copied"])
                    analysis_dictionary["summary"]["file_copied"]["uniqueTotal"] = len(list(set(data["behavior"]["summary"]["file_copied"])))
                if "file_moved" in data["behavior"]["summary"]:
                    analysis_dictionary["summary"]["file_moved"] = {}
                    analysis_dictionary["summary"]["file_moved"]["data"] = data["behavior"]["summary"]["file_moved"]
                    analysis_dictionary["summary"]["file_moved"]["total"] = len(data["behavior"]["summary"]["file_moved"])
                    analysis_dictionary["summary"]["file_moved"]["uniqueTotal"] = len(list(set(data["behavior"]["summary"]["file_moved"])))
                if "file_written" in data["behavior"]["summary"]:
                    analysis_dictionary["summary"]["file_written"] = {}
                    analysis_dictionary["summary"]["file_written"]["data"] = data["behavior"]["summary"]["file_written"]
                    analysis_dictionary["summary"]["file_written"]["total"] = len(data["behavior"]["summary"]["file_written"])
                    analysis_dictionary["summary"]["file_written"]["uniqueTotal"] = len(list(set(data["behavior"]["summary"]["file_written"])))
                if "file_exists" in data["behavior"]["summary"]:
                    analysis_dictionary["summary"]["file_exists"] = {}
                    analysis_dictionary["summary"]["file_exists"]["data"] = data["behavior"]["summary"]["file_exists"]
                    analysis_dictionary["summary"]["file_exists"]["total"] = len(data["behavior"]["summary"]["file_exists"])
                    analysis_dictionary["summary"]["file_exists"]["uniqueTotal"] = len(list(set(data["behavior"]["summary"]["file_exists"])))
                if "file_read" in data["behavior"]["summary"]:
                    analysis_dictionary["summary"]["file_read"] = {}
                    analysis_dictionary["summary"]["file_read"]["data"] = data["behavior"]["summary"]["file_read"]
                    analysis_dictionary["summary"]["file_read"]["total"] = len(data["behavior"]["summary"]["file_read"])
                    analysis_dictionary["summary"]["file_read"]["uniqueTotal"] = len(list(set(data["behavior"]["summary"]["file_read"])))
                if "directory_enumerated" in data["behavior"]["summary"]:
                    analysis_dictionary["summary"]["directory_enumerated"] = {}
                    analysis_dictionary["summary"]["directory_enumerated"]["data"] = data["behavior"]["summary"]["directory_enumerated"]
                    analysis_dictionary["summary"]["directory_enumerated"]["total"] = len(data["behavior"]["summary"]["directory_enumerated"])
                    analysis_dictionary["summary"]["directory_enumerated"]["uniqueTotal"] = len(list(set(data["behavior"]["summary"]["directory_enumerated"])))

            if "processes" in data["behavior"]:
                for proc in data["behavior"]["processes"]:
                    if "calls" in proc:
                        for call in proc["calls"]:

                            if 'time' in call:
                                if "timeOfCall" not in analysis_dictionary['stats']:
                                    analysis_dictionary['stats']['timeOfCall'] = [call['time']]
                                else:
                                    analysis_dictionary['stats']['timeOfCall'].append(call['time'])

                            if "totalAPICalls" not in analysis_dictionary['stats']:
                                analysis_dictionary['stats']['totalAPICalls'] = 1
                            else:
                                analysis_dictionary['stats']['totalAPICalls'] = analysis_dictionary['stats']['totalAPICalls'] + 1

                            if "category" in call:
                                if call["category"] == "file":

                                    if "totalFileCategoryAPICalls" not in analysis_dictionary['stats']:
                                        analysis_dictionary['stats']['totalFileCategoryAPICalls'] = 1
                                    else:
                                        analysis_dictionary['stats']['totalFileCategoryAPICalls'] = analysis_dictionary['stats']['totalFileCategoryAPICalls'] + 1

                                    if "api" in call:

                                        if "fileAPICalls" not in analysis_dictionary:
                                            analysis_dictionary['fileAPICalls'] = {}

                                        if call['api'] not in analysis_dictionary['fileAPICalls']:
                                            analysis_dictionary['fileAPICalls'][call["api"]] = 1
                                        else:
                                            analysis_dictionary['fileAPICalls'][call["api"]] = analysis_dictionary['fileAPICalls'][call["api"]] + 1

                            if 'uniqueFiles' not in analysis_dictionary:
                                analysis_dictionary['uniqueFiles'] = {}

                            if 'uniqueFilesTotal' not in analysis_dictionary:
                                analysis_dictionary['uniqueFilesTotal'] = 0

                            if 'uniqueFileExtensions' not in analysis_dictionary:
                                analysis_dictionary['uniqueFileExtensions'] = {}

                            if 'uniqueFileExtensionsTotal' not in analysis_dictionary:
                                analysis_dictionary['uniqueFileExtensionsTotal'] = 0

                            if 'uniqueFileLocations' not in analysis_dictionary:
                                analysis_dictionary['uniqueFileLocations'] = {}

                            if 'uniqueFileLocationsTotal' not in analysis_dictionary:
                                analysis_dictionary['uniqueFileLocationsTotal'] = 0

                            if 'arguments' in call:
                                if 'filepath' in call['arguments']:

                                    filePath = call['arguments']['filepath']
                                    file = filePath.split('\\')[-1]
                                    filePathExludingFileName = filePath.rsplit('\\', 1)[0]
                                    fileSplit = file.split('.')
                                    if len(fileSplit) >= 2:
                                        fileName = ''.join(fileSplit[:-1]) 
                                        fileExtension = fileSplit[-1]

                                        if fileName not in analysis_dictionary['uniqueFiles']:
                                            analysis_dictionary['uniqueFiles'][fileName] = 1
                                            analysis_dictionary['uniqueFilesTotal'] = analysis_dictionary['uniqueFilesTotal'] + 1
                                        else:
                                            analysis_dictionary['uniqueFiles'][fileName] = analysis_dictionary['uniqueFiles'][fileName] +1
                                            analysis_dictionary['uniqueFilesTotal'] = analysis_dictionary['uniqueFilesTotal'] + 1

                                        if fileExtension not in analysis_dictionary['uniqueFileExtensions']:
                                            analysis_dictionary['uniqueFileExtensions'][fileExtension] = 1
                                            analysis_dictionary['uniqueFileExtensionsTotal'] = analysis_dictionary['uniqueFileExtensionsTotal'] + 1
                                        else:
                                            analysis_dictionary['uniqueFileExtensions'][fileExtension] = analysis_dictionary['uniqueFileExtensions'][fileExtension] +1
                                            analysis_dictionary['uniqueFileExtensionsTotal'] = analysis_dictionary['uniqueFileExtensionsTotal'] + 1

                                        if filePathExludingFileName not in analysis_dictionary['uniqueFileLocations']:
                                            analysis_dictionary['uniqueFileLocations'][filePathExludingFileName] = 1
                                            analysis_dictionary['uniqueFileLocationsTotal'] = analysis_dictionary['uniqueFileLocationsTotal'] + 1
                                        else:
                                            analysis_dictionary['uniqueFileLocations'][filePathExludingFileName] = analysis_dictionary['uniqueFileLocations'][filePathExludingFileName] +1
                                            analysis_dictionary['uniqueFileLocationsTotal'] = analysis_dictionary['uniqueFileLocationsTotal'] + 1

                            # ***********************************************************************************

# ------------------------------------------------------------------------------------------------------------------------------------------------------------
# ------------------------------------------------------------------------------------------------------------------------------------------------------------

        totalFileCategoryAPICalls = 0 if "totalFileCategoryAPICalls" not in analysis_dictionary['stats'] else analysis_dictionary['stats']['totalFileCategoryAPICalls']

        knownExtensions = {
            "documents": [".123",".602",".abw",".accdb",".doc",".docm",".docx",".dot",".dotm",".dotx",".eps",".fb2",".htm",".html",".lrf",".mobi",".odc",".odf",".odg",".odi",".odm",".odp",".ods",".odt",".otg",".oth",".otp",".ots",".ott",".pdb",".pdf",".pot",".potm",".potx",".pps",".ppsx",".ppt",".pptm",".pptx",".ps",".pub",".qpw",".rtf",".sdc",".sdd",".sdw",".sgml",".sla",".slk",".stw",".sxg",".sxi",".sxm",".sxw",".txt",".uop",".uot",".uof",".wdb",".wks",".wpd",".wps",".xhtml",".xml",".xps",".xwp",".csv",".tsv",".ods",".xls",".xlsm",".xlsx",".xlt",".xltm",".xltx",".ods",".numbers",".odg",".pub",".md",".epub",".key",".odt",".sxi",".tex",".wpd",".pages",".txt",".rtf"],
            "images": [".ai",".bmp",".cdr",".cmx",".djvu",".eps",".gif",".ico",".jpeg",".jpg",".png",".ps",".psd",".svg",".tif",".tiff",".wmf",".xbm",".xpm",".webp",".tga",".dds",".j2k",".jfif",".jif",".jpe",".jfif-tbnl",".jpeg-tbnl",".jpg-tbnl",".jpe-tbnl",".jpg-large",".png-large",".webp-large",".gif-large",".jpeg-large",".jpg-large",".raw"],
            "videos": [".3g2",".3gp",".amv",".asf",".avi",".drc",".flv",".flv",".flv",".flv",".flv",".gifv",".m2v",".m4p",".m4v",".mkv",".mkv",".mng",".mov",".mp2",".mp4",".mpe",".mpeg",".mpg",".mpv",".mvv",".ogv",".qt",".rm",".rmvb",".roq",".srt",".svi",".swf",".vob",".webm",".wmv",".yuv"],
            "audio": [".3ga",".aac",".ac3",".aif",".aiff",".amr",".ape",".au",".awb",".dct",".dss",".dvf",".flac",".gsm",".iklax",".ivs",".m4a",".m4b",".m4p",".m4r",".mmf",".mp3",".mpc",".msv",".nmf",".nsf",".ogg",".oga",".mogg",".opus",".ra",".rm",".rmvb",".sln",".tta",".vox",".wav",".wma",".wv",".webm"],
            "databases": [".accdb",".db",".db3",".dbf",".fdb",".gdb",".ldf",".mdf",".mdb",".mde",".myd",".nsf",".odb",".pouch",".pdb",".sdb",".sql",".sqlite",".sqlite3",".xdb",".ydb"],
            "archives": [".001",".7z",".ace",".alz",".arc",".arj",".bz",".bz2",".cab",".cfs",".chm",".cpio",".cpt",".csh",".dar",".dd",".dgc",".dmg",".ear",".gz",".hqx",".ice",".jar",".kgb",".lbr",".lha",".lzh",".lzx",".mhtml",".mie",".pak",".paq6",".paq7",".paq8",".par",".par2",".pea",".pim",".pit",".qda",".rar",".rk",".sda",".sea",".sen",".sfark",".sfx",".shar",".sit",".sitx",".sqx",".tar",".tbz2",".tgz",".tlz",".tz",".uha",".uue",".war",".wim",".xar",".xp3",".xz",".yz1",".z",".zip",".zipx",".zoo",".zpaq",".zz"],
            "executable": [".apk",".app",".bat",".bin",".cmd",".com",".cpl",".dll",".exe",".gadget",".hta",".inf",".ins",".inx",".ipa",".isu",".jar",".js",".jse",".lnk",".msc",".msi",".msp",".mst",".osx",".out",".paf",".pif",".prc",".ps1",".reg",".rgs",".run",".scr",".sct",".shb",".shs",".u3p",".vb",".vbe",".vbs",".vbscript",".ws",".wsf",".wsh"],
            "system": [".386",".admx",".appx",".bak",".bak1",".bak2",".bak3",".bak4",".bat",".bin",".cab",".cat",".cfg",".cpl",".cur",".dll",".dmp",".drv",".grp",".icns",".ico",".ini",".job",".key",".lnk",".log",".man",".mgr",".msc",".msi",".msp",".mui",".nfo",".ocx",".pdb",".pif",".pl",".pm",".pol",".pps",".prf",".ps1",".reg",".rgs",".scr",".sys",".tff",".ttf",".wpl"],
            "backup": [".bak",".backup",".bu",".old",".orig",".temp",".tmp",".swp",".swo",".swn",".swo",".1st",".0",".1",".2",".3",".4",".5",".6",".7",".8",".9",".001",".002",".003",".004",".005",".006",".007",".008",".009",".0010",".0011",".0012",".0013",".0014",".0015",".0016",".0017",".0018",".0019",".0020",".0021",".0022",".0023",".0024",".0025",".0026",".0027",".0028",".0029",".0030",".0031",".0032",".0033",".0034",".0035",".0036",".0037",".0038",".0039",".0040",".0041",".0042",".0043",".0044",".0045",".0046",".0047",".0048",".0049",".0050",".0051",".0052",".0053",".0054",".0055",".0056",".0057",".0058",".0059",".0060",".0061",".0062",".0063",".0064",".0065",".0066",".0067",".0068",".0069",".0070",".0071",".0072",".0073",".0074",".0075",".0076",".0077",".0078",".0079",".0080",".0081",".0082",".0083",".0084",".0085",".0086",".0087",".0088",".0089",".0090",".0091",".0092",".0093",".0094",".0095",".0096",".0097",".0098",".0099",".01",".02",".03",".04",".05",".06",".07",".08",".09",".001",".002",".003",".004",".005",".006",".007",".008",".009"],
            "virtualMachine": [".vmx",".vbox",".vdi",".vhd",".qcow2",".ova",".vmsd",".vmtm",".vswp",".nvram"],
            "email": [".dbx",".eml",".emlx",".mbox",".msg",".pst",".ost",".mbx",".tbb",".mht",".nws",".tnef"],
            "games": [".sav",".cfg",".ini",".pak",".wad",".gam",".nes",".snes",".gen",".gba",".n64",".d64",".rom",".iso",".bin",".cue",".cso",".chd",".gdi",".cdi",".elf",".prx",".nds",".3ds",".chm",".dat",".rez",".map",".m3u",".xm",".mod",".s3m",".it",".adlib",".mus",".xma",".mpq",".bb",".ddraw",".voi",".aoe",".bar",".mpk",".w3g",".dol",".bgl",".ttf",".bik",".bik2",".pss",".blk",".bmd",".blp",".brres",".dem",".dem2",".dem3",".dem4",".dmo",".elf",".epk",".ezs",".fsb",".gbs",".gsb",".gsc",".gsm",".h4m",".ilm",".kra",".l3d",".l3p",".l3t",".lpk",".lst",".m3p",".m3s",".m4a",".m4b",".m4s",".m4v",".mgz",".mmp",".mps",".mpp",".nmp",".nut",".omod",".osu",".osz",".p8",".p8.png",".pk3",".pk4",".pk5",".pk6",".pk7",".pk8",".pk9",".pke",".pkg",".pkh",".pkk",".pkm",".pko",".pkp",".pkr",".pks",".pkt",".pku",".pkv",".pkw",".pkx",".pky",".pkz",".plr",".plz",".rez",".res",".rgd",".rkv",".rom",".rpz",".rrk",".rtb",".rvdata2",".rwdata",".rxdata",".sbk",".sbl",".sdb",".sdg",".sdl",".sdw",".sep",".sgc",".sgh",".shc",".slc",".snd",".snd0",".sndt",".sndx",".snp",".sod",".sof",".ssf",".ssg",".ssf",".ssg",".sso",".sst",".sts",".szt",".tem",".ucl",".udk",".umap",".umx",".unr",".unx",".unx",".uop",".usa",".usm",".utr",".v64",".vl2",".vpk",".w3x",".wad",".wdl",".wfav",".wgp",".wl6",".wlk",".wmo",".x2m",".xma",".xp3",".xxx",".ydk",".ydr",".ypt",".z64"],
            "development": [".c",".cpp",".h",".hpp",".java",".py",".cs",".html",".css",".js",".php",".rb",".swift",".go",".perl",".sql",".json",".xml",".yaml",".ini",".cfg",".md",".txt",".log",".gitignore",".dockerignore",".bat",".sh",".ps1",".makefile",".yml",".conf",".properties",".gradle",".classpath",".project",".sln",".vcxproj",".suo",".dll",".lib",".obj",".o",".a",".so",".exe",".app",".ipa",".apk",".jar",".war",".ear",".class",".dmg",".pkg",".deb",".rpm",".tar.gz",".zip",".7z",".rar",".bz2",".gz",".tar",".tar.bz2",".tar.xz",".img",".iso",".vhd",".vhdx",".vdi",".vmdk",".bak",".swp",".swo",".swn",".swo",".old",".bak",".orig",".backup",".temp",".tmp",".cache",".test",".bak1",".bak2",".bak3",".bu"]
        }

        analysis_dictionary["fileLocationCounter"] = {
            "Documents": 0,
            "Pictures": 0,
            "Music": 0,
            "Videos": 0,
            "Desktop": 0,
            "Downloads": 0,
            "Other": 0
        }

        if "uniqueFileLocations" in analysis_dictionary:
            for val in analysis_dictionary['uniqueFileLocations']:
                if "Documents" in val:
                    analysis_dictionary["fileLocationCounter"]["Documents"] = analysis_dictionary["fileLocationCounter"]["Documents"] + analysis_dictionary['uniqueFileLocations'][val]
                elif "Pictures" in val:
                    analysis_dictionary["fileLocationCounter"]["Pictures"] = analysis_dictionary["fileLocationCounter"]["Pictures"] + analysis_dictionary['uniqueFileLocations'][val]
                elif "Music" in val:
                    analysis_dictionary["fileLocationCounter"]["Music"] = analysis_dictionary["fileLocationCounter"]["Music"] + analysis_dictionary['uniqueFileLocations'][val]
                elif "Videos" in val:
                    analysis_dictionary["fileLocationCounter"]["Videos"] = analysis_dictionary["fileLocationCounter"]["Videos"] + analysis_dictionary['uniqueFileLocations'][val]
                elif "Desktop" in val:
                    analysis_dictionary["fileLocationCounter"]["Desktop"] = analysis_dictionary["fileLocationCounter"]["Desktop"] + analysis_dictionary['uniqueFileLocations'][val]
                elif "Downloads" in val:
                    analysis_dictionary["fileLocationCounter"]["Downloads"] = analysis_dictionary["fileLocationCounter"]["Downloads"] + analysis_dictionary['uniqueFileLocations'][val]
                else:
                    analysis_dictionary["fileLocationCounter"]["Other"] = analysis_dictionary["fileLocationCounter"]["Other"] + analysis_dictionary['uniqueFileLocations'][val]

        timeDiff = 0
        if "timeOfCall" in analysis_dictionary["stats"]:
            analysis_dictionary["stats"]["timeOfCall"].sort()
            timeDiff = analysis_dictionary["stats"]["timeOfCall"][-1] - analysis_dictionary["stats"]["timeOfCall"][1]

        analysis_dictionary["fileExtensionsCounter"] = {
            "documents": 0,
            "images": 0,
            "videos": 0,
            "audio": 0,
            "databases": 0,
            "archives": 0,
            "executable": 0,
            "system": 0,
            "backup": 0,
            "virtualMachine": 0,
            "email": 0,
            "games": 0,
            "development": 0,
            "unknown": 0
        }

        if "uniqueFileExtensions" in analysis_dictionary:
            for val in analysis_dictionary['uniqueFileExtensions']:
                if "."+val in knownExtensions['documents']:
                    analysis_dictionary["fileExtensionsCounter"]["documents"] = analysis_dictionary["fileExtensionsCounter"]["documents"] + analysis_dictionary['uniqueFileExtensions'][val]
                elif "."+val in knownExtensions['images']:
                    analysis_dictionary["fileExtensionsCounter"]["images"] = analysis_dictionary["fileExtensionsCounter"]["images"] + analysis_dictionary['uniqueFileExtensions'][val]
                elif "."+val in knownExtensions['videos']:
                    analysis_dictionary["fileExtensionsCounter"]["videos"] = analysis_dictionary["fileExtensionsCounter"]["videos"] + analysis_dictionary['uniqueFileExtensions'][val]
                elif "."+val in knownExtensions['audio']:
                    analysis_dictionary["fileExtensionsCounter"]["audio"] = analysis_dictionary["fileExtensionsCounter"]["audio"] + analysis_dictionary['uniqueFileExtensions'][val]
                elif "."+val in knownExtensions['databases']:
                    analysis_dictionary["fileExtensionsCounter"]["databases"] = analysis_dictionary["fileExtensionsCounter"]["databases"] + analysis_dictionary['uniqueFileExtensions'][val]
                elif "."+val in knownExtensions['archives']:
                    analysis_dictionary["fileExtensionsCounter"]["archives"] = analysis_dictionary["fileExtensionsCounter"]["archives"] + analysis_dictionary['uniqueFileExtensions'][val]
                elif "."+val in knownExtensions['executable']:
                    analysis_dictionary["fileExtensionsCounter"]["executable"] = analysis_dictionary["fileExtensionsCounter"]["executable"] + analysis_dictionary['uniqueFileExtensions'][val]
                elif "."+val in knownExtensions['system']:
                    analysis_dictionary["fileExtensionsCounter"]["system"] = analysis_dictionary["fileExtensionsCounter"]["system"] + analysis_dictionary['uniqueFileExtensions'][val]
                elif "."+val in knownExtensions['backup']:
                    analysis_dictionary["fileExtensionsCounter"]["backup"] = analysis_dictionary["fileExtensionsCounter"]["backup"] + analysis_dictionary['uniqueFileExtensions'][val]
                elif "."+val in knownExtensions['virtualMachine']:
                    analysis_dictionary["fileExtensionsCounter"]["virtualMachine"] = analysis_dictionary["fileExtensionsCounter"]["virtualMachine"] + analysis_dictionary['uniqueFileExtensions'][val]
                elif "."+val in knownExtensions['email']:
                    analysis_dictionary["fileExtensionsCounter"]["email"] = analysis_dictionary["fileExtensionsCounter"]["email"] + analysis_dictionary['uniqueFileExtensions'][val]
                elif "."+val in knownExtensions['games']:
                    analysis_dictionary["fileExtensionsCounter"]["games"] = analysis_dictionary["fileExtensionsCounter"]["games"] + analysis_dictionary['uniqueFileExtensions'][val]
                elif "."+val in knownExtensions['development']:
                    analysis_dictionary["fileExtensionsCounter"]["development"] = analysis_dictionary["fileExtensionsCounter"]["development"] + analysis_dictionary['uniqueFileExtensions'][val]
                else:
                    analysis_dictionary["fileExtensionsCounter"]["unknown"] = analysis_dictionary["fileExtensionsCounter"]["unknown"] + analysis_dictionary['uniqueFileExtensions'][val]

#************************************************************************************************************************************************************
#************************************************************************************************************************************************************

#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

        # default values

        F1_totalAPICalls = 0
        F2_percentageOfFileAPICalls = 0
        F4_percentageOfUniqueFilesTouched = 0
        F5_percentageOfUniqueFileExtensionsTouched = 0
        F6_percentageOfUniqueFileLocationsTouched = 0
        F7_1_percentgeOfFileExtensionPy = 0
        F7_2_percentgeOfFileExtensionPng = 0
        F7_3_percentgeOfFileExtensionTxt = 0
        F7_4_percentgeOfFileExtensionTlc = 0
        F7_5_percentgeOfFileExtensionMsg = 0
        F7_6_percentgeOfFileExtensionExe = 0
        F7_7_percentageOfFileExtensionDll = 0
        F9_APICallsPerSecond = 0
        F10_percentageOfPotentialCustomExtensionsUsed = 0
        F11_1_percentageOfFileExtensionsDocuments = 0
        F11_2_percentageOfFileExtensionsImages = 0
        F11_3_percentageOfFileExtensionsVideos = 0
        F11_4_percentageOfFileExtensionsAudio = 0
        F11_5_percentageOfFileExtensionsDatabase = 0
        F11_6_percentageOfFileExtensionsArchives = 0
        F11_7_percentageOfFileExtensionsExecutables = 0
        F11_8_percentageOfFileExtensionsSystem = 0
        F11_9_percentageOfFileExtensionsBackup = 0
        F11_10_percentageOfFileExtensionsEmail = 0
        F11_11_percentageOfFileExtensionsVMImages = 0
        F11_12_percentageOfFileExtensionsGames = 0
        F11_13_percentageOfFileExtensionsDevelopment = 0

#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

        features_labels = [
                           "PercentageOfFileAPICalls",
                           "PercentageOfUniqueFiles",
                           "PercentageOfUniqueFileLocations",
                           "PercentageOfUniqueFileExtensions",
                           "PercentageOfPotentialCustomExtensions",
                           "PercentageOfRansomwareExtensions",
                           "PercentageOfFileExtensionsDocuments", "PercentageOfFileExtensionsImages", "PercentageOfFileExtensionsVideos", "PercentageOfFileExtensionsAudio", "PercentageOfFileExtensionsDatabase","PercentageOfFileExtensionsArchives","PercentageOfFileExtensionsExecutables","PercentageOfFileExtensionsSystem", "PercentageOfFileExtensionsBackup","PercentageOfFileExtensionsEmail", "PercentageOfFileExtensionsVMImages","PercentageOfFileExtensionsGames","PercentageOfFileExtensionsDevelopment",
                           "APICallsPerSecond"
                           ]
        features = []

        F1_totalAPICalls = 0 if "totalAPICalls" not in analysis_dictionary['stats'] else analysis_dictionary['stats']['totalAPICalls']

        F2_percentageOfFileAPICalls = 0 if F1_totalAPICalls == 0 else round((totalFileCategoryAPICalls / F1_totalAPICalls) * 100)

        if "uniqueFiles" in analysis_dictionary and "uniqueFilesTotal" in analysis_dictionary and analysis_dictionary['uniqueFilesTotal'] != 0:
            F4_percentageOfUniqueFilesTouched = round((len(analysis_dictionary['uniqueFiles']) / analysis_dictionary['uniqueFilesTotal']) * 100)
        if "uniqueFileExtensions" in analysis_dictionary and "uniqueFileExtensionsTotal" in analysis_dictionary and analysis_dictionary['uniqueFileExtensionsTotal'] != 0:
            F5_percentageOfUniqueFileExtensionsTouched = round((len(analysis_dictionary['uniqueFileExtensions']) / analysis_dictionary['uniqueFileExtensionsTotal']) * 100)
        if "uniqueFiles" in analysis_dictionary and "uniqueFilesTotal" in analysis_dictionary and analysis_dictionary['uniqueFilesTotal'] != 0:
            F6_percentageOfUniqueFileLocationsTouched = round((len(analysis_dictionary['uniqueFiles']) / analysis_dictionary['uniqueFilesTotal']) * 100)

        if "uniqueFileExtensions" in analysis_dictionary and "uniqueFileExtensionsTotal" in analysis_dictionary and analysis_dictionary['uniqueFileExtensionsTotal'] != 0:
            F7_1_percentgeOfFileExtensionPy = 0 if 'py' not in analysis_dictionary['uniqueFileExtensions'] else round((analysis_dictionary['uniqueFileExtensions']['py'] / analysis_dictionary['uniqueFileExtensionsTotal']) * 100)
            F7_2_percentgeOfFileExtensionPng = 0 if 'png' not in analysis_dictionary['uniqueFileExtensions'] else round((analysis_dictionary['uniqueFileExtensions']['png'] / analysis_dictionary['uniqueFileExtensionsTotal']) * 100)
            F7_3_percentgeOfFileExtensionTxt = 0 if 'txt' not in analysis_dictionary['uniqueFileExtensions'] else round((analysis_dictionary['uniqueFileExtensions']['txt'] / analysis_dictionary['uniqueFileExtensionsTotal']) * 100)
            F7_4_percentgeOfFileExtensionTlc = 0 if 'tlc' not in analysis_dictionary['uniqueFileExtensions'] else round((analysis_dictionary['uniqueFileExtensions']['tlc'] / analysis_dictionary['uniqueFileExtensionsTotal']) * 100)
            F7_5_percentgeOfFileExtensionMsg = 0 if 'msg' not in analysis_dictionary['uniqueFileExtensions'] else round((analysis_dictionary['uniqueFileExtensions']['msg'] / analysis_dictionary['uniqueFileExtensionsTotal']) * 100)
            F7_6_percentgeOfFileExtensionExe = 0 if 'exe' not in analysis_dictionary['uniqueFileExtensions'] else round((analysis_dictionary['uniqueFileExtensions']['exe'] / analysis_dictionary['uniqueFileExtensionsTotal']) * 100)
            F7_7_percentageOfFileExtensionDll = 0 if 'dll' not in analysis_dictionary['uniqueFileExtensions'] else round((analysis_dictionary['uniqueFileExtensions']['dll'] / analysis_dictionary['uniqueFileExtensionsTotal']) * 100)

        if "stats" in analysis_dictionary and "timeOfCall" in analysis_dictionary["stats"] and timeDiff != 0:
            F9_APICallsPerSecond = round((len(analysis_dictionary["stats"]["timeOfCall"]) / timeDiff))

        if "fileExtensionsCounter" in analysis_dictionary and "uniqueFileExtensionsTotal" in analysis_dictionary and analysis_dictionary['uniqueFileExtensionsTotal'] != 0:
            F10_percentageOfPotentialCustomExtensionsUsed = round((analysis_dictionary["fileExtensionsCounter"]["unknown"] / analysis_dictionary['uniqueFileExtensionsTotal']) * 100)

        if "fileExtensionsCounter" in analysis_dictionary and "uniqueFileExtensionsTotal" in analysis_dictionary and analysis_dictionary['uniqueFileExtensionsTotal'] != 0:
            F11_1_percentageOfFileExtensionsDocuments = round((analysis_dictionary["fileExtensionsCounter"]["documents"] / analysis_dictionary['uniqueFileExtensionsTotal']) * 100)
            F11_2_percentageOfFileExtensionsImages = round((analysis_dictionary["fileExtensionsCounter"]["images"] / analysis_dictionary['uniqueFileExtensionsTotal']) * 100)
            F11_3_percentageOfFileExtensionsVideos = round((analysis_dictionary["fileExtensionsCounter"]["videos"] / analysis_dictionary['uniqueFileExtensionsTotal']) * 100)
            F11_4_percentageOfFileExtensionsAudio = round((analysis_dictionary["fileExtensionsCounter"]["audio"] / analysis_dictionary['uniqueFileExtensionsTotal']) * 100)
            F11_5_percentageOfFileExtensionsDatabase = round((analysis_dictionary["fileExtensionsCounter"]["databases"] / analysis_dictionary['uniqueFileExtensionsTotal']) * 100)
            F11_6_percentageOfFileExtensionsArchives = round((analysis_dictionary["fileExtensionsCounter"]["archives"] / analysis_dictionary['uniqueFileExtensionsTotal']) * 100)
            F11_7_percentageOfFileExtensionsExecutables = round((analysis_dictionary["fileExtensionsCounter"]["executable"] / analysis_dictionary['uniqueFileExtensionsTotal']) * 100)
            F11_8_percentageOfFileExtensionsSystem = round((analysis_dictionary["fileExtensionsCounter"]["system"] / analysis_dictionary['uniqueFileExtensionsTotal']) * 100)
            F11_9_percentageOfFileExtensionsBackup = round((analysis_dictionary["fileExtensionsCounter"]["backup"] / analysis_dictionary['uniqueFileExtensionsTotal']) * 100)
            F11_10_percentageOfFileExtensionsEmail = round((analysis_dictionary["fileExtensionsCounter"]["virtualMachine"] / analysis_dictionary['uniqueFileExtensionsTotal']) * 100)
            F11_11_percentageOfFileExtensionsVMImages = round((analysis_dictionary["fileExtensionsCounter"]["email"] / analysis_dictionary['uniqueFileExtensionsTotal']) * 100)
            F11_12_percentageOfFileExtensionsGames = round((analysis_dictionary["fileExtensionsCounter"]["games"] / analysis_dictionary['uniqueFileExtensionsTotal']) * 100)
            F11_13_percentageOfFileExtensionsDevelopment = round((analysis_dictionary["fileExtensionsCounter"]["development"] / analysis_dictionary['uniqueFileExtensionsTotal']) * 100)

        RansomwareExtensions = round((F7_1_percentgeOfFileExtensionPy + F7_2_percentgeOfFileExtensionPng + F7_3_percentgeOfFileExtensionTxt + F7_4_percentgeOfFileExtensionTlc + F7_5_percentgeOfFileExtensionMsg + F7_6_percentgeOfFileExtensionExe + F7_7_percentageOfFileExtensionDll ) / 7)
        
        features.append([
                         F2_percentageOfFileAPICalls,
                         F4_percentageOfUniqueFilesTouched,
                         F6_percentageOfUniqueFileLocationsTouched,
                         F5_percentageOfUniqueFileExtensionsTouched,
                         F10_percentageOfPotentialCustomExtensionsUsed,
                         RansomwareExtensions,
                         F11_1_percentageOfFileExtensionsDocuments, F11_2_percentageOfFileExtensionsImages, F11_3_percentageOfFileExtensionsVideos, F11_4_percentageOfFileExtensionsAudio, F11_5_percentageOfFileExtensionsDatabase, F11_6_percentageOfFileExtensionsArchives, F11_7_percentageOfFileExtensionsExecutables, F11_8_percentageOfFileExtensionsSystem, F11_9_percentageOfFileExtensionsBackup, F11_10_percentageOfFileExtensionsEmail, F11_11_percentageOfFileExtensionsVMImages, F11_12_percentageOfFileExtensionsGames, F11_13_percentageOfFileExtensionsDevelopment,
                         F9_APICallsPerSecond
                         ]
                        )             
        
        return pd.DataFrame(features)

    if pre == "PSMTFIDF":
        features_labels = ["strings"]
        features = []
        
        if "strings" in data:
            try:
                strings = " ".join([s.replace('\n', ' ').replace(',', ' ') for s in data["strings"]])
                features.append(strings)
            except:
                features.append(["Key error"])  
        vectorizer = joblib.load("Models/{}_model.pkl".format("TFIDF"))
        features = vectorizer.transform(features)

        return features
    

    return []
