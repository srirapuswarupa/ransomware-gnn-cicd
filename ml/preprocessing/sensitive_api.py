"""
Pre-Attack Sensitive API Calls (PASAC) Taxonomy and Feature Mapping.
Inspired by RansoGuard (Cen et al., 2025) and GraphShield (Amer et al., 2026).
Identifies sensitive APIs across key tactical phases of the ransomware lifecycle.
"""
from typing import Dict, Set, Tuple

API_CATEGORIES: Dict[str, str] = {
    # 1. File Discovery and Enumeration
    "FindFirstFile": "File_Enumeration",
    "FindFirstFileW": "File_Enumeration",
    "FindFirstFileA": "File_Enumeration",
    "FindNextFile": "File_Enumeration",
    "FindNextFileW": "File_Enumeration",
    "FindNextFileA": "File_Enumeration",
    "FindClose": "File_Enumeration",
    "GetLogicalDrives": "File_Enumeration",
    "GetDriveTypeW": "File_Enumeration",
    "GetDriveTypeA": "File_Enumeration",

    # 2. File I/O and Destruction
    "CreateFile": "File_IO",
    "CreateFileW": "File_IO",
    "CreateFileA": "File_IO",
    "ReadFile": "File_IO",
    "WriteFile": "File_IO",
    "DeleteFile": "File_IO",
    "DeleteFileW": "File_IO",
    "DeleteFileA": "File_IO",
    "SetFileAttributes": "File_IO",
    "SetFileAttributesW": "File_IO",
    "SetFileAttributesA": "File_IO",
    "MoveFileEx": "File_IO",
    "MoveFileExW": "File_IO",
    "MoveFileExA": "File_IO",
    "SetEndOfFile": "File_IO",
    "FlushFileBuffers": "File_IO",

    # 3. Cryptography (Encryption Engine)
    "CryptAcquireContext": "Cryptography",
    "CryptAcquireContextW": "Cryptography",
    "CryptAcquireContextA": "Cryptography",
    "CryptGenKey": "Cryptography",
    "CryptGenRandom": "Cryptography",
    "CryptEncrypt": "Cryptography",
    "CryptDecrypt": "Cryptography",
    "CryptExportKey": "Cryptography",
    "CryptImportKey": "Cryptography",
    "CryptDestroyKey": "Cryptography",
    "CryptReleaseContext": "Cryptography",
    "BCryptOpenAlgorithmProvider": "Cryptography",
    "BCryptGenerateSymmetricKey": "Cryptography",
    "BCryptEncrypt": "Cryptography",
    "BCryptDestroyKey": "Cryptography",
    "BCryptCloseAlgorithmProvider": "Cryptography",

    # 4. Process and Memory Operations
    "OpenProcess": "Process_Memory",
    "VirtualAlloc": "Process_Memory",
    "VirtualAllocEx": "Process_Memory",
    "VirtualProtect": "Process_Memory",
    "VirtualProtectEx": "Process_Memory",
    "WriteProcessMemory": "Process_Memory",
    "ReadProcessMemory": "Process_Memory",
    "CreateRemoteThread": "Process_Memory",
    "TerminateProcess": "Process_Memory",
    "HeapAlloc": "Process_Memory",
    "VirtualFree": "Process_Memory",

    # 5. Registry & Persistence
    "RegOpenKeyEx": "Registry_Service",
    "RegOpenKeyExW": "Registry_Service",
    "RegOpenKeyExA": "Registry_Service",
    "RegSetValueEx": "Registry_Service",
    "RegSetValueExW": "Registry_Service",
    "RegSetValueExA": "Registry_Service",
    "RegCreateKeyEx": "Registry_Service",
    "RegCreateKeyExW": "Registry_Service",
    "RegDeleteKey": "Registry_Service",
    "RegDeleteValue": "Registry_Service",
    "RegCloseKey": "Registry_Service",
    "OpenSCManager": "Registry_Service",
    "OpenSCManagerW": "Registry_Service",
    "CreateService": "Registry_Service",
    "StartService": "Registry_Service",

    # 6. Defense Evasion and Impact (VSS Shadow Deletion / System disruption)
    "ShellExecute": "Defense_Evasion",
    "ShellExecuteW": "Defense_Evasion",
    "ShellExecuteA": "Defense_Evasion",
    "CreateProcess": "Defense_Evasion",
    "CreateProcessW": "Defense_Evasion",
    "CreateProcessA": "Defense_Evasion",
    "WinExec": "Defense_Evasion",

    # 7. Network and C2 Communication
    "WSAStartup": "Network_C2",
    "socket": "Network_C2",
    "connect": "Network_C2",
    "send": "Network_C2",
    "recv": "Network_C2",
    "closesocket": "Network_C2",
    "InternetOpen": "Network_C2",
    "InternetOpenW": "Network_C2",
    "InternetConnect": "Network_C2",
    "HttpOpenRequest": "Network_C2",
    "HttpSendRequest": "Network_C2",
    "InternetReadFile": "Network_C2",
    "InternetCloseHandle": "Network_C2",

    # 8. System Discovery / Reconnaissance
    "GetSystemInfo": "System_Discovery",
    "GetNativeSystemInfo": "System_Discovery",
    "IsDebuggerPresent": "System_Discovery",
    "CheckRemoteDebuggerPresent": "System_Discovery",
    "GetComputerName": "System_Discovery",
    "GetComputerNameW": "System_Discovery",
    "GlobalMemoryStatusEx": "System_Discovery",
    "GetVersionEx": "System_Discovery",

    # 9. Benign / Standard Runtime Utilities
    "GetTickCount": "System_Util",
    "Sleep": "System_Util",
    "CloseHandle": "System_Util",
    "GetModuleHandle": "System_Util",
    "GetModuleHandleW": "System_Util",
    "GetProcAddress": "System_Util",
    "LoadLibrary": "System_Util",
    "LoadLibraryW": "System_Util",
    "ExitProcess": "System_Util",
    "GetCurrentProcess": "System_Util",
    "GetCurrentThread": "System_Util",
    "GetLastError": "System_Util",
}

# Pre-Attack Sensitive APIs according to PASAC literature
SENSITIVE_APIS: Set[str] = {
    # Discovery & Evasion
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "ShellExecute", "ShellExecuteW",
    "CreateProcess", "CreateProcessW", "WinExec",
    # Crypto
    "CryptAcquireContext", "CryptAcquireContextW", "CryptGenKey", "CryptEncrypt", "CryptExportKey",
    "BCryptOpenAlgorithmProvider", "BCryptGenerateSymmetricKey", "BCryptEncrypt",
    # File traversal & destruction
    "FindFirstFile", "FindFirstFileW", "FindNextFile", "FindNextFileW",
    "DeleteFile", "DeleteFileW", "MoveFileEx", "MoveFileExW",
    # Memory injection
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    # Persistence
    "RegSetValueEx", "RegSetValueExW", "CreateService",
    # C2
    "connect", "send", "HttpSendRequest"
}

# Canonical mapping for normalizing API names
CANONICAL_NAME_MAP: Dict[str, str] = {
    k: k[:-1] if k.endswith(('W', 'A')) and k[:-1] in [
        "FindFirstFile", "FindNextFile", "CreateFile", "DeleteFile", "SetFileAttributes",
        "MoveFileEx", "CryptAcquireContext", "RegOpenKeyEx", "RegSetValueEx", "RegCreateKeyEx",
        "OpenSCManager", "ShellExecute", "CreateProcess", "InternetOpen", "GetComputerName",
        "GetModuleHandle", "LoadLibrary", "GetDriveType"
    ] else k
    for k in API_CATEGORIES
}

CATEGORY_LIST = [
    "File_IO",
    "File_Enumeration",
    "Cryptography",
    "Process_Memory",
    "Registry_Service",
    "Defense_Evasion",
    "Network_C2",
    "System_Discovery",
    "System_Util"
]

def get_api_category(api_name: str) -> str:
    """Returns the functional category for an API call."""
    if api_name in API_CATEGORIES:
        return API_CATEGORIES[api_name]
    # Check canonicalized version
    canon = CANONICAL_NAME_MAP.get(api_name, api_name)
    return API_CATEGORIES.get(canon, "System_Util")

def is_pre_attack_sensitive(api_name: str) -> bool:
    """Checks whether the API is categorized as a Pre-Attack Sensitive API."""
    canon = CANONICAL_NAME_MAP.get(api_name, api_name)
    return api_name in SENSITIVE_APIS or canon in SENSITIVE_APIS
