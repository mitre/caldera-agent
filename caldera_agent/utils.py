import sys
import ctypes
import os
import win32api
import win32security
from copy import copy
from ctypes import windll, c_int, c_ulong, sizeof, c_uint32, c_uint64, create_unicode_buffer, pointer
from enum import IntEnum


def process_is_elevated(pid):
    PROCESS_QUERY_INFORMATION = 0x0400
    pHandle = win32api.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
    hToken = win32security.OpenProcessToken(pHandle, win32security.TOKEN_QUERY)
    # TokenElevationType = 18
    TokenElevation = 20
    return win32security.GetTokenInformation(hToken, TokenElevation) == 1


def process_sid(pid):
    PROCESS_QUERY_INFORMATION = 0x0400
    pHandle = win32api.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
    hToken = win32security.OpenProcessToken(pHandle, win32security.TOKEN_QUERY)
    TokenUser = 1
    sid, _ = win32security.GetTokenInformation(hToken, TokenUser)
    return sid


def sid_user(sid):
    username, domain, typ = win32security.LookupAccountSid(None, sid)
    return domain, username

LPWSTR = ctypes.c_wchar_p
LPCWSTR = ctypes.c_wchar_p
DWORD = ctypes.c_ulong
ULONG = ctypes.c_ulong
WORD = ctypes.c_ushort
BYTE = ctypes.c_ubyte
netapi32 = ctypes.WinDLL('Netapi32.dll')


class GUID(ctypes.Structure):
    _fields_ = [('Data1', DWORD),
                ('Data2', WORD),
                ('Data3', WORD),
                ('Data4', BYTE * 8)]


class DSROLE_PRIMARY_DOMAIN_INFO_BASIC(ctypes.Structure):
    _fields_ = [("MachineRole", ULONG),
                ("Flags", ULONG),
                ("DomainNameFlat", LPWSTR),
                ("DomainNameDns", LPWSTR),
                ("DomainForestName", LPWSTR),
                ("DomainGuid", GUID)]


DsRoleGetPrimaryDomainInformation = netapi32['DsRoleGetPrimaryDomainInformation']
DsRoleGetPrimaryDomainInformation.restype = DWORD
DsRoleGetPrimaryDomainInformation.argtypes = (LPCWSTR, ctypes.c_ulong, ctypes.POINTER(ctypes.POINTER(DSROLE_PRIMARY_DOMAIN_INFO_BASIC)))


def getDomainNameFlat():
    dsinfo_ptr = ctypes.POINTER(DSROLE_PRIMARY_DOMAIN_INFO_BASIC)()
    retval = DsRoleGetPrimaryDomainInformation(None, 1, ctypes.byref(dsinfo_ptr))
    if retval != 0:
        raise Exception('DsRoleGetPrimaryDomainInformation failed')
    dsinfo = dsinfo_ptr[0]
    ret_str = copy(dsinfo.DomainNameFlat)
    netapi32['DsRoleFreeMemory'](ctypes.byref(dsinfo))

    return ret_str

is_64bits = sys.maxsize > 2**32

PDWORD = ctypes.POINTER(DWORD)
BOOL = ctypes.c_int
kernel32 = ctypes.WinDLL('Kernel32.dll')

# BOOL WINAPI QueryFullProcessImageName(
#   _In_    HANDLE hProcess,
#   _In_    DWORD  dwFlags,
#   _Out_   LPTSTR lpExeName,
#   _Inout_ PDWORD lpdwSize
# );
QueryFullProcessImageNameW = kernel32['QueryFullProcessImageNameW']
QueryFullProcessImageNameW.restype = BOOL
QueryFullProcessImageNameW.argtypes = (ctypes.c_void_p, DWORD, LPCWSTR, PDWORD)

max_unicode_path = 32767 * 2 + 200


def process_path(pid):
    PROCESS_QUERY_INFORMATION = 0x0400
    file_path_buffer = ctypes.create_unicode_buffer(max_unicode_path)
    length_path = ctypes.c_ulong(max_unicode_path)
    pHandle = win32api.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)

    retval = QueryFullProcessImageNameW(pHandle.handle, 0, file_path_buffer, ctypes.byref(length_path))

    if retval == 0:
        raise Exception('QueryFullProcessImageNameW failed')

    return file_path_buffer.value


def processes():
    """
    :rtype : dict
    """
    bool = c_int
    dword = c_ulong
    HANDLE = c_uint64 if is_64bits else c_uint32
    PROCESS_QUERY_INFORMATION = 0x400
    process_name = create_unicode_buffer(1024 * 64 + 1)
    process_name_size = dword(int(sizeof(process_name) / 2))
    pids = (dword * 4096)()
    pids_size = dword(0)
    if (windll.psapi.EnumProcesses(pids, sizeof(pids), pointer(pids_size)) == 0):
        raise Exception('Windows error')
    retval = {}
    for i in range(0, int(pids_size.value/sizeof(dword))):
        process_handle = HANDLE(windll.kernel32.OpenProcess(dword(PROCESS_QUERY_INFORMATION), bool(0), dword(pids[i])))
        if process_handle.value != 0:
            try:
                if (windll.kernel32.QueryFullProcessImageNameW(process_handle, dword(0), process_name, pointer(process_name_size)) == 0):
                    raise Exception('Windows error')
                process_name_size = dword(sizeof(process_name))
                retval[process_name.value] = pids[i]
            finally:
                windll.kernel32.CloseHandle(process_handle)
    return retval


def get_process_handle(process, access):
    """
    :param process: Either the image_name ('explorer.exe') or the pid of the process
    :param access: The access rights to acquire on the token
    :return: int
    """
    plist = processes()
    for key, val in plist.items():
        if type(process) is int:
            if val == process:
                return win32api.OpenProcess(access, False, val)
        else:
            if os.path.basename(key) == process:
                return win32api.OpenProcess(access, False, val)
    return None


class WTS_CONNECTSTATE_CLASS(IntEnum):
    WTSActive = 0
    WTSConnected = 1
    WTSConnectQuery = 2
    WTSShadow = 3
    WTSDisconnected = 4
    WTSIdle = 5
    WTSListen = 6
    WTSReset = 7
    WTSDown = 8
    WTSInit = 9
