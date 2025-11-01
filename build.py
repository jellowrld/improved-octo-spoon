import os
import subprocess

print("Building evasion.sys (SSDT Hook)...")

os.makedirs("drivers", exist_ok=True)

with open("drivers/evasion.c", "w", encoding="utf-8") as f:
    f.write('''
#include <ntddk.h>

typedef NTSTATUS (*pNtQueueApcThread)(
    HANDLE ThreadHandle,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK ApcStatusBlock,
    ULONG ApcReserved
);

pNtQueueApcThread OriginalNtQueueApcThread = NULL;

NTSTATUS HookedNtQueueApcThread(
    HANDLE ThreadHandle,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK ApcStatusBlock,
    ULONG ApcReserved
) {
    DbgPrint("[HOOK] APC: 0x%p -> 0x%p\\n", ApcRoutine, ApcContext);
    return OriginalNtQueueApcThread(ThreadHandle, ApcRoutine, ApcContext, ApcStatusBlock, ApcReserved);
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    UNICODE_STRING name;
    PVOID addr;

    RtlInitUnicodeString(&name, L"NtQueueApcThread");
    addr = MmGetSystemRoutineAddress(&name);
    if (addr) {
        OriginalNtQueueApcThread = (pNtQueueApcThread)InterlockedExchangePointer((PVOID*)addr, HookedNtQueueApcThread);
        DbgPrint("[EVASION] Hooked NtQueueApcThread\\n");
    }

    DriverObject->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}
''')

result = subprocess.run([
    "cl", "/D_AMD64_", "/driver", "/W3",
    "drivers/evasion.c",
    "/link", "/SUBSYSTEM:NATIVE", "/DRIVER", "/OUT:drivers/evasion.sys"
], capture_output=True)

if result.returncode == 0:
    print("evasion.sys built successfully!")
else:
    print("Build failed. Install Visual Studio + WDK.")
    print(result.stderr.decode())
