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
    DbgPrint("[EVASION] APC Queued: Thread=0x%p, Routine=0x%p, Context=0x%p\n", 
             ThreadHandle, ApcRoutine, ApcContext);
    return OriginalNtQueueApcThread(ThreadHandle, ApcRoutine, ApcContext, ApcStatusBlock, ApcReserved);
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[EVASION] Driver unloaded.\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    UNICODE_STRING name;
    PVOID addr;

    DriverObject->DriverUnload = DriverUnload;

    RtlInitUnicodeString(&name, L"NtQueueApcThread");
    addr = MmGetSystemRoutineAddress(&name);
    if (addr) {
        OriginalNtQueueApcThread = (pNtQueueApcThread)InterlockedExchangePointer((PVOID*)addr, HookedNtQueueApcThread);
        DbgPrint("[EVASION] Hooked NtQueueApcThread at 0x%p\n", addr);
    } else {
        DbgPrint("[EVASION] Failed to find NtQueueApcThread\n");
    }

    return STATUS_SUCCESS;
}
