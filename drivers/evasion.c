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
    DbgPrint("[OCTOSPOON] APC Queued: 0x%p -> 0x%p\n", ApcRoutine, ApcContext);
    return OriginalNtQueueApcThread(ThreadHandle, ApcRoutine, ApcContext, ApcStatusBlock, ApcReserved);
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[OCTOSPOON] Driver unloaded.\n");
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
        DbgPrint("[OCTOSPOON] Hooked NtQueueApcThread at 0x%p\n", addr);
    } else {
        DbgPrint("[OCTOSPOON] Failed to find NtQueueApcThread\n");
    }

    return STATUS_SUCCESS;
}