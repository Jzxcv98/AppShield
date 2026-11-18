// SPDX-License-Identifier: GPL-3.0-only
#include <fltKernel.h>
#include "PathPolicy.h"

#define ASF_TAG 'FsSA'
#define ASF_BUCKETS 64u
// Process access masks used by ObReferenceObjectByHandle. WDK km headers
// do not expose both public process access constants.
#define ASF_PROCESS_QUERY_LIMITED_INFORMATION 0x1000u
#define ASF_PROCESS_SUSPEND_RESUME 0x0800u
typedef struct {
    volatile LONG References;
    ULONG Count;
    ASF_RULE Rules[ANYSIZE_ARRAY];
} POLICY;

typedef struct {
    LIST_ENTRY Link;
    PEPROCESS Process;
    HANDLE Id;
    POLICY *Policy;
    ULONGLONG CreatorConnection;
} PROCESS_ENTRY;

typedef struct {
    POLICY *Policy;
    ULONG Granted;
} OPEN_CONTEXT;

static PFLT_FILTER Filter;
static PFLT_PORT ServerPort;
typedef struct {
    PFLT_PORT Port;
    PEPROCESS Process;
    ULONGLONG Generation;
} BROKER;
static BROKER *ActiveBroker;        // protected by TableLock
static ULONGLONG LastConnection;
static LIST_ENTRY Buckets[ASF_BUCKETS];
static KSPIN_LOCK TableLock;
static ULONG ManagedCount, PendingCreates;
static BOOLEAN Ready, Stopping;

static void Reference(POLICY *p) { InterlockedIncrement(&p->References); }
static void Release(POLICY *p) {
    if (p && InterlockedDecrement(&p->References) == 0) ExFreePoolWithTag(p, ASF_TAG);
}
static PLIST_ENTRY Bucket(HANDLE id) {
    return &Buckets[((ULONG_PTR)id >> 2) % ASF_BUCKETS];
}
// TableLock protects membership and policy attachment. Entries for newly created
// processes exist before their first user instruction; exit and bind serialize here.
static PROCESS_ENTRY *FindLocked(HANDLE id) {
    PLIST_ENTRY head = Bucket(id), it;
    for (it = head->Flink; it != head; it = it->Flink) {
        PROCESS_ENTRY *e = CONTAINING_RECORD(it, PROCESS_ENTRY, Link);
        if (e->Id == id) return e;
    }
    return NULL;
}
// Called outside the table lock, at PASSIVE_LEVEL from process notification or unload.
static void FreeEntry(PROCESS_ENTRY *entry) {
    if (entry) {
        Release(entry->Policy);
        ObDereferenceObject(entry->Process);
        ExFreePoolWithTag(entry, ASF_TAG);
    }
}
static POLICY *Lookup(PEPROCESS process, BOOLEAN pinCreate) {
    KIRQL old;
    POLICY *p = NULL;
    HANDLE id;
    PROCESS_ENTRY *entry;
    if (!process) return NULL;
    id = PsGetProcessId(process);
    KeAcquireSpinLock(&TableLock, &old);
    entry = FindLocked(id);
    if (entry && entry->Process == process && entry->Policy) {
        p = entry->Policy;
        Reference(p);
        if (pinCreate) ++PendingCreates;
    }
    KeReleaseSpinLock(&TableLock, old);
    return p;
}
static void FinishCreate(POLICY *p) {
    KIRQL old;
    Release(p);
    KeAcquireSpinLock(&TableLock, &old);
    --PendingCreates;
    KeReleaseSpinLock(&TableLock, old);
}

static VOID OnProcess(PEPROCESS process, HANDLE id, PPS_CREATE_NOTIFY_INFO create) {
    KIRQL old;
    PROCESS_ENTRY *entry, *stale = NULL;
    if (!create) {
        KeAcquireSpinLock(&TableLock, &old);
        entry = FindLocked(id);
        if (entry && entry->Process == process) {
            RemoveEntryList(&entry->Link);
            if (entry->Policy) --ManagedCount;
        } else entry = NULL;
        KeReleaseSpinLock(&TableLock, old);
        FreeEntry(entry);
        return;
    }
    if (!NT_SUCCESS(create->CreationStatus)) return;
    entry = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*entry), ASF_TAG);
    KeAcquireSpinLock(&TableLock, &old);
    {
        PROCESS_ENTRY *parent, *creator;
        POLICY *inherited, *actual;
        // A creation vetoed by another callback may have no runnable process.
        // Never let an entry left over from a failed creation identify a reused PID.
        stale = FindLocked(id);
        if (stale) {
            RemoveEntryList(&stale->Link);
            if (stale->Policy) --ManagedCount;
        }
        parent = FindLocked(create->ParentProcessId);
        creator = FindLocked(create->CreatingThreadId.UniqueProcess);
        inherited = parent ? parent->Policy : NULL;
        actual = creator ? creator->Policy : NULL;
        if ((actual && inherited && actual != inherited) || ((actual || inherited) && (!entry || Stopping))) {
            create->CreationStatus = STATUS_ACCESS_DENIED;
        } else if (entry && !Stopping) {
            entry->Process = process;
            ObReferenceObject(process);
            entry->Id = id;
            entry->Policy = actual ? actual : inherited;
            if (ActiveBroker && create->CreatingThreadId.UniqueProcess == PsGetProcessId(ActiveBroker->Process))
                entry->CreatorConnection = ActiveBroker->Generation;
            if (entry->Policy) { Reference(entry->Policy); ++ManagedCount; }
            InsertHeadList(Bucket(id), &entry->Link);
            entry = NULL;
        }
    }
    KeReleaseSpinLock(&TableLock, old);
    FreeEntry(stale);
    if (entry) ExFreePoolWithTag(entry, ASF_TAG);
}

static ULONG NamedAccess(PFLT_CALLBACK_DATA data, const POLICY *p, FLT_FILE_NAME_OPTIONS query) {
    PFLT_FILE_NAME_INFORMATION info = NULL;
    ULONG access = 0;
    if (NT_SUCCESS(FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | query, &info))) {
        if (NT_SUCCESS(FltParseFileNameInformation(info)) && info->Stream.Length == 0)
            access = AsfGrantForName(p->Rules, p->Count, info->Name.Buffer, info->Name.Length / sizeof(WCHAR));
        FltReleaseFileNameInformation(info);
    }
    return access;
}

static FLT_PREOP_CALLBACK_STATUS Deny(PFLT_CALLBACK_DATA data) {
    data->IoStatus.Status = STATUS_ACCESS_DENIED;
    data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}
static BOOLEAN AllowedMask(PFLT_CALLBACK_DATA data, ULONG grant) {
    ACCESS_MASK wanted = data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    ACCESS_MASK allowed = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
    if (!(grant & ASF_READ)) return FALSE;
    if (grant & ASF_WRITE) allowed |= FILE_GENERIC_WRITE;
    RtlMapGenericMask(&wanted, IoGetFileObjectGenericMapping());
    return (wanted & ~allowed) == 0;
}

static FLT_PREOP_CALLBACK_STATUS PreCreate(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objs, PVOID *ctx) {
    ULONG options;
    FLT_FILESYSTEM_TYPE fs;
    POLICY *p = Lookup(FltGetRequestorProcess(data), TRUE);
    if (!p) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    options = data->Iopb->Parameters.Create.Options;
    if (!AsfAllowsOpen(options, BooleanFlagOn(data->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY)) ||
        !NT_SUCCESS(FltGetFileSystemType(objs->Volume, &fs)) || fs != FLT_FSTYPE_NTFS ||
        !AllowedMask(data, NamedAccess(data, p, FLT_FILE_NAME_QUERY_DEFAULT))) {
        FinishCreate(p);
        return Deny(data);
    }
    *ctx = p;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}
static FLT_POSTOP_CALLBACK_STATUS PostCreate(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objs,
                                             PVOID ctx, FLT_POST_OPERATION_FLAGS flags) {
    POLICY *p = ctx;
    // The manager can simulate completion while tearing down an instance. Its
    // draining callback is for context cleanup only; it is not a real file open.
    if (FlagOn(flags, FLTFL_POST_OPERATION_DRAINING)) {
        FinishCreate(p);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (NT_SUCCESS(data->IoStatus.Status)) {
        BOOLEAN opened = data->IoStatus.Status != STATUS_REPARSE;
        BOOLEAN ok = FALSE;
        if (opened) {
            ULONG grant = NamedAccess(data, p, FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY);
            FILE_STANDARD_INFORMATION standard;
            FILE_BASIC_INFORMATION basic;
            OPEN_CONTEXT *openedContext = NULL;
            if (AllowedMask(data, grant) && !FlagOn(objs->FileObject->Flags, FO_VOLUME_OPEN) &&
                NT_SUCCESS(FltQueryInformationFile(objs->Instance, objs->FileObject,
                    &basic, sizeof(basic), FileBasicInformation, NULL)) &&
                NT_SUCCESS(FltQueryInformationFile(objs->Instance, objs->FileObject,
                    &standard, sizeof(standard), FileStandardInformation, NULL)) &&
                AsfAllowsFinalObject(basic.FileAttributes, standard.Directory, standard.NumberOfLinks, standard.DeletePending) &&
                NT_SUCCESS(FltAllocateContext(Filter, FLT_STREAMHANDLE_CONTEXT, sizeof(*openedContext),
                    NonPagedPoolNx, (PFLT_CONTEXT *)&openedContext))) {
                Reference(p);
                openedContext->Policy = p;
                openedContext->Granted = grant;
                ok = NT_SUCCESS(FltSetStreamHandleContext(objs->Instance, objs->FileObject,
                    FLT_SET_CONTEXT_KEEP_IF_EXISTS, openedContext, NULL));
                FltReleaseContext(openedContext);
            }
        }
        if (!ok) {
            if (opened) FltCancelFileOpen(objs->Instance, objs->FileObject);
            data->IoStatus.Status = STATUS_ACCESS_DENIED;
            data->IoStatus.Information = 0;
            FltSetCallbackDataDirty(data);
        }
    }
    FinishCreate(p);
    return FLT_POSTOP_FINISHED_PROCESSING;
}
static VOID ContextCleanup(PFLT_CONTEXT ctx, FLT_CONTEXT_TYPE type) {
    UNREFERENCED_PARAMETER(type);
    Release(((OPEN_CONTEXT *)ctx)->Policy);
}
static FLT_PREOP_CALLBACK_STATUS PreHandle(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objs, PVOID *completion) {
    OPEN_CONTEXT *ctx = NULL;
    POLICY *p;
    ULONG required = ASF_READ;
    BOOLEAN ok;
    UNREFERENCED_PARAMETER(completion);
    // Paging and cache-manager I/O can run in a different process context. Authorize
    // the originating file open, and do not abort unrelated paging writes.
    if ((data->Iopb->MajorFunction == IRP_MJ_READ || data->Iopb->MajorFunction == IRP_MJ_WRITE) &&
        FlagOn(data->Iopb->IrpFlags, IRP_PAGING_IO)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    p = Lookup(FltGetRequestorProcess(data), FALSE);
    if (!p) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    switch (data->Iopb->MajorFunction) {
    case IRP_MJ_READ: case IRP_MJ_QUERY_INFORMATION: case IRP_MJ_QUERY_EA:
    case IRP_MJ_QUERY_SECURITY: case IRP_MJ_DIRECTORY_CONTROL: case IRP_MJ_QUERY_VOLUME_INFORMATION:
    case IRP_MJ_QUERY_QUOTA: case IRP_MJ_LOCK_CONTROL: case IRP_MJ_FLUSH_BUFFERS: break;
    case IRP_MJ_WRITE: required |= ASF_WRITE; break;
    case IRP_MJ_SET_INFORMATION:
        switch (data->Iopb->Parameters.SetFileInformation.FileInformationClass) {
        case FilePositionInformation: break;
        case FileEndOfFileInformation: case FileAllocationInformation: required |= ASF_WRITE; break;
        default: Release(p); return Deny(data);
        }
        break;
    case IRP_MJ_NETWORK_QUERY_OPEN: case IRP_MJ_MDL_READ: case IRP_MJ_PREPARE_MDL_WRITE:
        Release(p);
        return FLT_PREOP_DISALLOW_FASTIO; // File system must use a checked create.
    case IRP_MJ_QUERY_OPEN:
        Release(p);
        return FLT_PREOP_DISALLOW_FSFILTER_IO;
    default: Release(p); return Deny(data);
    }
    ok = KeGetCurrentIrql() <= APC_LEVEL &&
        NT_SUCCESS(FltGetStreamHandleContext(objs->Instance, objs->FileObject, (PFLT_CONTEXT *)&ctx)) &&
        ctx->Policy == p && (ctx->Granted & required) == required;
    if (ctx) FltReleaseContext(ctx);
    Release(p);
    return ok ? FLT_PREOP_SUCCESS_NO_CALLBACK : Deny(data);
}

static NTSTATUS Connect(PFLT_PORT port, PVOID serverCookie, PVOID buf, ULONG len, PVOID *cookie) {
    POLICY *p;
    KIRQL old;
    BOOLEAN available;
    BROKER *broker;
    UNREFERENCED_PARAMETER(serverCookie); UNREFERENCED_PARAMETER(buf); UNREFERENCED_PARAMETER(len);
    p = Lookup(PsGetCurrentProcess(), FALSE);
    if (p) { Release(p); return STATUS_ACCESS_DENIED; }
    broker = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*broker), ASF_TAG);
    if (!broker) return STATUS_INSUFFICIENT_RESOURCES;
    broker->Port = port;
    broker->Process = PsGetCurrentProcess();
    ObReferenceObject(broker->Process);
    KeAcquireSpinLock(&TableLock, &old);
    available = Ready && !Stopping && !ActiveBroker && LastConnection != MAXULONGLONG;
    if (available) {
        broker->Generation = ++LastConnection;
        ActiveBroker = broker;
    }
    KeReleaseSpinLock(&TableLock, old);
    if (!available) {
        ObDereferenceObject(broker->Process);
        ExFreePoolWithTag(broker, ASF_TAG);
        return STATUS_DEVICE_NOT_READY;
    }
    *cookie = broker;
    return STATUS_SUCCESS;
}
static VOID Disconnect(PVOID cookie) {
    BROKER *broker = cookie;
    KIRQL old;
    KeAcquireSpinLock(&TableLock, &old);
    if (ActiveBroker == broker) ActiveBroker = NULL;
    KeReleaseSpinLock(&TableLock, old);
    FltCloseClientPort(Filter, &broker->Port);
    ObDereferenceObject(broker->Process);
    ExFreePoolWithTag(broker, ASF_TAG);
}

static NTSTATUS Message(PVOID cookie, PVOID input, ULONG inputLen, PVOID output, ULONG outputLen, PULONG returned) {
    ASF_REQUEST req;
    ASF_REPLY reply = { ASF_PROTOCOL, 0, 0, 0 };
    PEPROCESS target = NULL;
    PROCESS_ENTRY *entry;
    POLICY *policy = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i, ruleBytes;
    KIRQL old;
    BROKER *broker = cookie;
    *returned = 0;
    if (broker->Process != PsGetCurrentProcess()) return STATUS_ACCESS_DENIED;
    if (!input || inputLen < sizeof(req) || !output || outputLen < sizeof(reply)) return STATUS_INVALID_PARAMETER;
    __try { RtlCopyMemory(&req, input, sizeof(req)); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
    if (req.Version != ASF_PROTOCOL || req.Reserved || req.RuleCount > ASF_MAX_RULES ||
        (req.Operation != ASF_QUERY && req.Operation != ASF_BIND)) return STATUS_INVALID_PARAMETER;
    ruleBytes = req.RuleCount * sizeof(ASF_RULE);
    if (inputLen != sizeof(req) + ruleBytes || (req.Operation == ASF_QUERY && req.RuleCount) ||
        (req.Operation == ASF_BIND && (!req.ProcessHandle || !req.RuleCount))) return STATUS_INVALID_PARAMETER;
    if (req.ProcessHandle) {
        status = ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)req.ProcessHandle,
            req.Operation == ASF_BIND ? ASF_PROCESS_SUSPEND_RESUME | ASF_PROCESS_QUERY_LIMITED_INFORMATION : ASF_PROCESS_QUERY_LIMITED_INFORMATION,
            *PsProcessType, UserMode, (PVOID *)&target, NULL);
        if (!NT_SUCCESS(status)) return status;
    }
    if (req.Operation == ASF_BIND) {
        if (target == broker->Process || target == PsInitialSystemProcess) { status = STATUS_ACCESS_DENIED; goto finish; }
        policy = ExAllocatePool2(POOL_FLAG_NON_PAGED, FIELD_OFFSET(POLICY, Rules) + ruleBytes, ASF_TAG);
        if (!policy) { status = STATUS_INSUFFICIENT_RESOURCES; goto finish; }
        policy->References = 1;
        policy->Count = req.RuleCount;
        __try { RtlCopyMemory(policy->Rules, (PUCHAR)input + sizeof(req), ruleBytes); }
        __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); goto finish; }
        for (i = 0; i < policy->Count; i++) {
            if (!AsfValidRoot(&policy->Rules[i])) { status = STATUS_INVALID_PARAMETER; goto finish; }
        }
    }
    KeAcquireSpinLock(&TableLock, &old);
    entry = target ? FindLocked(PsGetProcessId(target)) : NULL;
    if (entry && entry->Process != target) entry = NULL;
    if (req.Operation == ASF_BIND) {
        if (!Ready || Stopping || ActiveBroker != broker || !entry || entry->Policy ||
            entry->CreatorConnection != broker->Generation) status = STATUS_INVALID_DEVICE_STATE;
        else { entry->Policy = policy; policy = NULL; ++ManagedCount; }
    }
    reply.ManagedProcesses = ManagedCount;
    reply.HandleBound = entry && entry->Policy ? 1 : 0;
    KeReleaseSpinLock(&TableLock, old);
    if (NT_SUCCESS(status)) {
        __try { RtlCopyMemory(output, &reply, sizeof(reply)); *returned = sizeof(reply); }
        __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
    }
finish:
    Release(policy);
    if (target) ObDereferenceObject(target);
    return status;
}

static NTSTATUS Unload(FLT_FILTER_UNLOAD_FLAGS flags) {
    KIRQL old;
    ULONG i;
    UNREFERENCED_PARAMETER(flags);
    KeAcquireSpinLock(&TableLock, &old);
    if (ManagedCount != 0 || PendingCreates != 0) {
        KeReleaseSpinLock(&TableLock, old);
        return STATUS_FLT_DO_NOT_DETACH;
    }
    Stopping = TRUE;
    KeReleaseSpinLock(&TableLock, old);
    FltCloseCommunicationPort(ServerPort);
    PsSetCreateProcessNotifyRoutineEx(OnProcess, TRUE);
    FltUnregisterFilter(Filter);
    for (i = 0; i < ASF_BUCKETS; ++i) {
        while (!IsListEmpty(&Buckets[i])) {
            PLIST_ENTRY link = RemoveHeadList(&Buckets[i]);
            FreeEntry(CONTAINING_RECORD(link, PROCESS_ENTRY, Link));
        }
    }
    return STATUS_SUCCESS;
}
static NTSTATUS QueryDetach(PCFLT_RELATED_OBJECTS objs, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS flags) {
    UNREFERENCED_PARAMETER(objs); UNREFERENCED_PARAMETER(flags);
    return STATUS_FLT_DO_NOT_DETACH;
}
static const FLT_CONTEXT_REGISTRATION Contexts[] = {
    { FLT_STREAMHANDLE_CONTEXT, 0, ContextCleanup, sizeof(OPEN_CONTEXT), ASF_TAG },
    { FLT_CONTEXT_END }
};
static const FLT_OPERATION_REGISTRATION Operations[] = {
    { IRP_MJ_CREATE, 0, PreCreate, PostCreate },
    { IRP_MJ_READ, 0, PreHandle, NULL }, { IRP_MJ_WRITE, 0, PreHandle, NULL },
    { IRP_MJ_QUERY_INFORMATION, 0, PreHandle, NULL }, { IRP_MJ_SET_INFORMATION, 0, PreHandle, NULL },
    { IRP_MJ_QUERY_EA, 0, PreHandle, NULL }, { IRP_MJ_SET_EA, 0, PreHandle, NULL },
    { IRP_MJ_QUERY_SECURITY, 0, PreHandle, NULL }, { IRP_MJ_SET_SECURITY, 0, PreHandle, NULL },
    { IRP_MJ_QUERY_VOLUME_INFORMATION, 0, PreHandle, NULL }, { IRP_MJ_QUERY_QUOTA, 0, PreHandle, NULL },
    { IRP_MJ_LOCK_CONTROL, 0, PreHandle, NULL }, { IRP_MJ_FLUSH_BUFFERS, 0, PreHandle, NULL },
    { IRP_MJ_DIRECTORY_CONTROL, 0, PreHandle, NULL }, { IRP_MJ_FILE_SYSTEM_CONTROL, 0, PreHandle, NULL },
    { IRP_MJ_DEVICE_CONTROL, 0, PreHandle, NULL }, { IRP_MJ_SET_VOLUME_INFORMATION, 0, PreHandle, NULL },
    { IRP_MJ_SET_QUOTA, 0, PreHandle, NULL }, { IRP_MJ_NETWORK_QUERY_OPEN, 0, PreHandle, NULL },
    { IRP_MJ_QUERY_OPEN, 0, PreHandle, NULL },
    { IRP_MJ_MDL_READ, 0, PreHandle, NULL }, { IRP_MJ_PREPARE_MDL_WRITE, 0, PreHandle, NULL },
    { IRP_MJ_OPERATION_END }
};
static const FLT_REGISTRATION Registration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP, Contexts, Operations,
    Unload, NULL, QueryDetach
};
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath) {
    NTSTATUS status;
    ULONG i;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING name = RTL_CONSTANT_STRING(ASF_PORT_NAME);
    UNREFERENCED_PARAMETER(registryPath);
    KeInitializeSpinLock(&TableLock);
    for (i = 0; i < ASF_BUCKETS; ++i) InitializeListHead(&Buckets[i]);
    status = FltRegisterFilter(driver, &Registration, &Filter);
    if (!NT_SUCCESS(status)) return status;
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status)) {
        InitializeObjectAttributes(&attributes, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);
        status = FltCreateCommunicationPort(Filter, &ServerPort, &attributes, NULL, Connect, Disconnect, Message, 1);
        FltFreeSecurityDescriptor(sd);
    }
    if (!NT_SUCCESS(status)) { FltUnregisterFilter(Filter); return status; }
    status = PsSetCreateProcessNotifyRoutineEx(OnProcess, FALSE);
    if (NT_SUCCESS(status)) {
        status = FltStartFiltering(Filter);
        if (NT_SUCCESS(status)) {
            KIRQL old;
            KeAcquireSpinLock(&TableLock, &old);
            Ready = TRUE;
            KeReleaseSpinLock(&TableLock, old);
            return status;
        }
        PsSetCreateProcessNotifyRoutineEx(OnProcess, TRUE);
    }
    FltCloseCommunicationPort(ServerPort);
    FltUnregisterFilter(Filter);
    // Process arrivals between notify registration and a failed start can leave placeholders.
    for (i = 0; i < ASF_BUCKETS; ++i) {
        while (!IsListEmpty(&Buckets[i])) {
            PLIST_ENTRY link = RemoveHeadList(&Buckets[i]);
            FreeEntry(CONTAINING_RECORD(link, PROCESS_ENTRY, Link));
        }
    }
    return status;
}
