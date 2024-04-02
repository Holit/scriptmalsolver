#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *

from qiling.const import QL_ARCH
from qiling.exception import *
from qiling.os.const import *
from qiling.os.windows.consts.const import *
from qiling.os.windows.handle import *
from qiling.os.windows import structs
from qiling.os.windows import utils


# void *memcpy(
#    void *dest,
#    const void *src,
#    size_t count
# );
@winsdkapi(cc=CDECL, params={
    'dest'  : POINTER,
    'src'   : POINTER,
    'count' : UINT
})
def hook_memcpy(ql: Qiling, address: int, params):
    dest = params['dest']
    src = params['src']
    count = params['count']

    data = bytes(ql.mem.read(src, count))
    ql.mem.write(dest, data)

    return dest

def _QueryInformationProcess(ql: Qiling, address: int, params):
    flag = params["ProcessInformationClass"]
    obuf_ptr = params["ProcessInformation"]
    obuf_len = params['ProcessInformationLength']
    res_size_ptr = params["ReturnLength"]

    if flag == ProcessDebugFlags:
        res_data = ql.pack32(1)

    elif flag == ProcessDebugPort:
        res_data = ql.pack32(0)

    elif flag == ProcessDebugObjectHandle:
        return STATUS_PORT_NOT_SET

    elif flag == ProcessBasicInformation:
        kconf = ql.os.profile['KERNEL']
        pbi_struct = structs.make_process_basic_info(ql.arch.bits)

        pci_obj = pbi_struct(
            ExitStatus=0,
            PebBaseAddress=ql.loader.TEB.PebAddress,
            AffinityMask=0,
            BasePriority=0,
            UniqueProcessId=kconf.getint('pid'),
            InheritedFromUniqueProcessId=kconf.getint('parent_pid')
        )

        res_data = bytes(pci_obj)

    else:
        # TODO: support more info class ("flag") values
        ql.log.info(f'QueryInformationProcess: no implementation for info class {flag:#04x}')

        return STATUS_UNSUCCESSFUL

    res_size = len(res_data)

    if obuf_len >= res_size:
        ql.mem.write(obuf_ptr, res_data)

    if res_size_ptr:
        ql.mem.write_ptr(res_size_ptr, res_size)

    return STATUS_SUCCESS

# NTSTATUS WINAPI ZwQueryInformationProcess(
#   _In_      HANDLE           ProcessHandle,
#   _In_      PROCESSINFOCLASS ProcessInformationClass,
#   _Out_     PVOID            ProcessInformation,
#   _In_      ULONG            ProcessInformationLength,
#   _Out_opt_ PULONG           ReturnLength
# );
@winsdkapi(cc=STDCALL, params={
    'ProcessHandle'            : HANDLE,
    'ProcessInformationClass'  : PROCESSINFOCLASS,
    'ProcessInformation'       : PVOID,
    'ProcessInformationLength' : ULONG,
    'ReturnLength'             : PULONG
})
def hook_ZwQueryInformationProcess(ql: Qiling, address: int, params):
    # TODO have no idea if is cdecl or stdcall

    return _QueryInformationProcess(ql, address, params)

# __kernel_entry NTSTATUS NtQueryInformationProcess(
#   IN HANDLE           ProcessHandle,
#   IN PROCESSINFOCLASS ProcessInformationClass,
#   OUT PVOID           ProcessInformation,
#   IN ULONG            ProcessInformationLength,
#   OUT PULONG          ReturnLength
# );
@winsdkapi(cc=STDCALL, params={
    'ProcessHandle'            : HANDLE,
    'ProcessInformationClass'  : PROCESSINFOCLASS,
    'ProcessInformation'       : PVOID,
    'ProcessInformationLength' : ULONG,
    'ReturnLength'             : PULONG
})
def hook_NtQueryInformationProcess(ql: Qiling, address: int, params):
    # TODO have no idea if is cdecl or stdcall

    return _QueryInformationProcess(ql, address, params)

def _QuerySystemInformation(ql: Qiling, address: int, params):
    SystemInformationClass = params['SystemInformationClass']
    SystemInformation = params['SystemInformation']
    SystemInformationLength = params['SystemInformationLength']
    ReturnLength = params['ReturnLength']

    if SystemInformationClass == SystemBasicInformation:
        max_uaddr = {
            QL_ARCH.X86  : 0x7FFEFFFF,
            QL_ARCH.X8664: 0x7FFFFFFEFFFF
        }[ql.arch.type]

        sbi_struct = structs.make_system_basic_info(ql.arch.bits)

        # FIXME: retrieve the necessary info from KUSER_SHARED_DATA
        sbi_obj = sbi_struct(
            TimerResolution              = 156250,
            PageSize                     = ql.mem.pagesize,
            NumberOfPhysicalPages        = 0x003FC38A,
            LowestPhysicalPageNumber     = 1,
            HighestPhysicalPageNumber    = 0x0046DFFF,
            AllocationGranularity        = 1,
            MinimumUserModeAddress       = 0x10000,
            MaximumUserModeAddress       = max_uaddr,
            ActiveProcessorsAffinityMask = 0x3F,
            NumberOfProcessors           = 6
        )

        if ReturnLength:
            ql.mem.write_ptr(ReturnLength, sbi_struct.sizeof(), 4)

        if SystemInformationLength < sbi_struct.sizeof():
            return STATUS_INFO_LENGTH_MISMATCH

        sbi_obj.save_to(ql.mem, SystemInformation)

    else:
        raise QlErrorNotImplemented(f'not implemented for {SystemInformationClass=}')

    return STATUS_SUCCESS

# __kernel_entry NTSTATUS NtQuerySystemInformation(
#   IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
#   OUT PVOID                   SystemInformation,
#   IN ULONG                    SystemInformationLength,
#   OUT PULONG                  ReturnLength
# );
@winsdkapi(cc=STDCALL, params={
    'SystemInformationClass'  : SYSTEM_INFORMATION_CLASS,
    'SystemInformation'       : PVOID,
    'SystemInformationLength' : ULONG,
    'ReturnLength'            : PULONG
})
def hook_NtQuerySystemInformation(ql: Qiling, address: int, params):
    # In minwindef.h
    # #define WINAPI      __stdcall

    _QuerySystemInformation(ql, address, params)

# pub unsafe extern "system" fn ZwQuerySystemInformation(
#   IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
#   OUT PVOID                   SystemInformation,
#   IN ULONG                    SystemInformationLength,
#   OUT PULONG                  ReturnLength
# );
@winsdkapi(cc=STDCALL, params={
    'SystemInformationClass'  : SYSTEM_INFORMATION_CLASS,
    'SystemInformation'       : PVOID,
    'SystemInformationLength' : ULONG,
    'ReturnLength'            : PULONG
})
def hook_ZwQuerySystemInformation(ql: Qiling, address: int, params):
    # In minwindef.h
    # #define WINAPI      __stdcall

    return _QuerySystemInformation(ql, address, params)

# pub unsafe extern "system" fn ZwCreateDebugObject(
#     DebugObjectHandle: PHANDLE,
#     DesiredAccess: ACCESS_MASK,
#     ObjectAttributes: POBJECT_ATTRIBUTES,
#     Flags: ULONG
# ) -> NTSTATUS
@winsdkapi(cc=STDCALL, params={
    'DebugObjectHandle' : PHANDLE,
    'DesiredAccess'     : ACCESS_MASK,
    'ObjectAttributes'  : POBJECT_ATTRIBUTES,
    'Flags'             : ULONG
})
def hook_ZwCreateDebugObject(ql: Qiling, address: int, params):
    # FIXME: find documentation, almost none was found online, and create the correct object
    handle = Handle(id=params["DebugObjectHandle"])
    ql.os.handle_manager.append(handle)
    return STATUS_SUCCESS

# __kernel_entry NTSYSCALLAPI NTSTATUS NtQueryObject(
#   HANDLE                   Handle,
#   OBJECT_INFORMATION_CLASS ObjectInformationClass,
#   PVOID                    ObjectInformation,
#   ULONG                    ObjectInformationLength,
#   PULONG                   ReturnLength
# );
@winsdkapi(cc=STDCALL, params={
    'Handle'                  : HANDLE,
    'ObjectInformationClass'  : OBJECT_INFORMATION_CLASS,
    'ObjectInformation'       : PVOID,
    'ObjectInformationLength' : ULONG,
    'ReturnLength'            : PULONG
})
def hook_ZwQueryObject(ql: Qiling, address: int, params):
    handle = params['Handle']
    ObjectInformationClass = params['ObjectInformationClass']
    ObjectInformation = params['ObjectInformation']
    ObjectInformationLength = params['ObjectInformationLength']
    ReturnLength = params['ReturnLength']

    s = 'DebugObject'.encode('utf-16le')
    addr = ql.os.heap.alloc(len(s))
    ql.mem.write(addr, s)

    unistr_struct = structs.make_unicode_string(ql.arch.bits)

    unistr_obj = unistr_struct(
        Length        = len(s),
        MaximumLength = len(s),
        Buffer        = addr
    )

    oti_struct = structs.make_object_type_info(ql.arch.bits)

    oti_obj = oti_struct(
        TypeName             = unistr_obj,
        TotalNumberOfObjects = 1,
        TotalNumberOfHandles = 1
    )

    oati_struct = structs.make_object_all_types_info(ql.arch.bits, 1)

    if ObjectInformationClass == ObjectTypeInformation:
        out = oti_obj

    elif ObjectInformationClass == ObjectAllTypesInformation:
        # FIXME: al-khaser refers the object named 'DebugObject' twice: the first time it creates a handle
        # for it (so number of handles is expected to be higher than 0) and then closes it. the next time
        # it accesses it (here), it expects the number of handles to be 0.
        #
        # ideally we would track the handles for each object, but since we do not - this is a hack to let
        # it pass.
        oti_obj.TotalNumberOfHandles = 0

        oati_obj = oati_struct(
            NumberOfObjectTypes   = 1,
            ObjectTypeInformation = (oti_obj,)
        )

        out = oati_obj

    else:
        raise QlErrorNotImplemented(f'API not implemented ({ObjectInformationClass=})')

    if ReturnLength:
        ql.mem.write_ptr(ReturnLength, out.sizeof(), 4)

    if ObjectInformationLength < out.sizeof():
        return STATUS_INFO_LENGTH_MISMATCH

    if ObjectInformation and handle:
        out.save_to(ql.mem, ObjectInformation)

    return STATUS_SUCCESS

# NTSYSAPI NTSTATUS NTAPI NtSetInformatonProcess(
#   _In_      HANDLE           ProcessHandle,
#   _In_      PROCESSINFOCLASS ProcessInformationClass,
#   _In_      PVOID            ProcessInformation
#   _In_      ULONG            ProcessInformationLength
# );
@winsdkapi(cc=STDCALL, params={
    'ProcessHandle'            : HANDLE,
    'ProcessInformationClass'  : PROCESSINFOCLASS,
    'ProcessInformation'       : PVOID,
    'ProcessInformationLength' : ULONG
})
def hook_ZwSetInformationProcess(ql: Qiling, address: int, params):
    _SetInformationProcess(ql, address, params)

@winsdkapi(cc=STDCALL, params={
    'ProcessHandle'            : HANDLE,
    'ProcessInformationClass'  : PROCESSINFOCLASS,
    'ProcessInformation'       : PVOID,
    'ProcessInformationLength' : ULONG
})
def hook_NtSetInformationProcess(ql: Qiling, address: int, params):
    _SetInformationProcess(ql, address, params)

def _SetInformationProcess(ql: Qiling, address: int, params):
    process = params["ProcessHandle"]
    flag = params["ProcessInformationClass"]
    ibuf_ptr = params["ProcessInformation"]
    ibuf_len = params["ProcessInformationLength"]

    if flag == ProcessDebugFlags:
        flag_name = 'ProcessDebugFlags'
        comment = ''
        read_len = 4

    elif flag == ProcessDebugPort:
        flag_name = 'ProcessDebugPort'
        comment = ''
        read_len = 4

    elif flag == ProcessDebugObjectHandle:
        return STATUS_PORT_NOT_SET

    elif flag == ProcessBreakOnTermination:
        flag_name = 'ProcessBreakOnTermination'
        comment = 'the critical flag of the process'
        read_len = 1    # FIXME: is it really a single-byte data?

    elif flag == ProcessExecuteFlags:
        flag_name = 'ProcessExecuteFlags'
        comment = 'DEP for the process'
        read_len = 1

    elif flag == ProcessBasicInformation:
        flag_name = 'ProcessBasicInformation'
        comment = 'PEB debug flag for the process'

        pbi_struct = structs.make_process_basic_info(ql.arch.bits)
        read_len = pbi_struct.sizeof()

    else:
        # TODO: support more info class ("flag") values
        ql.log.info(f'SetInformationProcess: no implementation for info class {flag:#04x}')

        return STATUS_UNSUCCESSFUL

    if ibuf_len >= read_len:
        data = (ql.mem.read_ptr if read_len in (1, 2, 4, 8) else ql.mem.read)(ibuf_ptr, read_len)

        ql.log.debug(f'SetInformationProcess: {flag_name} was set to {data}')

        if comment:
            ql.log.debug(f'The target may be attempting modify {comment}')

        # NOTE: we don't actually change anything

    return STATUS_SUCCESS

# NTSYSAPI
# NTSTATUS
# NTAPI
# NtYieldExecution(
#  );
@winsdkapi(cc=STDCALL, params={})
def hook_ZwYieldExecution(ql: Qiling, address: int, params):
    # FIXME: offer timeslice of this thread
    return STATUS_NO_YIELD_PERFORMED

# NTSTATUS LdrGetProcedureAddress(
#  IN HMODULE              ModuleHandle,
#  IN PANSI_STRING         FunctionName OPTIONAL,
#  IN WORD                 Oridinal OPTIONAL,
#  OUT PVOID               *FunctionAddress );
@winsdkapi(cc=STDCALL, params={
    'ModuleHandle'    : HMODULE,
    'FunctionName'    : PANSI_STRING,
    'Ordinal'         : WORD,
    'FunctionAddress' : POINTER
})
def hook_LdrGetProcedureAddress(ql: Qiling, address: int, params):
    ModuleHandle = params['ModuleHandle']
    FunctionName = params['FunctionName']
    Ordinal = params['Ordinal']
    FunctionAddress = params['FunctionAddress']

    # Check if dll is loaded
    dll_name = next((os.path.basename(path).casefold() for base, _, path in ql.loader.images if base == ModuleHandle), None)

    if dll_name is None:
        ql.log.debug(f'Could not find specified handle {ModuleHandle} in loaded DLL')
        return STATUS_DLL_NOT_FOUND

    identifier = utils.read_pansi_string(ql, FunctionName) if FunctionName else Ordinal
    iat = ql.loader.import_address_table[dll_name]

    if not identifier:
        return STATUS_INVALID_PARAMETER

    if identifier not in iat:
        return STATUS_PROCEDURE_NOT_FOUND

    ql.mem.write_ptr(FunctionAddress, iat[identifier])

    return STATUS_SUCCESS


# NTSYSAPI PVOID RtlAllocateHeap(
#  PVOID  HeapHandle,
#  ULONG  Flags,
#  SIZE_T Size
# );
@winsdkapi(cc=STDCALL, params={
    'HeapHandle' : PVOID,
    'Flags'      : ULONG,
    'Size'       : SIZE_T
})
def hook_RtlAllocateHeap(ql: Qiling, address: int, params):
    return ql.os.heap.alloc(params["Size"])

# wchar_t* wcsstr( const wchar_t* dest, const wchar_t* src );
@winsdkapi(cc=STDCALL, params={
    'dest' : POINTER, # WSTRING
    'src'  : WSTRING
})
def hook_wcsstr(ql: Qiling, address: int, params):
    dest = params["dest"]
    src = params["src"]

    dest_str = ql.os.utils.read_wstring(dest)

    if src in dest_str:
        return dest + dest_str.index(src)

    return 0

# HANDLE CsrGetProcessId();
@winsdkapi(cc=STDCALL, params={})
def hook_CsrGetProcessId(ql: Qiling, address: int, params):
    pid = ql.os.profile["PROCESSES"].getint("csrss.exe", fallback=12345)
    return pid

# TODO:
# 适配如下函数：
# EventRegister	kernelbase
# ZwWaitForAlertByThreadId	ntdll
# ZwQueryKey	ntdll
# ZwCreateFile	ntdll
# ZwNotifyChangeKey	ntdll
# ZwQueryAttributesFile	ntdll
# RtlReleaseSRWLockExclusive	ntdll
# RegisterTraceGuidsW	kernelbase
# EventRegister	kernelbase

# NTSYSAPI NTSTATUS ZwNotifyChangeKey(
#   [in]            HANDLE           KeyHandle,
#   [in, optional]  HANDLE           Event,
#   [in, optional]  PIO_APC_ROUTINE  ApcRoutine,
#   [in, optional]  PVOID            ApcContext,
#   [out]           PIO_STATUS_BLOCK IoStatusBlock,
#   [in]            ULONG            CompletionFilter,
#   [in]            BOOLEAN          WatchTree,
#   [out, optional] PVOID            Buffer,
#   [in]            ULONG            BufferSize,
#   [in]            BOOLEAN          Asynchronous
# );
@winsdkapi(cc=STDCALL, params={
    'KeyHandle'       : HANDLE,
    'Event'           : HANDLE,
    'ApcRoutine'      : PIO_APC_ROUTINE,
    'ApcContext'      : PVOID,
    'IoStatusBlock'   : PIO_STATUS_BLOCK,
    'CompletionFilter': ULONG,
    'WatchTree'       : BOOLEAN,
    'Buffer'          : PVOID,
    'BufferSize'      : ULONG,
    'Asynchronous'    : BOOLEAN
})
def hook_ZwNotifyChangeKey(ql: Qiling, address: int, params):
    return STATUS_SUCCESS

# void ReleaseSRWLockExclusive(
#   PSRWLOCK SRWLock
# );
@winsdkapi(cc=STDCALL, params={
    'SRWLock' : PSRWLOCK
})
def hook_RtlReleaseSRWLockExclusive(ql: Qiling, address: int, params):
    return

# NTSYSAPI NTSTATUS ZwCreateFile(
#   [out]          PHANDLE            FileHandle,
#   [in]           ACCESS_MASK        DesiredAccess,
#   [in]           POBJECT_ATTRIBUTES ObjectAttributes,
#   [out]          PIO_STATUS_BLOCK   IoStatusBlock,
#   [in, optional] PLARGE_INTEGER     AllocationSize,
#   [in]           ULONG              FileAttributes,
#   [in]           ULONG              ShareAccess,
#   [in]           ULONG              CreateDisposition,
#   [in]           ULONG              CreateOptions,
#   [in, optional] PVOID              EaBuffer,
#   [in]           ULONG              EaLength
# );
@winsdkapi(cc=STDCALL, params={
    'FileHandle'        : PHANDLE,
    'DesiredAccess'     : ACCESS_MASK,
    'ObjectAttributes'  : POBJECT_ATTRIBUTES,
    'IoStatusBlock'     : PIO_STATUS_BLOCK,
    'AllocationSize'    : PLARGE_INTEGER,
    'FileAttributes'    : ULONG,
    'ShareAccess'       : ULONG,
    'CreateDisposition' : ULONG,
    'CreateOptions'     : ULONG,
    'EaBuffer'          : PVOID,
    'EaLength'          : ULONG
})
def hook_ZwCreateFile(ql: Qiling, address: int, params):
    param_hFileHandle = params['FileHandle']
    param_dwDesiredAccess = params['DesiredAccess']
    param_dwCreationDisposition = params['CreateDisposition']
    param_dwCreationOptions = params['CreateOptions']

    perm_write = param_dwDesiredAccess & GENERIC_WRITE
    perm_read  = param_dwDesiredAccess & GENERIC_READ
    perm_exec = param_dwDesiredAccess & GENERIC_EXECUTE

    handle = ql.os.handle_manager.get(param_hFileHandle)

    if handle is None:
        return ERROR_INVALID_HANDLE
    
    return STATUS_SUCCESS

# undocumented
# NTSYSCALLAPI
# NTSTATUS
# NTAPI
# ZwWaitForAlertByThreadId(
#     _In_ PVOID Address,
#     _In_opt_ PLARGE_INTEGER Timeout
#     );
@winsdkapi(cc=STDCALL, params={
    'Address' : PVOID,
    'Timeout' : PLARGE_INTEGER
})
# Crtical, this function has been called with error for 82+39 times
def hook_ZwWaitForAlertByThreadId(ql: Qiling, address: int, params):
    if(not ql.multithread):
        # 如果未启用多线程，则返回错误
        return STATUS_INVALID_THREAD
    # TODO : refractor multi-thread construct, allows notify
    return STATUS_SUCCESS

# NTSYSAPI NTSTATUS ZwQueryKey(
#   [in]            HANDLE                KeyHandle,
#   [in]            KEY_INFORMATION_CLASS KeyInformationClass,
#   [out, optional] PVOID                 KeyInformation,
#   [in]            ULONG                 Length,
#   [out]           PULONG                ResultLength
# );
@winsdkapi(cc=STDCALL, params={
    'KeyHandle'          : HANDLE,
    'KeyInformationClass': KEY_INFORMATION_CLASS,
    'KeyInformation'     : PVOID,
    'Length'             : ULONG,
    'ResultLength'       : PULONG
})
def hook_ZwQueryKey(ql: Qiling, address: int, params):
    # due to incomplete registry implementation, this function failed.
    return STATUS_REGISTRY_CORRUPT
    return STATUS_SUCCESS

# NTSYSAPI NTSTATUS ZwQueryFullAttributesFile(
#   [in]  POBJECT_ATTRIBUTES             ObjectAttributes,
#   [out] PFILE_NETWORK_OPEN_INFORMATION FileInformation
# );
@winsdkapi(cc=STDCALL, params={
    'ObjectAttributes' : POBJECT_ATTRIBUTES,
    'FileInformation'   : PFILE_NETWORK_OPEN_INFORMATION
})
def hook_ZwQueryAttributesFile(ql: Qiling, address: int, params):
    return ERROR_FILE_NOT_FOUND
    return STATUS_SUCCESS

#RtlInitializeCriticalSection