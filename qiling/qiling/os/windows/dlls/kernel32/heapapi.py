#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *

# HANDLE HeapCreate(
#   DWORD  flOptions,
#   SIZE_T dwInitialSize,
#   SIZE_T dwMaximumSize
# );
@winsdkapi(cc=STDCALL, params={
    'flOptions'     : DWORD,
    'dwInitialSize' : SIZE_T,
    'dwMaximumSize' : SIZE_T
})
def hook_HeapCreate(ql: Qiling, address: int, params):
    dwInitialSize = params["dwInitialSize"]

    return ql.os.heap.alloc(dwInitialSize)

# DECLSPEC_ALLOCATOR LPVOID HeapAlloc(
#   HANDLE hHeap,
#   DWORD  dwFlags,
#   SIZE_T dwBytes
# );
@winsdkapi(cc=STDCALL, params={
    'hHeap'   : HANDLE,
    'dwFlags' : DWORD,
    'dwBytes' : SIZE_T
})
def hook_HeapAlloc(ql: Qiling, address: int, params):
    dwBytes = params["dwBytes"]

    return ql.os.heap.alloc(dwBytes)

# SIZE_T HeapSize(
#   HANDLE  hHeap,
#   DWORD   dwFlags,
#   LPCVOID lpMem
# );
@winsdkapi(cc=STDCALL, params={
    'hHeap'   : HANDLE,
    'dwFlags' : DWORD,
    'lpMem'   : LPCVOID
})
def hook_HeapSize(ql: Qiling, address: int, params):
    pointer = params["lpMem"]

    return ql.os.heap.size(pointer)

# BOOL HeapFree(
#  HANDLE                 hHeap,
#  DWORD                  dwFlags,
#  _Frees_ptr_opt_ LPVOID lpMem
# );
@winsdkapi(cc=STDCALL, params={
    'hHeap'   : HANDLE,
    'dwFlags' : DWORD,
    'lpMem'   : LPVOID
})
def hook_HeapFree(ql: Qiling, address: int, params):
    lpMem = params['lpMem']

    return ql.os.heap.free(lpMem)

# BOOL HeapSetInformation(
#  HANDLE                 HeapHandle,
#  HEAP_INFORMATION_CLASS HeapInformationClass,
#  PVOID                  HeapInformation,
#  SIZE_T                 HeapInformationLength
# );
@winsdkapi(cc=STDCALL, params={
    'HeapHandle'            : HANDLE,
    'HeapInformationClass'  : HEAP_INFORMATION_CLASS,
    'HeapInformation'       : PVOID,
    'HeapInformationLength' : SIZE_T
})
def hook_HeapSetInformation(ql: Qiling, address: int, params):
    return 1

# HANDLE GetProcessHeap(
# );
@winsdkapi(cc=STDCALL, params={})
def hook_GetProcessHeap(ql: Qiling, address: int, params):
    return ql.os.heap.start_address

# DECLSPEC_ALLOCATOR LPVOID HeapReAlloc(
#   [in] HANDLE                 hHeap,
#   [in] DWORD                  dwFlags,
#   [in] _Frees_ptr_opt_ LPVOID lpMem,
#   [in] SIZE_T                 dwBytes
# );
@winsdkapi(cc=STDCALL, params={
    'hHeap'   : HANDLE,
    'dwFlags' : DWORD,
    'lpMem'   : LPVOID,
    'dwBytes' : SIZE_T
})
def hook_HeapReAlloc(ql: Qiling, address: int, params):
    lpMem = params['lpMem']
    dwBytes = params['dwBytes']
    
    #hHeap is ignored, check if needed
    #dwFlags is ignored, check if needed
    # Value	Meaning
    # HEAP_GENERATE_EXCEPTIONS
    # 0x00000004
    # The operating-system raises an exception to indicate a function failure, such as an out-of-memory condition, instead of returning NULL.
    # To ensure that exceptions are generated for all calls to this function, specify HEAP_GENERATE_EXCEPTIONS in the call to HeapCreate. In this case, it is not necessary to additionally specify HEAP_GENERATE_EXCEPTIONS in this function call.

    # HEAP_NO_SERIALIZE
    # 0x00000001
    # Serialized access will not be used. For more information, see Remarks.
    # To ensure that serialized access is disabled for all calls to this function, specify HEAP_NO_SERIALIZE in the call to HeapCreate. In this case, it is not necessary to additionally specify HEAP_NO_SERIALIZE in this function call.

    # This value should not be specified when accessing the process heap. The system may create additional threads within the application's process, such as a CTRL+C handler, that simultaneously access the process heap.

    # HEAP_REALLOC_IN_PLACE_ONLY
    # 0x00000010
    # There can be no movement when reallocating a memory block. If this value is not specified, the function may move the block to a new location. If this value is specified and the block cannot be resized without moving, the function fails, leaving the original memory block unchanged.
    # HEAP_ZERO_MEMORY
    # 0x00000008
    # If the reallocation request is for a larger size, the additional region of memory beyond the original size be initialized to zero. The contents of the memory block up to its original size are unaffected.

    return ql.os.heap.realloc(lpMem, dwBytes)