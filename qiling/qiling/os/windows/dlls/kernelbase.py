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
from qiling.os.windows.const import *
from qiling.os.windows.handle import *
from qiling.os.windows import structs
from qiling.os.windows import utils

# ULONG WMIAPI RegisterTraceGuidsW(
#   [in]      WMIDPREQUEST             RequestAddress,
#   [in]      PVOID                    RequestContext,
#   [in]      LPCGUID                  ControlGuid,
#   [in]      ULONG                    GuidCount,
#   [in, out] PTRACE_GUID_REGISTRATION TraceGuidReg,
#   [in]      LPCWSTR                  MofImagePath,
#   [in]      LPCWSTR                  MofResourceName,
#   [out]     PTRACEHANDLE             RegistrationHandle
# );
@winsdkapi(cc=STDCALL, params={
    'RequestAddress'    : WMIDPREQUEST,
    'RequestContext'    : PVOID,
    'ControlGuid'       : LPCGUID,
    'GuidCount'         : ULONG,
    'TraceGuidReg'      : PTRACE_GUID_REGISTRATION,
    'MofImagePath'      : LPCWSTR,
    'MofResourceName'   : LPCWSTR,
    'RegistrationHandle': PTRACEHANDLE
})
def hook_RegisterTraceGuidsW(ql: Qiling, address: int, params):
    return 0


# ULONG EVNTAPI EventRegister(
#   [in]           LPCGUID         ProviderId,
#   [in, optional] PENABLECALLBACK EnableCallback,
#   [in, optional] PVOID           CallbackContext,
#   [out]          PREGHANDLE      RegHandle
# );
@winsdkapi(cc=STDCALL, params={
    'ProviderId' : LPCGUID,
    'EnableCallback' : PENABLECALLBACK,
    'CallbackContext' : PVOID,
    'RegHandle' : PREGHANDLE
})
def hook_EventRegister(ql:Qiling, address: int, params):
    return STATUS_SUCCESS
# TODO:
# PENABLECALLBACK, PREGHANDLE is not defined in this framework.