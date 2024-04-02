#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import base64

from qiling import Qiling
from qiling.exception import QlErrorNotImplemented
from qiling.os.windows.api import *
from qiling.qiling.os.windows.consts.const import CRYPT_STRING_BASE64
from qiling.os.windows.fncc import *

def _CryptStringToBinary(ql: Qiling, address: int, params) -> int:
    flag_src = params["dwFlags"]
    string_src = params["pszString"]
    size_src = params["cchString"]
    size_dst_pointer = params["pcbBinary"]
    string_dst = params["pbBinary"]
    flag_dst = params["pdwFlags"]

    size_dst = ql.mem.read_ptr(size_dst_pointer, 4)

    if size_dst and size_dst < size_src:
        raise QlErrorNotImplemented("API not implemented")

    if flag_src == CRYPT_STRING_BASE64:
        # Had a padding error, hope this always works
        add_pad = 4 - (len(string_src) % 4)
        if add_pad != 4:
            string_src += "=" * add_pad
        output = base64.b64decode(string_src).decode("utf-16le") + "\x00"
    else:
        ql.log.debug("Flag")
        ql.log.debug(flag_src)
        raise QlErrorNotImplemented("API not implemented")

    if string_dst == 0:
        # Only wants the length
        return len(output)
    else:
        if flag_dst:
            # Is optional
            ql.mem.write_ptr(flag_dst, flag_src, 4)

        # Write size
        ql.mem.write_ptr(size_dst_pointer, len(output), 4)

        # Write result
        ql.mem.write(string_dst, bytes(output, encoding="utf-16le"))
    return 1

# BOOL CryptStringToBinaryA(
#   LPCSTR pszString,
#   DWORD  cchString,
#   DWORD  dwFlags,
#   BYTE   *pbBinary,
#   DWORD  *pcbBinary,
#   DWORD  *pdwSkip,
#   DWORD  *pdwFlags
# );
@winsdkapi(cc=STDCALL, params={
    'pszString' : LPCSTR,
    'cchString' : DWORD,
    'dwFlags'   : DWORD,
    'pbBinary'  : PBYTE,
    'pcbBinary' : PDWORD,
    'pdwSkip'   : PDWORD,
    'pdwFlags'  : PDWORD
})
def hook_CryptStringToBinaryA(ql: Qiling, address: int, params):
    return _CryptStringToBinary(ql, address, params)

@winsdkapi(cc=STDCALL, params={
    'pszString' : LPCWSTR,
    'cchString' : DWORD,
    'dwFlags'   : DWORD,
    'pbBinary'  : PBYTE,
    'pcbBinary' : PDWORD,
    'pdwSkip'   : PDWORD,
    'pdwFlags'  : PDWORD
})
def hook_CryptStringToBinaryW(ql: Qiling, address: int, params):
    return _CryptStringToBinary(ql, address, params)
