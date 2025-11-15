import idaapi

def is_64bit():
    # IDA 9.2
    if hasattr(idaapi, "inf_is_64bit"):
        return idaapi.inf_is_64bit()

    # IDA 7.x / 8.x
    info = idaapi.get_inf_structure()
    return info.is_64bit()

BIT64_MODE = is_64bit()

print(BIT64_MODE)

if BIT64_MODE:
    PTR_SIZE = 8
    BAD_RET = 0xffffffffffffffff
else:
    PTR_SIZE = 4
    BAD_RET = 0xffffffff