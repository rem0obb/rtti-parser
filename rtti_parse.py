from rtti_parser_core.vtable import TypeInfoVtable
from rtti_parser_core.elf import read_elf_sym_crossplatform
from rtti_parser_core.common import search, demangle
from rtti_parser_core.rtti import BasicClass, SiClass, VmiClass
import time
import logging

import idc
import idautils
import ida_name
import ida_ida
import ida_bytes
import idaapi
import ida_segment


idaapi.require('rtti_parser_core.binary_stream')
idaapi.require('rtti_parser_core.vtable')
idaapi.require('rtti_parser_core.consts')
idaapi.require('rtti_parser_core.elf')
idaapi.require('rtti_parser_core.common')
idaapi.require('rtti_parser_core.rtti')


class TiClassKind:
    CLASS_TYPE = '__class_type_info'
    # CLASS_TYPE = '_ZTVN10__cxxabiv117__class_type_infoE'
    # SI_CLASS_TYPE = '_ZTVN10__cxxabiv120__si_class_type_infoE'
    SI_CLASS_TYPE = '__si_class_type_infoE'
    # VMI_CLASS_TYPE = '_ZTVN10__cxxabiv121__vmi_class_type_infoE'
    VMI_CLASS_TYPE = '__vmi_class_type_infoE'


"""
These are symbols, that used to find typeinfos and vtables
"""
symbol_table = {
    TiClassKind.CLASS_TYPE: BasicClass,
    TiClassKind.SI_CLASS_TYPE: SiClass,
    TiClassKind.VMI_CLASS_TYPE: VmiClass
}

typeinfo_counter = 0
vtable_counter = 0
func_counter = 0


def sanitize_ea(ea):
    """Convert tuple/str to integer EA and avoid crashes on IDA 9.2."""
    if ea is None:
        return idc.BADADDR

    if isinstance(ea, int):
        return ea

    if isinstance(ea, tuple):
        for item in ea:
            if isinstance(item, int):
                return item
            try:
                return int(item)
            except:
                pass
        return idc.BADADDR

    if isinstance(ea, str):
        try:
            return int(ea, 16)
        except:
            return idc.BADADDR

    try:
        return int(ea)
    except:
        return idc.BADADDR


def XrefsToCompat(ea):
    """IDA 9.2 requires the flags parameter sometimes."""
    try:
        return idautils.XrefsTo(ea, 0)
    except TypeError:
        return idautils.XrefsTo(ea)


def get_item_head_compat(ea):
    """IDA 9.2 sometimes requires int only."""
    ea = sanitize_ea(ea)
    try:
        return ida_bytes.get_item_head(ea)
    except:
        try:
            return ida_bytes.get_item_head(int(ea))
        except:
            return idc.BADADDR
            
def process_class_info(symbol_name, ea):
    global typeinfo_counter, vtable_counter, func_counter

    for typeinfo_ea in XrefsToCompat(ea):
        if typeinfo_ea.frm == idc.BADADDR:
            continue

        classtype = symbol_table[symbol_name](typeinfo_ea.frm)

        # skip this one, because name hasn't been read.
        if not classtype.read_name():
            print(
                f'Failed to read name of typeinfo. mangled is: {classtype.type_name} at {hex(typeinfo_ea.frm)}'
            )
            continue
        # will get rid of global variables later
        typeinfo_counter += 1

        classtype.read_typeinfo()

        print(f'Found typeinfo for {classtype.dn_name} at {hex(typeinfo_ea.frm)}')

        # read vtable
        if not classtype.read_vtable():
            print(
                f'Failed to find vtable for {classtype.dn_name}'
            )
            continue

        vtable_counter += 1
        func_counter += len(classtype.vtable.entries)

        # create struct for vtable
        if classtype.create_vtable_struct():
            # retype functions
            classtype.retype_vtable_functions()
        else:
            print(
                f'vtable struct for {classtype.dn_name} not created !')


def process():
    start_time = time.time()
    for symbol_name in symbol_table:
        addr_ea = search(symbol_name)
        # get start of the string
        addr_ea = get_item_head_compat(addr_ea)
        print(f'Found {symbol_name} at {hex(addr_ea)}')

        # get only firest xref
        elf_sym_struct_ea = next(XrefsToCompat(addr_ea), None)
        if not elf_sym_struct_ea:
            print(
                f'No Code refs found for {symbol_name}'
            )
            continue

        # parse Elf<64/32>_Sym struct
        elf_sym_s = read_elf_sym_crossplatform(
            elf_sym_struct_ea.frm)

        if not elf_sym_s or elf_sym_s.st_value == idc.BADADDR:
            print(
                f'No st_value in Elf Sym struct. ea: {hex(elf_sym_struct_ea.frm)}. elf_sym struct: {elf_sym_s}')
            continue

        print(f'elf_sym_s address is: {hex(elf_sym_s.st_value)}')

        typeinfo_vtable = TypeInfoVtable(
            symbol_name, demangle(symbol_name), elf_sym_s.st_value)

        typeinfo_vtable.read()
        # using typeinfo offset to search for other typeinfos
        process_class_info(symbol_name, typeinfo_vtable.typeinfo_offset_ea)

    print(f'Completed in {round(time.time() - start_time, 2)}s')
    print(f'Total new classes: {typeinfo_counter}\n\
Total vtables: {vtable_counter}\n\
Total reanmed funcitons {func_counter}')


class BetterRTTIParserPlugin(idaapi.plugin_t):
    flags = 0
    comment = 'Parse RTTI information from executable'
    help = 'Parse RTTI information from executable'
    wanted_name = 'Better RTTI Parser'
    wanted_hotkey = ''

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        process()

    def term(self):
        pass

def PLUGIN_ENTRY():
    try:
        return BetterRTTIParserPlugin()

    except Exception as err:
        import traceback
        print('rtti_parse.py Error: %s\n%s' % str((err), traceback.format_exc()))
        raise

if __name__ == '__main__':
    process()