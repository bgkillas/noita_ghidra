import re
import ghidra
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.app.script import GhidraState
from ghidra.app.util.cparser.C import CParser
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import (Address, AddressFactory, AddressSpace)
from ghidra.program.model.data import (
    ArrayDataType,
    DataTypeConflictHandler,
    DataTypeManager,
    StringDataType,
    StructureDataType,
    CategoryPath,
)
from ghidra.program.model.listing import Program
state = getState()
program = state.getCurrentProgram()
fpapi = FlatProgramAPI(program)
fdapi = FlatDecompilerAPI(fpapi)
addressFactory = program.getAddressFactory();
space = addressFactory.getDefaultAddressSpace();
fm = program.getFunctionManager()
def pascal_to_snake(s):
    return re.sub('([a-z])([A-Z])', r'\1_\2', s).lower()
addr = space.getAddress(0x007ea410);
fn = fpapi.getFunctionAt(addr)
fn.setName("register_lua_functions", SourceType.USER_DEFINED)
decompiled = fdapi.decompile(fn)
while True:
    start = decompiled.find("FUN_")
    if start == -1:
        break
    decompiled = decompiled[start+4:]
    comma = decompiled.find(',')
    fn_addr = int(decompiled[:comma], 16)
    addr = space.getAddress(fn_addr);
    fn = fpapi.getFunctionAt(addr)
    start_name = decompiled.find('"')
    decompiled = decompiled[start_name+1:]
    end_name = decompiled.find('"')
    name = decompiled[:end_name]
    fn.setName("lua" + pascal_to_snake(name), SourceType.USER_DEFINED)
