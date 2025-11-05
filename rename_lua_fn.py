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
from ghidra.program.model.listing import (Program, Function)
state = getState()
program = state.getCurrentProgram()
fpapi = FlatProgramAPI(program)
fdapi = FlatDecompilerAPI(fpapi)
addressFactory = program.getAddressFactory();
space = addressFactory.getDefaultAddressSpace();
fm = program.getFunctionManager()
dtm = program.getDataTypeManager()
def create_type(dtm, name, size):
    existing = dtm.getDataType("noita.exe/custom/" + name)
    if existing is None:
        category = CategoryPath("/noita.exe/custom")
        struct = StructureDataType(category, name, size)
        struct = dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER)
    else:
        struct = existing
    return struct
type = create_type(dtm, "lua_state", 4)
def pascal_to_snake(s):
    return re.sub('([a-z])([A-Z])', r'\1_\2', s).lower()
addr = space.getAddress(0x007ea410);
fn = fpapi.getFunctionAt(addr)
fn.setName("register_lua_functions", SourceType.USER_DEFINED)
sig = fn.getSignature()
args = sig.getArguments()
args[0].setName("lua_state")
args[0].setDataType(type)
#fn.updateFunction(sig.getCallingConventionName(), sig.getReturnType(), args, Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True, SourceType.USER_DEFINED)
decompiled = fdapi.decompile(fn)
while True:
    target = "lua_pushcclosure(param_1,"
    start = decompiled.find(target)
    if start == -1:
        break
    decompiled = decompiled[start+len(target):]
    comma = decompiled.find(',')
    fn_addr = decompiled[:comma]
    fn = fpapi.getFunction(fn_addr)
    sig = fn.getSignature()
    args = sig.getArguments()
    if len(args) != 0:
        args[0].setName("lua_state")
        args[0].setDataType(type)
        #fn.updateFunction(sig.getCallingConventionName(), sig.getReturnType(), args, Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True, SourceType.USER_DEFINED)
    start_name = decompiled.find('"')
    decompiled = decompiled[start_name+1:]
    end_name = decompiled.find('"')
    name = decompiled[:end_name]
    fn.setName("lua_" + pascal_to_snake(name), SourceType.USER_DEFINED)
