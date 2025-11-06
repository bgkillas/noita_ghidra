import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;

public class RenameLuaFn extends GhidraScript {
    protected void run() throws Exception {
        GhidraState gstate = this.getState();
        Program program = gstate.getCurrentProgram();
        FlatProgramAPI fpapi = new FlatProgramAPI(program);
        FlatDecompilerAPI fdapi = new FlatDecompilerAPI(fpapi);
        AddressFactory addressFactory = program.getAddressFactory();
        AddressSpace space = addressFactory.getDefaultAddressSpace();
        ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
        DataType type = new PointerDataType(this.create_type(dtm, "lua_state", 4), dtm);
        Address addr = space.getAddress(0x007ea410);
        Function fn = fpapi.getFunctionAt(addr);
        fn.setName("register_lua_functions", SourceType.USER_DEFINED);
        FunctionSignature sig = fn.getSignature();
        ParameterDefinition[] args = sig.getArguments();
        args[0].setName("lua_state");
        args[0].setDataType(type);
        FunctionDefinitionDataType fddt = new FunctionDefinitionDataType(sig);
        fddt.setArguments(args);
        ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(fn.getEntryPoint(), fddt, SourceType.USER_DEFINED);
        this.runCommand(cmd);
        String decompiled = fdapi.decompile(fn);

        while(true) {
            String target = "lua_pushcclosure(";
            int start = decompiled.indexOf(target);
            if (start == -1) {
                return;
            }

            decompiled = decompiled.substring(start + target.length());
            int comma = decompiled.indexOf(44);
            decompiled = decompiled.substring(comma + 1);
            comma = decompiled.indexOf(44);
            String fn_addr = decompiled.substring(0, comma);
            Function lua_fn = fpapi.getGlobalFunctions(fn_addr).get(0);
            FunctionSignature lua_sig = lua_fn.getSignature();
            ParameterDefinition[] lua_args = lua_sig.getArguments();
            if (lua_args.length != 0) {
                lua_args[0].setName("lua_state");
                lua_args[0].setDataType(type);
                FunctionDefinitionDataType lua_fddt = new FunctionDefinitionDataType(lua_sig);
                lua_fddt.setArguments(lua_args);
                ApplyFunctionSignatureCmd lua_cmd = new ApplyFunctionSignatureCmd(lua_fn.getEntryPoint(), lua_fddt, SourceType.USER_DEFINED);
                this.runCommand(lua_cmd);
            }

            int start_name = decompiled.indexOf(34);
            decompiled = decompiled.substring(start_name + 1);
            int end_name = decompiled.indexOf(34);
            String name = decompiled.substring(0, end_name);
            lua_fn.setName("lua_" + pascal_to_snake(name), SourceType.USER_DEFINED);
        }
    }

    DataType create_type(ProgramBasedDataTypeManager dtm, String name, int size) {
        DataType existing = dtm.getDataType("noita.exe/custom/" + name);
        if (existing != null) {
            return existing;
        }
        CategoryPath category = new CategoryPath("/noita.exe/custom");
        StructureDataType struct = new StructureDataType(category, name, size);
        return dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
    }

    public static String pascal_to_snake(String input) {
        return input.replaceAll("([a-z0-9])([A-Z])", "$1_$2").replaceAll("([A-Z])([A-Z][a-z])", "$1_$2").toLowerCase();
    }
}
