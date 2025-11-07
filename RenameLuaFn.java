import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.stream.Stream;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class RenameLuaFn extends GhidraScript {
    GhidraState gstate;
    Program program;
    FlatProgramAPI fpapi;
    FlatDecompilerAPI fdapi;
    AddressFactory addressFactory;
    AddressSpace space;
    ProgramBasedDataTypeManager dtm;
    SourceType source = SourceType.USER_DEFINED;
	Map<String, String> map = new HashMap<>();
    DataTypeManagerService svc;
    protected void run() throws Exception {
        gstate = this.getState();
        program = gstate.getCurrentProgram();
        fpapi = new FlatProgramAPI(program);
        fdapi = new FlatDecompilerAPI(fpapi);
        addressFactory = program.getAddressFactory();
        space = addressFactory.getDefaultAddressSpace();
        dtm = program.getDataTypeManager();
        svc = state.getTool().getService(DataTypeManagerService.class);
    	map.put("usize", "uint");
    	map.put("isize", "int");
    	map.put("f32", "float");
    	map.put("f64", "double");
    	for (int i = 8; i < 128; i *= 2) {
    		map.put("u"+i, "uint"+i+"_t");
       		map.put("i"+i, "int"+i+"_t");
    	}
    	System.out.println(map);
        parse_rust();
    	rename_lua_fn();
    	rename_globals();
    	rename_functions();
    }
    
    void parse_rust() throws Exception {
    	String out = "struct T a:*[**u64;3] b:isize c:bool d:char e:u64"
    			+ "\nenum K A:-1 B:0"
    			+ "\nunion Y a:*isize b:usize";
    	Stream<String> lines = out.lines();
    	for (String line : lines.toList()) {
    		String[] split = line.split(" ");
    		String name = split[1];
    		if (name.endsWith(">")) {
    			continue;
    		}
    		if (split[0].equals("struct")) {
    			StructureDataType struct = create_struct(name);
    			for (int i = 2; i < split.length; i++) {
    				String[] pair = split[i].split(":");
    				String component = pair[0];
    				String value = pair[1];
    				DataType type = parse_type(value);
    				struct.add(type, type.getLength(), component, "");
    			}
    			dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
    		} else if (split[0].equals("union")) {
    			UnionDataType union = create_union(name);
    			for (int i = 2; i < split.length; i++) {
    				String[] pair = split[i].split(":");
    				String component = pair[0];
    				String value = pair[1];
    				DataType type = parse_type(value);
    				union.add(type, type.getLength(), component, "");
    			}
    			dtm.addDataType(union, DataTypeConflictHandler.REPLACE_HANDLER);    			
    		} else if (split[0].equals("enum")) {
    			EnumDataType enumt = create_enum(name);
    			for (int i = 2; i < split.length; i++) {
    				String[] pair = split[i].split(":");
    				String component = pair[0];
    				String value = pair[1];
    				enumt.add(component, Long.parseLong(value), "");
    			}
    			dtm.addDataType(enumt, DataTypeConflictHandler.REPLACE_HANDLER);    			    			
    		}
    	}	
    }
    
    DataType parse_type(String name) {
		if (name.startsWith("*")) {
			name = name.substring(1);
			System.out.println(name);
			return new PointerDataType(parse_type(name));
		}
		if (name.startsWith("[") && name.endsWith("]")) {
			name = name.substring(1, name.length() - 1);
			int split = name.lastIndexOf(";");
			int len = Integer.parseInt(name.substring(split+1));
			name = name.substring(0, split);
			System.out.println(name);
			return new ArrayDataType(parse_type(name), len);			
		}
		if (map.containsKey(name)) {
			System.out.println(name);
			name = map.get(name);
			System.out.println(name);
		}
		return get_type(name);
    }

    DataType get_type(String name) {
        for (DataTypeManager datatypemanager : svc.getDataTypeManagers()) {
        	DataType type = find_type_in_manager(datatypemanager, name);
        	if (type != null) {
        		return type;
        	}
        }
        return null;
    }
    
    private DataType find_type_in_manager(DataTypeManager datatypemanager, String name) {
    	System.out.println();
        Iterator<DataType> types = datatypemanager.getAllDataTypes();
        while (types.hasNext()) {
            DataType type = types.next();
            if (type.getName().startsWith("uint")) {
            	System.out.println(name);
            	System.out.println(type.getName());
            	System.out.println(name.length());
            	System.out.println(type.getName().length());
            }
            if (type.getName().equals(name)) {
                return type;
            }
        }
        return null;
    }
    StructureDataType create_struct(String name) {
        CategoryPath category = new CategoryPath("/custom");
        return new StructureDataType(category, name, 0);
    }
    
    EnumDataType create_enum(String name) {
        CategoryPath category = new CategoryPath("/custom");
        return new EnumDataType(category, name, 1);
    }
    
    UnionDataType create_union(String name) {
        CategoryPath category = new CategoryPath("/custom");
        return new UnionDataType(category, name);
    }
    
    void rename_functions() throws Exception {
    	String[] fn_names = {"get_entity", "kill_entity", "create_entity"};
    	long[] fn_addrs = {0x0056eba0, 0x0044df60, 0x0056e590};
    	for (int i = 0; i < fn_addrs.length; i++) {
    		Address addr = space.getAddress(fn_addrs[i]);
    		Function fn = fpapi.getFunctionAt(addr);
    		fn.setName(fn_names[i], source);
    	}
    }

    void rename_globals() throws Exception {
       	String[] names = {"entity_manager_ptr", "world_seed", "new_game_count",
    			"global_stats", "game_global_ptr", "entity_tag_manager_ptr",
    			"component_type_manager", "component_tag_manager_ptr", "translation_manager",
    			"platform", "internal_filenames", "inventory_system",
    			"lua_mods", "max_component_id", "component_system_manager"};
    	long[] addrs = {0x01204b98, 0x1205004, 0x1205024, 
    			0x1208940, 0x122374c, 0x1206fac, 
    			0x1223c88, 0x1204b30, 0x1207c28,
    			0x1221bc0, 0x1207bd4, 0x12224f0,
    			0x1207e90, 0x1152ff0, 0x12236e8};
    	for (int i = 0; i < addrs.length; i++) {
    		Address addr = space.getAddress(addrs[i]);
    		Symbol sym = fpapi.getSymbolAt(addr);
    		sym.setName(names[i], source);
    	}
    }
    
    DataType create_type(String name, int size) {
        DataType existing = dtm.getDataType("custom/" + name);
        if (existing != null) {
            return existing;
        }
        CategoryPath category = new CategoryPath("/custom");
        StructureDataType struct = new StructureDataType(category, name, size);
        return dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
    }

    static String pascal_to_snake(String input) {
        return input.replaceAll("([a-z0-9])([A-Z])", "$1_$2").replaceAll("([A-Z])([A-Z][a-z])", "$1_$2").toLowerCase();
    }
    
    void rename_lua_fn() throws Exception {
        DataType type = new PointerDataType(this.create_type("lua_state", 4), dtm);
        Address addr = space.getAddress(0x007ea410);
        Function fn = fpapi.getFunctionAt(addr);
        fn.setName("register_lua_functions", source);
        FunctionSignature sig = fn.getSignature();
        ParameterDefinition[] args = sig.getArguments();
        args[0].setName("lua_state");
        args[0].setDataType(type);
        FunctionDefinitionDataType fddt = new FunctionDefinitionDataType(sig);
        fddt.setArguments(args);
        ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(fn.getEntryPoint(), fddt, source);
        this.runCommand(cmd);
        String decompiled = fdapi.decompile(fn);

        while(true) {
            String target = "lua_pushcclosure(";
            int start = decompiled.indexOf(target);
            if (start == -1) {
                return;
            }

            decompiled = decompiled.substring(start + target.length());
            int comma = decompiled.indexOf(',');
            decompiled = decompiled.substring(comma + 1);
            comma = decompiled.indexOf(',');
            String fn_addr = decompiled.substring(0, comma);
            Function lua_fn = fpapi.getGlobalFunctions(fn_addr).get(0);
            FunctionSignature lua_sig = lua_fn.getSignature();
            ParameterDefinition[] lua_args = lua_sig.getArguments();
            if (lua_args.length != 0) {
                lua_args[0].setName("lua_state");
                lua_args[0].setDataType(type);
                FunctionDefinitionDataType lua_fddt = new FunctionDefinitionDataType(lua_sig);
                lua_fddt.setArguments(lua_args);
                ApplyFunctionSignatureCmd lua_cmd = new ApplyFunctionSignatureCmd(lua_fn.getEntryPoint(), lua_fddt, source);
                this.runCommand(lua_cmd);
            }

            int start_name = decompiled.indexOf('"');
            decompiled = decompiled.substring(start_name + 1);
            int end_name = decompiled.indexOf('"');
            String name = decompiled.substring(0, end_name);
            lua_fn.setName("lua_" + pascal_to_snake(name), source);
        }
    }
}
