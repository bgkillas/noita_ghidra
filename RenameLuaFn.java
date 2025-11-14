import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Scanner;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class RenameLuaFn extends GhidraScript {
	GhidraState gstate;
	Program program;
	FlatProgramAPI fpapi;
	FlatDecompilerAPI fdapi;
	AddressFactory addressFactory;
	AddressSpace space;
	ProgramBasedDataTypeManager dtm;
	SourceType source = SourceType.USER_DEFINED;
	Map<String, String> type_map = new HashMap<>();
	Map<String, java.util.function.Function<List<String>, DataType>> generic_map = new HashMap<>();
	DataTypeManagerService svc;
	List<String> failed = new ArrayList<>();
	Listing listing;
	SymbolTable table;
	String folder;

	protected void run() throws Exception {
		gstate = this.getState();
		program = gstate.getCurrentProgram();
		fpapi = new FlatProgramAPI(program);
		fdapi = new FlatDecompilerAPI(fpapi);
		addressFactory = program.getAddressFactory();
		space = addressFactory.getDefaultAddressSpace();
		dtm = program.getDataTypeManager();
		svc = state.getTool().getService(DataTypeManagerService.class);
		listing = currentProgram.getListing();
		table = program.getSymbolTable();
		folder = sourceFile.getParentFile().getAbsolutePath();
		type_map.put("usize", "uint");
		type_map.put("isize", "int");
		type_map.put("f32", "float");
		type_map.put("f64", "double");
		type_map.put("c_void", "uint");
		for (int i = 8; i < 128; i *= 2) {
			type_map.put("u" + i, "uint" + i);
			type_map.put("i" + i, "int" + i);
		}
		parse_rust();
		parse_component_doc();
		run_fails();
		rename_lua_fn();
		rename_globals();
		rename_functions();
		parse_vtables();
	}

	boolean vtable_filter(String name) {
		return name.endsWith("Component");
	}

	void parse_vtables() throws Exception {
		Iterator<GhidraClass> iter = table.getClassNamespaces();
		String rust = "use std::fmt::Debug;\n" + "pub trait VFTable: Debug {\n"
				+ "    const VFTABLE_PTR: *const Self;\n" + "    const VFTABLE: Self;\n" + "}\n";
		while (iter.hasNext()) {
			Symbol sym = iter.next().getSymbol();
			if (!vtable_filter(sym.getName())) {
				continue;
			}
			int k = 0;
			for (Symbol s : table.getChildren(sym)) {
				if (s.getName().equals("vftable")) {
					Data dat = fpapi.getDataAt(s.getAddress());
					byte[] bytes = dat.getBytes();
					String def = "impl VFTable for " + sym.getName() + "VFTable";
					rust += "#[derive(Debug)]\n" + "#[repr(C)]\n" + "pub struct " + sym.getName() + "VFTable";
					if (k != 0) {
						rust += k;
						def += k;
					}
					rust += " {\n";
					def += " {\n" + "    const VFTABLE_PTR: *const Self = 0x" + s.getAddress().toString()
							+ " as *const Self;\n";
					def += "    const VFTABLE: Self = Self {\n";
					Map<String, Integer> map = new HashMap<>();
					for (int i = 0; i + 3 < bytes.length; i += 4) {
						byte[] num = { bytes[i + 3], bytes[i + 2], bytes[i + 1], bytes[i] };
						Address addr = addressFactory.getAddress(Integer.toString(ByteBuffer.wrap(num).getInt(), 16));
						String name = "f" + i / 4;
						Function fn = fpapi.getFunctionAt(addr);
						if (!fn.getName().startsWith("FUN_")) {
							name = fn.getName();
						}
						if (map.get(name) != null) {
							int n = map.get(name);
							n += 1;
							map.put(name, n);
							name += n;
						} else {
							map.put(name, 0);
						}
						rust += "    pub " + name + ": " + "*const usize,\n";
						def += "        " + name + ": 0x" + addr.toString() + " as *const usize,\n";
					}
					rust += "}\n";
					def += "    };\n}\n";
					rust += def;
					k += 1;
				}
			}
		}
		Files.writeString(Path.of(folder + "/vftables.rs"), rust);
	}

	void parse_component_doc() throws Exception {
		File file = new File(folder + "/component_documentation.txt");
		Scanner reader = new Scanner(file);
		List<String> components = new ArrayList<>();
		String cur = "";
		while (reader.hasNextLine()) {
			String line = reader.nextLine();
			if (line.length() == 0) {
				components.add(cur.substring(1));
				cur = "";
			} else {
				cur += "\n" + line;
			}
		}
		reader.close();
		String rust = "use crate::noita::types::*;\n";
		for (String com : components) {
			rust += parse_component(com);
		}
		Files.writeString(Path.of(folder + "/components.rs"), rust);
	}

	int parse_hex(String str) {
		if (str.startsWith("0x")) {
			return Integer.parseInt(str.substring(2), 16);
		}
		return Integer.parseInt(str);
	}

	String parse_component(String component) throws Exception {
		String[] lines = component.split("\n");
		String name = lines[0];
		Tuple<StructureDataType, List<Triple<String, Integer, Integer>>> tuple = get_struct(name);
		StructureDataType struct = tuple.a;
		List<Triple<String, Integer, Integer>> list = tuple.b;
		struct.replaceAtOffset(0, parse("ComponentData"), 72, "base", "");
		for (int i = 1; i < lines.length; i++) {
			String line = normalize(lines[i]);
			String[] desc_split = line.split("\"");
			if (!line.contains("\"")) {
				continue;
			}
			String desc;
			if (desc_split.length == 1) {
				desc = "";
			} else {
				desc = desc_split[1];
			}
			line = desc_split[0].trim().replaceAll(" +", " ");
			String[] parts = line.split(" ");
			String type = parts[0];
			String field = parts[1];
			String def = parts[2];
			if (!def.equals("-")) {
				if (desc.length() == 0) {
					desc += "Default: " + def;
				} else if (desc.endsWith(".")) {
					desc += " Default: " + def;
				} else {
					desc += ". Default: " + def;
				}
			}
			int j = 0;
			for (Triple<String, Integer, Integer> tup : list) {
				if (tup.a.equals(field)) {
					break;
				}
				j += 1;
			}
			field = pascal_to_snake(field);
			if (field.equals("type")) {
				field = "arc_type";
			} else if (field.equals("loop")) {
				field = "loops";
			}
			Triple<String, Integer, Integer> tup = list.get(j);
			int field_size = tup.b;
			int field_offset = tup.c;
			boolean array = type.endsWith("ArrayInline");
			type = type.replace("ArrayInline", "");
			DataType data;
			if (type.endsWith("::enum")) {
				data = create_enum_with(type.substring(0, type.length() - 6), field_size);
			} else {
				data = parse(type);
			}
			if (array) {
				data = new ArrayDataType(data, field_size / data.getLength());
			}
			struct.replaceAtOffset(field_offset, data, field_size, field, desc);
		}
		String s = "#[derive(Debug)]\n" + "#[repr(C)]\n" + "pub struct " + name + " {\n";
		for (DataTypeComponent com : struct.getComponents()) {
			if (com.getComment() != null && com.getComment().length() != 0) {
				s += "    //" + com.getComment() + "\n";
			}
			if (com.getFieldName() == null) {
				s += "    " + "f" + Integer.toString(com.getOffset(), 16) + ": u8,\n";
			} else {
				s += "    pub " + com.getFieldName() + ": " + unparse(com.getDataType().getName()) + ",\n";
			}
		}
		s += "}\n";
		for (DataTypeComponent com : struct.getComponents()) {
			if (com.getFieldName() == null) {
				struct.replaceAtOffset(com.getOffset(), parse("u8"), 1, "f" + Integer.toString(com.getOffset(), 16),
						"");
			}
		}
		s += "impl Default for " + name + " {\n" + "    fn default() -> Self {\n" + "        Self {\n";
		for (DataTypeComponent com : struct.getComponents()) {
			String def;
			if (com.getComment() == null) {
				def = "Default::default()";
			} else {
				int n = com.getComment().indexOf("Default: ");
				if (n == -1) {
					def = "Default::default()";
				} else {
					def = com.getComment().substring(n + "Default: ".length());
					if (!def.matches("-*[0-9]*\\.*[0-9]*")) {
						def = "StdString::from_str(\"" + def + "\")";
					} else if (def.matches("-*[0-9]*") && unparse(com.getDataType().getName()).matches("f[0-9]+")) {
						def += ".0";
					} else if (com.getDataType().getName().equals("bool")) {
						if (def.equals("0")) {
							def = "false";
						} else if (def.equals("1")) {
							def = "true";
						}
					}
				}
			}
			s += "            " + com.getFieldName() + ": " + def + ",\n";
		}
		s += "        }\n" + "    }\n" + "}\n";
		s += "impl Component for " + name + " {\n" + "    fn default(base: ComponentData) -> Self {\n"
				+ "        Self {\n" + "            base,\n" + "            ..Default::default()\n" + "        }\n"
				+ "    }\n" + "    const VTABLE: *const ComponentVTable = " + name + "VFTable::VFTABLE_PTR.cast()\n"
				+ "    const NAME: &'static str = \"" + name + "\";\n"
				+ "    const C_NAME: CString = CString::from_str(\"" + name + "\\0\");\n" + "}\n";
		dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
		return s;
	}

	String unparse(String t) {
		if (type_map.containsValue(t)) {
			for (Entry<String, String> entry : type_map.entrySet()) {
				if (entry.getValue().equals(t)) {
					return entry.getKey();
				}
			}
			return null;
		}
		if (t.endsWith(" *")) {
			return "*mut " + unparse(t.substring(0, t.length() - 2));
		}
		if (t.endsWith("*")) {
			return "*mut " + unparse(t.substring(0, t.length() - 1));
		}
		if (t.endsWith("]")) {
			int n = t.lastIndexOf('[');
			int k = Integer.parseInt(t.substring(n + 1, t.length() - 1));
			return "[" + t.substring(0, n) + ";" + k + "]";
		}
		if (t.endsWith(">")) {
			int start = t.indexOf("<");
			return t.substring(0, start + 1) + unparse(t.substring(start + 1, t.length() - 1)) + ">";
		}
		return t;
	}

	Tuple<StructureDataType, List<Triple<String, Integer, Integer>>> get_struct(String name) throws Exception {
		Address vftable = null;
		Symbol sym = table.getClassSymbol(name, null);
		for (Symbol s : table.getChildren(sym)) {
			if (s.getName().equals("vftable")) {
				vftable = s.getAddress();
				break;
			}
		}
		if (vftable == null) {
			return null;
		}
		Reference ref = fpapi.getReferencesTo(vftable)[0];
		Function fun = fpapi.getFunctionContaining(ref.getFromAddress());
		int size = 0;
		for (Reference parent : fpapi.getReferencesTo(fun.getEntryPoint())) {
			Function fn = fpapi.getFunctionContaining(parent.getFromAddress());
			String decomp = fdapi.decompile(fn);
			if (decomp.contains("operator_new(")) {
				decomp = decomp.split("operator_new\\(")[1];
				size = parse_hex(decomp.split("\\)")[0]);
			}
		}
		if (size == 0) {
			String decomp = fdapi.decompile(fun);
			decomp = decomp.split("operator_new\\(")[1];
			size = parse_hex(decomp.split("\\)")[0]);
		}
		StructureDataType struct = create_struct_with(name, size);
		int lua_get = fpapi.getInt(vftable.add(4 * 14));
		Address lua_addr = addressFactory.getAddress(Integer.toString(lua_get, 16));
		Function lua_fn = fpapi.getFunctionAt(lua_addr);
		String lua = fdapi.decompile(lua_fn);
		String[] lines = lua.split("\n");
		int field_size = 0;
		int field_offset = 0;
		String field_name = "";
		List<Triple<String, Integer, Integer>> list = new ArrayList<>();
		for (String line : lines) {
			if (line.contains("}")) {
				if (!line.startsWith(" ")) {
					return new Tuple<>(struct, list);
				}
				list.add(new Triple<>(field_name, field_size, field_offset));
			}
			int start = line.indexOf(",");
			if (start != -1) {
				line = line.substring(start + 1);
				start = line.indexOf(")");
				line = line.substring(0, start);
				if (line.startsWith("\"")) {
					field_name = line.substring(1, line.length() - 1);
				} else {
					Address addr = addressFactory.getAddress(line.substring(6));
					if (addr == null) {
						continue;
					}
					field_name = "";
					byte b = fpapi.getByte(addr);
					while (b != 0) {
						field_name += (char) b;
						addr = addr.add(1);
						b = fpapi.getByte(addr);
					}
				}
			}
			start = line.indexOf("[2]");
			if (start != -1) {
				line = line.substring(start + 6);
				field_size = parse_hex(line.substring(0, line.length() - 1));
			}
			start = line.indexOf("+");
			if (start != -1) {
				line = line.substring(start + 2);
				field_offset = parse_hex(line.substring(0, line.length() - 1));
			}
		}
		return new Tuple<>(struct, list);
	}

	class Tuple<T, K> {
		T a;
		K b;

		Tuple(T a, K b) {
			this.a = a;
			this.b = b;
		}
	}

	class Triple<T, K, V> {
		T a;
		K b;
		V c;

		Triple(T a, K b, V c) {
			this.a = a;
			this.b = b;
			this.c = c;
		}
	}

	String normalize(String line) {
		line = line.trim();
		line = line.replace("std::vector< int >", "std::vector<int>")
				.replace("std::vector< float >", "std::vector<float>").replace("unsigned int", "uint");
		line = line.replace("Vec2", "vec2");
		int n = line.indexOf(" ");
		String[] vecs = { "Vector", "VECTOR", "Vec", "VEC" };
		for (String s : vecs) {
			line = line.substring(0, n).replace(s + "_", "Vec").replace("_" + s, "Vec").replace(s, "Vec")
					+ line.substring(n);
			n = line.indexOf(" ");
		}
		line = line.substring(0, n).replace("TeleportComponentState::Enumstate", "TeleportComponentState::Enum state")
				.replace("PathFindingComponentState::EnummState", "PathFindingComponentState::Enum mState")
				.replace("MSG_QUEUE_PATH_FINDING_RESULTjob_result_receiver",
						"MSG_QUEUE_PATH_FINDING_RESULT job_result_receiver")
				.replace("ParticleEmitter_Animation*m_cached_image_animation",
						"ParticleEmitter_Animation* m_cached_image_animation")
				.replace("PARTICLE_EMITTER_CUSTOM_STYLE::Enumcustom_style",
						"PARTICLE_EMITTER_CUSTOM_STYLE::Enum custom_style")
				.replace("NINJA_ROPE_SEGMENTVecmSegments", "NINJA_ROPE_SEGMENTVec mSegments")
				.replace("MOVETOSURFACE_TYPE::Enumtype", "MOVETOSURFACE_TYPE::Enum type")
				.replace("InvenentoryUpdateListener*update_listener", "InvenentoryUpdateListener* update_listener")
				.replace("EXPLOSION_TRIGGER_TYPE::Enumtrigger", "EXPLOSION_TRIGGER_TYPE::Enum trigger")
				.replace("::Enum", "::enum").replace("std::vector", "StdVec").replace("std::vec", "StdVec")
				.replace("std::set", "StdSet").replace("std_string", "StdString").replace("types::", "")
				.replace("grid::", "").replace("as::", "").replace("std::string", "StdString") + line.substring(n);
		n = line.indexOf(" ");
		if (line.startsWith("Vec")) {
			line = line.replace("Vec", "StdVec<");
			n = line.indexOf(" ");
			line = line.substring(0, n) + ">" + line.substring(n);
		}
		n = line.indexOf(" ");
		if (line.substring(0, n).endsWith("Vec")) {
			line = "StdVec<" + line.replace("Vec", "");
			n = line.indexOf(" ");
			line = line.substring(0, n) + ">" + line.substring(n);
		}
		n = line.indexOf(" ");
		line = line.substring(0, n).replaceAll("([a-z])([A-Z])", "$1_$2").toLowerCase() + line.substring(n);
		Pattern pattern = Pattern.compile("(_|[0-9])([a-z])");
		Matcher matcher = pattern.matcher(line.substring(0, n));
		String res = "";
		int i = 0;
		while (matcher.find()) {
			MatchResult match = matcher.toMatchResult();
			String l;
			if (line.substring(match.start(), match.start() + 1).equals("_")) {
				l = line.substring(match.start() + 1, match.end());
			} else {
				l = line.substring(match.start(), match.end());

			}
			res += line.substring(i, match.start()) + l.toUpperCase();
			i = match.end();
		}
		n = line.indexOf(" ");
		res += line.substring(i, n);
		res = res.substring(0, 1).toUpperCase() + res.substring(1);
		n = res.indexOf("<");
		if (n != -1) {
			res = res.substring(0, n) + res.substring(n, n + 2).toUpperCase() + res.substring(n + 2);
		}
		n = line.indexOf(" ");
		res = res.replace("Uint16", "u16").replace("Uint32T", "u32").replace("Uint32", "u32").replace("Int32", "i32")
				.replace("Int16", "i16").replace("Int64", "i64").replace("Int", "isize").replace("Uint64", "u64")
				.replace("Uint", "usize").replace("Npcparty", "NpcParty").replace("Pendingportal", "PendingPortal")
				.replace("StdString", "Stdstring").replace("String", "Stdstring").replace("Str", "Stdstring")
				.replace("Stdstring", "StdString").replace("Iklimb", "IKLimb")
				.replace("ValueRangeisize", "Valuerange<isize>").replace("ValueRange", "Valuerange<f32>")
				.replace("Valuerange", "ValueRange").replace("Float", "f32").replace("float", "f32")
				.replace("Double", "f64").replace("Entityid", "EntityId").replace("Cutthroughworld", "CutThroughWorld")
				.replace("Jumpparams", "JumpParams").replace("Inventoryitem", "InventoryItem")
				.replace("StackAnimationstate", "StackAnimationState")
				.replace("MapStdStringStdString", "StdMap<StdString,StdString>").replace("Aidata*", "AIData*")
				.replace("AiStateStack", "AIStateStack").replace("ConfigDrug_fx", "ConfigDrugFx")
				.replace("Bool", "bool").replace("Pathnode", "PathNode").replace("Iaabb", "IAABB")
				.replace("Aabb", "AABB").replace("Icell", "ICell").replace("MovetosurfaceType", "MoveToSurfaceType")
				.replace("Fcolor", "Color").replace("Ivec2", "IVec2").replace("OfMaterials", "Materials")
				.replace("Unsigned", "usize") + line.substring(n);
		return res;
	}

	void parse_rust() throws Exception {
		parse_file("/noita_entangled_worlds/noita_api/src/noita/types.rs");
		parse_file("/noita_entangled_worlds/noita_api/src/noita/types/");
	}

	void run_fails() throws Exception {
		for (String com : failed) {
			DataType invKind = dtm.getDataType("/custom/" + com);
			DataIterator it = listing.getData(true);
			while (it.hasNext() && !monitor.isCancelled()) {
				Data d = it.next();
				if (d.getBaseDataType() == invKind) {
					if (d.getLength() != invKind.getLength()) {
						clearListing(d.getMinAddress(), d.getMaxAddress());
						createData(d.getMinAddress(), invKind);
					}
				}
			}
		}
	}

	void parse_file(String file) throws Exception {
		Runtime rt = Runtime.getRuntime();
		String[] commands = { folder + "/target/release/parse", folder + file };
		Process proc = rt.exec(commands);
		BufferedReader std_input = new BufferedReader(new InputStreamReader(proc.getInputStream()));
		List<String> lines = new ArrayList<>();
		String line = null;
		while ((line = std_input.readLine()) != null) {
			if (line.split(" ", 3)[1].contains("<")) {
				register_data_type(line, false);
			} else {
				lines.add(line);
			}
		}
		for (String value : lines) {
			register_data_type(value, false);
		}
	}

	List<String> split_locally(String string, char delim, char lb, char rb) {
		List<String> ret = new ArrayList<>();
		int l = 0;
		int last = 0;
		for (int i = 0; i < string.length(); i++) {
			char c = string.charAt(i);
			if (c == lb) {
				l += 1;
			} else if (c == rb) {
				l -= 1;
			} else if (c == delim && l == 0) {
				ret.add(string.substring(last, i));
				last = i + 1;
			}
		}
		ret.add(string.substring(last));
		return ret;
	}

	DataType register_data_type(final String line, boolean ignore) {
		String[] split = line.split(" ");
		String name = split[1];
		if (name.endsWith(">") && !ignore) {
			int index = name.indexOf("<");
			final String name_no_gen = name.substring(0, index);
			generic_map.put(name_no_gen, values -> {
				List<String> generics = split_locally(name.substring(index + 1, name.length() - 1), ',', '<', '>');
				String join = "";
				for (String s : values) {
					join += s;
					join += ",";
				}
				join = join.substring(0, join.length() - 1);
				String rest = line.split(" ", 3)[2];
				for (int i = 0; i < generics.size(); i++) {
					String generic = generics.get(i);
					String value = values.get(i);
					Pattern pattern = Pattern.compile("[^A-Za-z0-9]" + generic + "([^A-Za-z0-9]|$)");
					Matcher matcher = pattern.matcher(rest);
					while (matcher.find()) {
						int pos = matcher.start() + 1;
						rest = rest.substring(0, pos) + value + rest.substring(pos + generic.length());
						matcher = pattern.matcher(rest);
					}
				}
				String string = split[0] + " " + name_no_gen + "<" + join + ">" + " " + rest;
				return register_data_type(string, true);
			});
			return null;
		}
		if (split[0].equals("struct")) {
			StructureDataType struct = create_struct(name);
			for (int i = 2; i < split.length; i++) {
				String[] pair = split[i].split(":");
				String component = pair[0];
				String value = pair[1];
				DataType type = parse_type(struct, value);
				struct.add(type, type.getLength(), component, "");
			}
			return dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
		} else if (split[0].equals("union")) {
			UnionDataType union = create_union(name);
			for (int i = 2; i < split.length; i++) {
				String[] pair = split[i].split(":");
				String component = pair[0];
				String value = pair[1];
				DataType type = parse_type(union, value);
				union.add(type, type.getLength(), component, "");
			}
			return dtm.addDataType(union, DataTypeConflictHandler.REPLACE_HANDLER);
		} else if (split[0].equals("enum")) {
			EnumDataType enumt = create_enum(name);
			for (int i = 2; i < split.length; i++) {
				String[] pair = split[i].split(":");
				String component = pair[0];
				String value = pair[1];
				enumt.add(component, Long.parseLong(value), "");
			}
			return dtm.addDataType(enumt, DataTypeConflictHandler.REPLACE_HANDLER);
		}
		return null;
	}

	DataType parse_type(DataType parent, String name) {
		if (parent != null && parent.getName().split("<")[0].equals(name.split("<")[0])) {
			return parent;
		}
		if (name.startsWith("*")) {
			name = name.substring(1);
			return new PointerDataType(parse_type(parent, name));
		}
		if (name.endsWith("*")) {
			name = name.substring(0, name.length() - 1);
			return new PointerDataType(parse_type(parent, name));
		}
		if (name.endsWith(">")) {
			int index = name.indexOf("<");
			List<String> generics = split_locally(name.substring(index + 1, name.length() - 1), ',', '<', '>');
			String name_no_gen = name.substring(0, index);
			return generic_map.get(name_no_gen).apply(generics);
		}
		if (name.startsWith("[") && name.endsWith("]")) {
			name = name.substring(1, name.length() - 1);
			int split = name.lastIndexOf(";");
			int len = Integer.parseInt(name.substring(split + 1));
			name = name.substring(0, split);
			return new ArrayDataType(parse_type(parent, name), len);
		}
		if (type_map.containsKey(name)) {
			name = type_map.get(name);
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
		failed.add(name);
		return dtm.addDataType(create_struct(name), DataTypeConflictHandler.REPLACE_HANDLER);
	}

	private DataType find_type_in_manager(DataTypeManager datatypemanager, String name) {
		Iterator<DataType> types = datatypemanager.getAllDataTypes();
		while (types.hasNext()) {
			DataType type = types.next();
			if (type.getName().equals(name)) {
				return type;
			}
		}
		return null;
	}

	StructureDataType create_struct(String name) {
		return create_struct_with(name, 0);
	}

	StructureDataType create_struct_with(String name, int n) {
		CategoryPath category = new CategoryPath("/custom");
		return new StructureDataType(category, name, n);
	}

	EnumDataType create_enum(String name) {
		return create_enum_with(name, 1);
	}

	EnumDataType create_enum_with(String name, int n) {
		CategoryPath category = new CategoryPath("/custom");
		return new EnumDataType(category, name, n);
	}

	UnionDataType create_union(String name) {
		CategoryPath category = new CategoryPath("/custom");
		return new UnionDataType(category, name);
	}

	DataType parse(String name) {
		return parse_type(null, name);
	}

	void rename(String name, long addr, String ret, String[][] params) throws Exception {
		Address address = space.getAddress(addr);
		Function fn = fpapi.getFunctionAt(address);
		fn.setName(name, source);
		if (ret != null) {
			fn.setReturnType(parse(ret), source);
		}
		if (params != null) {
			List<Variable> args = new ArrayList<>();
			for (int j = 0; j < params.length; j++) {
				String n = params[j][0];
				if (j == 0 && fn.getCallingConventionName().equals("__thiscall")) {
					n = "this";
				}
				args.add(new ParameterImpl(n, parse(params[j][1]), program));
			}
			fn.replaceParameters(args, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, source);
			if (fn.getCallingConventionName().equals("__thiscall")) {
				fn.setCustomVariableStorage(true);
				fn.getParameter(0).setDataType(parse(params[0][1]), true, true, source);
				fn.getParameter(0).setName(params[0][0], source);
			}
		}
	}

	void rename_functions() throws Exception {
        rename("get_entity", 0x0056eba0, "*Entity", new String[][] {{"entity_manager_ptr", "*EntityManager"}, {"index", "usize"}});
        rename("kill_entity", 0x0044df60, null, new String[][]{{"entity", "*Entity"}});
        rename("create_entity", 0x0056e590, "*Entity", new String[][]{{"entity_manager_ptr", "*EntityManager"}});
        rename("to_stdstring", 0x0041dd60, null, new String[][]{{"stdstring_ptr", "*StdString"}, {"string", "char[]"}, {"size", "usize"}});
        rename("create_component_by_name", 0x0056c8e0, "*ComponentData", new String[][]{{"name", "*StdString"}});
        rename("insert_component", 0x0056f720, "*usize", new String[][] {{"entity_manager_ptr", "*EntityManager"},{"component_data", "*ComponentData"}});
        rename("init_entity_manager", 0x0056de10, "*EntityManager", new String[][]{{"entity_manager_ptr", "*EntityManager"}});
        rename("std_string_cmp", 0x00442220, "bool", new String[][]{{"stdstring_ptr", "*StdString"}, {"string", "char[]"}});
        rename("init_world_state", 0x00636a00, null, null);
	}

	void rename_globals() throws Exception {
		String file = Files.readString(Path.of(folder + "/noita_entangled_worlds/noita_api/src/addr_grabber.rs"));
		String globals = file.split("make_globals\\!\\(\n")[1].split("\n\\);")[0];
		for (String line : globals.split("\n")) {
			String[] split = line.split("\\(")[1].split("\\)")[0].split(", ");
			Address addr = space.getAddress(split[1]);
			String ty = split[3];
			if (split[2].equals("true")) {
				ty = "*" + ty;
			}
			DataType type = parse(ty);
			listing.clearCodeUnits(addr, addr.add(type.getLength() - 1), false);
			createData(addr, type);
			Symbol sym = fpapi.getSymbolAt(addr);
			String name = split[0];
			if (split[2].equals("true")) {
				name += "_ptr";
			}
			sym.setName(pascal_to_snake(name), source);
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
		while (true) {
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
				ApplyFunctionSignatureCmd lua_cmd = new ApplyFunctionSignatureCmd(lua_fn.getEntryPoint(), lua_fddt,
						source);
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
