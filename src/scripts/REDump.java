// REDump.java - Ghidra headless extraction script for Angerona.
//
// Runs under `analyzeHeadless ... -postScript REDump.java <outfile> <mode> [args]`.
// Emits a single JSON document describing the analyzed program so an AI agent
// can reason about it without the Ghidra GUI.
//
// Modes:
//   meta               -> metadata, memory map, function index (no decompilation),
//                         strings, imports, exports, symbols, call graph, xrefs.
//   full [maxFuncs]     -> everything in `meta` PLUS decompiled C for functions
//                         (bounded by maxFuncs; 0 = all).
//   function <name|0xADDR> -> decompiled C + disassembly for a single function.
//
// JSON is hand-serialized (no external deps) to run on a stock Ghidra release.
//@category REAgent

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.lang.Register;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class REDump extends GhidraScript {

    private int decompTimeout = 45;
    private int maxStrings = 8000;
    private int maxDecompiledChars = 60000;
    private boolean restrictedMode = false;
    private String rangeAuthoritySha256 = "";
    private List<AddressRange> allowedRanges = new ArrayList<>();

    private static class PrefixOffsetRecord {
        Address pointerAddress;
        long value;
        String entryKind;
        Address baseTypeInfo;

        PrefixOffsetRecord(
            Address pointerAddress,
            long value,
            String entryKind,
            Address baseTypeInfo
        ) {
            this.pointerAddress = pointerAddress;
            this.value = value;
            this.entryKind = entryKind;
            this.baseTypeInfo = baseTypeInfo;
        }
    }

    private static class VtableAddressPointRecord {
        Address addressPoint;
        Address vtable;
        Address typeInfo;
        long offsetToTop;
        String tableKind;
        String tableRole;
        int leadingNullSlotCount;

        VtableAddressPointRecord(
            Address addressPoint,
            Address vtable,
            Address typeInfo,
            long offsetToTop,
            String tableRole,
            int leadingNullSlotCount
        ) {
            this.addressPoint = addressPoint;
            this.vtable = vtable;
            this.typeInfo = typeInfo;
            this.offsetToTop = offsetToTop;
            this.tableKind = offsetToTop == 0 ? "primary" : "secondary";
            this.tableRole = tableRole;
            this.leadingNullSlotCount = leadingNullSlotCount;
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "redump.json";
        String mode = args.length > 1 ? args[1].toLowerCase() : "meta";

        if (mode.equals("restricted_meta")) {
            configureRestricted(args.length > 2 ? args[2] : "", args.length > 3 ? args[3] : "");
            prepareRestrictedFunctions();
        } else if (mode.equals("function") && args.length > 3 && args[3].equals("restricted")) {
            configureRestricted(args.length > 4 ? args[4] : "", args.length > 5 ? args[5] : "");
            prepareRestrictedFunctions();
        }

        String json;
        if (mode.equals("function")) {
            String target = args.length > 2 ? args[2] : null;
            if (restrictedMode) {
                Address requested = target == null ? null : restrictedAddress(toAddr(target));
                if (requested == null || !isAllowed(requested)) {
                    throw new IllegalArgumentException("requested function is outside signed allowed ranges");
                }
                target = requested.toString();
            }
            json = buildFunctionJson(target);
        } else {
            boolean decompile = mode.equals("full");
            int maxFuncs = 0;
            if (decompile && args.length > 2) {
                try { maxFuncs = Integer.parseInt(args[2]); } catch (NumberFormatException ignore) {}
            }
            json = buildProgramJson(decompile, maxFuncs);
        }

        try (Writer w = new OutputStreamWriter(new FileOutputStream(outPath), StandardCharsets.UTF_8)) {
            w.write(json);
        }
        println("REDump wrote " + json.length() + " bytes to " + outPath);
    }

    // ----------------------------------------------------------------- program

    private String buildProgramJson(boolean decompile, int maxFuncs) throws Exception {
        List<String> top = new ArrayList<>();
        top.add(kv("schema", q("angerona/1")));
        top.add(kv("mode", q(restrictedMode ? "restricted_meta" : (decompile ? "full" : "meta"))));
        top.add(kv("range_authority_sha256", restrictedMode ? q(rangeAuthoritySha256) : "null"));
        top.add(kv("metadata", metadataObj()));
        top.add(kv("memory", memoryArr()));
        top.add(kv("functions", functionsArr(decompile, maxFuncs)));
        top.add(kv("strings", restrictedMode ? "[]" : stringsArr()));
        top.add(kv("imports", importsArr()));
        top.add(kv("exports", exportsArr()));
        top.add(kv("symbols", symbolsArr()));
        return obj(top);
    }

    private String metadataObj() {
        List<String> f = new ArrayList<>();
        int totalFunctions = currentProgram.getFunctionManager().getFunctionCount();
        int internalFunctions = internalFunctionCount();
        f.add(kvs("name", currentProgram.getName()));
        f.add(kvs("executable_path", nz(currentProgram.getExecutablePath())));
        f.add(kvs("executable_format", nz(currentProgram.getExecutableFormat())));
        f.add(kvs("language_id", currentProgram.getLanguageID().getIdAsString()));
        f.add(kvs("compiler_spec", currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()));
        f.add(kvs("processor", currentProgram.getLanguage().getProcessor().toString()));
        f.add(kvn("pointer_size", currentProgram.getDefaultPointerSize()));
        f.add(kvs("endian", currentProgram.getLanguage().isBigEndian() ? "big" : "little"));
        f.add(kvs("image_base", currentProgram.getImageBase().toString()));
        f.add(kvs("min_address", currentProgram.getMinAddress() != null ? currentProgram.getMinAddress().toString() : ""));
        f.add(kvs("max_address", currentProgram.getMaxAddress() != null ? currentProgram.getMaxAddress().toString() : ""));
        f.add(kvs("md5", nz(currentProgram.getExecutableMD5())));
        f.add(kvs("sha256", nz(currentProgram.getExecutableSHA256())));
        // Ghidra's manager total includes external imports, while functionsArr()
        // emits the internal address-space iterator.  Export both explicitly so
        // consumers do not mistake the difference for lost functions.
        f.add(kvn("function_count", totalFunctions));
        f.add(kvn("internal_function_count", internalFunctions));
        f.add(kvn("external_function_count", Math.max(0, totalFunctions - internalFunctions)));
        f.add(kvn("emitted_function_count", internalFunctions));
        return obj(f);
    }

    private int internalFunctionCount() {
        int count = 0;
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function fn = it.next();
            if (restrictedMode && !isAllowed(fn.getEntryPoint())) continue;
            count++;
        }
        return count;
    }

    private void configureRestricted(String spec, String authoritySha256) throws Exception {
        if (authoritySha256 == null || !authoritySha256.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("invalid restricted range authority hash");
        }
        restrictedMode = true;
        rangeAuthoritySha256 = authoritySha256;
        for (String item : spec.split(",")) {
            if (item.isEmpty()) continue;
            String[] fields = item.split(":", 2);
            if (fields.length != 2) throw new IllegalArgumentException("malformed restricted range");
            Address start = restrictedAddress(toAddr(fields[0]));
            long size = Long.parseLong(fields[1]);
            if (start == null || size <= 0) throw new IllegalArgumentException("invalid restricted range");
            Address end = start.add(size - 1);
            allowedRanges.add(new ghidra.program.model.address.AddressRangeImpl(start, end));
        }
        if (allowedRanges.isEmpty()) throw new IllegalArgumentException("empty restricted range set");
    }

    private boolean isAllowed(Address address) {
        if (!restrictedMode) return true;
        if (address == null) return false;
        for (AddressRange range : allowedRanges) {
            if (range.contains(address)) return true;
        }
        return false;
    }

    private Address restrictedAddress(Address address) {
        if (address == null) return null;
        if (currentProgram.getMemory().getBlock(address) != null) return address;
        try {
            Address rebased = currentProgram.getImageBase().add(address.getOffset());
            return currentProgram.getMemory().getBlock(rebased) != null ? rebased : address;
        } catch (Throwable ignored) {
            return address;
        }
    }

    private void prepareRestrictedFunctions() throws Exception {
        for (AddressRange range : allowedRanges) {
            AddressSet set = new AddressSet(range.getMinAddress(), range.getMaxAddress());
            DisassembleCommand command = new DisassembleCommand(range.getMinAddress(), set, true);
            if (!command.applyTo(currentProgram, monitor)) {
                throw new IllegalStateException("restricted disassembly failed: " + command.getStatusMsg());
            }
            Function containing = getFunctionContaining(range.getMinAddress());
            if (containing != null && !containing.getEntryPoint().equals(range.getMinAddress())) {
                currentProgram.getFunctionManager().removeFunction(containing.getEntryPoint());
            }
            if (getFunctionAt(range.getMinAddress()) == null) {
                createFunction(range.getMinAddress(), "angerona_allowed_" + range.getMinAddress());
            }
            Function restrictedFunction = getFunctionAt(range.getMinAddress());
            if (restrictedFunction == null) {
                throw new IllegalStateException("restricted function creation failed");
            }
            restrictedFunction.setBody(set);
        }
    }

    private String memoryArr() {
        List<String> items = new ArrayList<>();
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            List<String> f = new ArrayList<>();
            f.add(kvs("name", b.getName()));
            f.add(kvs("start", b.getStart().toString()));
            f.add(kvs("end", b.getEnd().toString()));
            f.add(kvn("size", b.getSize()));
            f.add(kvb("r", b.isRead()));
            f.add(kvb("w", b.isWrite()));
            f.add(kvb("x", b.isExecute()));
            f.add(kvb("initialized", b.isInitialized()));
            items.add(obj(f));
        }
        return arr(items);
    }

    private String functionsArr(boolean decompile, int maxFuncs) throws Exception {
        List<String> items = new ArrayList<>();
        DecompInterface decomp = null;
        if (decompile) {
            decomp = new DecompInterface();
            decomp.openProgram(currentProgram);
        }
        int decompiled = 0;
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function fn = it.next();
            if (restrictedMode && !isAllowed(fn.getEntryPoint())) continue;
            List<String> f = new ArrayList<>();
            f.add(kvs("name", fn.getName()));
            f.add(kvs("entry", fn.getEntryPoint().toString()));
            f.add(kvn("size", fn.getBody().getNumAddresses()));
            f.add(kv("body_ranges", bodyRangesArr(fn)));
            f.add(kvs("signature", fn.getSignature().getPrototypeString()));
            f.add(kvs("calling_convention", nz(fn.getCallingConventionName())));
            f.add(kvb("is_thunk", fn.isThunk()));
            f.add(kvb("is_external", fn.isExternal()));
            f.add(kvs("namespace", fn.getParentNamespace().getName(true)));
            MemoryBlock fnBlock = currentProgram.getMemory().getBlock(fn.getEntryPoint());
            f.add(kvs("memory_block", fnBlock != null ? fnBlock.getName() : ""));

            List<String> params = new ArrayList<>();
            for (Parameter p : fn.getParameters()) {
                List<String> pf = new ArrayList<>();
                pf.add(kvs("name", p.getName()));
                pf.add(kvs("type", p.getDataType().getName()));
                params.add(obj(pf));
            }
            f.add(kv("params", arr(params)));

            f.add(kv("callees", nameSetArr(safeCalled(fn))));
            f.add(kv("callers", nameSetArr(safeCallers(fn))));
            f.add(kv("xrefs_to", xrefsArr(fn.getEntryPoint())));

            if (decompile && (maxFuncs <= 0 || decompiled < maxFuncs) && !fn.isThunk() && !fn.isExternal()) {
                String c = decompileC(decomp, fn, false);
                if (c != null) {
                    f.add(kvs("decompiled", restrictedText(c)));
                    f.add(kvb("decompilation_complete", decompilationSucceeded(c)));
                    decompiled++;
                }
            }
            items.add(obj(f));
        }
        if (decomp != null) {
            decomp.dispose();
        }
        return arr(items);
    }

    private Set<Function> safeCalled(Function fn) {
        try { return fn.getCalledFunctions(monitor); } catch (Throwable t) { return java.util.Collections.emptySet(); }
    }

    private Set<Function> safeCallers(Function fn) {
        try { return fn.getCallingFunctions(monitor); } catch (Throwable t) { return java.util.Collections.emptySet(); }
    }

    private String nameSetArr(Set<Function> fns) {
        List<String> items = new ArrayList<>();
        int n = 0;
        for (Function f : fns) {
            items.add(q(restrictedMode && !isAllowed(f.getEntryPoint())
                ? "REDACTED_OUTSIDE_NATIVE_AUTHORITY" : f.getName()));
            if (++n >= 200) break;
        }
        return arr(items);
    }

    private String bodyRangesArr(Function fn) {
        List<String> items = new ArrayList<>();
        AddressRangeIterator ranges = fn.getBody().getAddressRanges();
        while (ranges.hasNext()) {
            AddressRange range = ranges.next();
            if (restrictedMode && (!isAllowed(range.getMinAddress()) || !isAllowed(range.getMaxAddress()))) {
                throw new IllegalStateException("restricted function body escapes signed authority");
            }
            List<String> fields = new ArrayList<>();
            fields.add(kvs("start", range.getMinAddress().toString()));
            fields.add(kvs("end", range.getMaxAddress().toString()));
            fields.add(kvn("size", range.getLength()));
            fields.add(kvb("end_inclusive", true));
            items.add(obj(fields));
        }
        return arr(items);
    }

    private String xrefsArr(Address addr) {
        List<String> items = new ArrayList<>();
        ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(addr);
        int n = 0;
        while (ri.hasNext()) {
            Reference r = ri.next();
            List<String> f = new ArrayList<>();
            boolean allowed = !restrictedMode || isAllowed(r.getFromAddress());
            f.add(kvs("from", allowed ? r.getFromAddress().toString() : "REDACTED_OUTSIDE_NATIVE_AUTHORITY"));
            f.add(kvs("type", effectiveXrefType(r)));
            f.add(kvs("engine_reference_type", r.getReferenceType().getName()));
            Function ff = getFunctionContaining(r.getFromAddress());
            f.add(kvs("from_function", allowed && ff != null ? ff.getName() :
                (allowed ? "" : "REDACTED_OUTSIDE_NATIVE_AUTHORITY")));
            MemoryBlock fromBlock = currentProgram.getMemory().getBlock(r.getFromAddress());
            f.add(kvs("from_memory_block", allowed && fromBlock != null ? fromBlock.getName() :
                (allowed ? "" : "REDACTED_OUTSIDE_NATIVE_AUTHORITY")));
            items.add(obj(f));
            if (++n >= 100) break;
        }
        return arr(items);
    }

    private String effectiveXrefType(Reference reference) {
        if (!reference.getReferenceType().isFlow()) {
            return reference.getReferenceType().getName();
        }
        Instruction instruction =
            currentProgram.getListing().getInstructionAt(reference.getFromAddress());
        if (instruction == null) {
            return reference.getReferenceType().getName();
        }
        // getFlowType() includes analysis overrides (for example a JMP that
        // Ghidra promoted to CALL after creating a function at its target).
        // The prototype preserves the machine instruction's original flow.
        FlowType flow = instruction.getPrototype().getFlowType(
            instruction.getInstructionContext());
        if (flow == null || !flow.isFlow()) {
            return reference.getReferenceType().getName();
        }
        if (flow.isCall()) {
            if (flow.isComputed()) return "COMPUTED_CALL";
            return flow.isConditional() ? "CONDITIONAL_CALL" : "UNCONDITIONAL_CALL";
        }
        if (flow.isJump()) {
            if (flow.isComputed()) return "COMPUTED_JUMP";
            return flow.isConditional() ? "CONDITIONAL_JUMP" : "UNCONDITIONAL_JUMP";
        }
        return reference.getReferenceType().getName();
    }

    private String decompileC(DecompInterface decomp, Function fn, boolean fullText) {
        try {
            DecompileResults res = decomp.decompileFunction(fn, decompTimeout, monitor);
            if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                String c = res.getDecompiledFunction().getC();
                if (!fullText && c != null && c.length() > maxDecompiledChars) {
                    c = c.substring(0, maxDecompiledChars) + "\n/* ... truncated by Angerona ... */\n";
                }
                return c;
            }
        } catch (Throwable t) {
            return "/* decompile failed: " + t.getMessage() + " */";
        }
        return null;
    }

    // --------------------------------------------------------------- strings

    private String stringsArr() {
        List<String> items = new ArrayList<>();
        int n = 0;
        DataIterator di = currentProgram.getListing().getDefinedData(true);
        while (di.hasNext()) {
            Data d = di.next();
            if (!d.hasStringValue()) continue;
            Object v = d.getValue();
            if (v == null) continue;
            List<String> f = new ArrayList<>();
            f.add(kvs("address", d.getAddress().toString()));
            f.add(kvs("value", v.toString()));
            f.add(kvn("length", v.toString().length()));
            f.add(kvn("byte_length", d.getLength()));
            MemoryBlock block = currentProgram.getMemory().getBlock(d.getAddress());
            f.add(kvs("memory_block", block != null ? block.getName() : ""));
            f.add(kv("xrefs_to", xrefsArr(d.getAddress())));
            f.add(kv("rtti_vtable_candidates", rttiVtableCandidatesArr(
                d.getAddress(), v.toString())));
            f.add(kv("rtti_typeinfo_candidates", rttiTypeInfoCandidatesArr(
                d.getAddress(), v.toString())));
            items.add(obj(f));
            if (++n >= maxStrings) break;
        }
        return arr(items);
    }

    private String rttiVtableCandidatesArr(Address typeName, String value) {
        List<String> items = new ArrayList<>();
        if (value == null ||
            !value.matches("N(?:\\d+[A-Za-z_][A-Za-z0-9_]*)+E")) {
            return arr(items);
        }
        int pointerSize = currentProgram.getDefaultPointerSize();
        if (pointerSize != 4 && pointerSize != 8) return arr(items);

        Set<String> seen = new java.util.HashSet<>();
        ReferenceIterator nameRefs =
            currentProgram.getReferenceManager().getReferencesTo(typeName);
        while (nameRefs.hasNext()) {
            Reference nameRef = nameRefs.next();
            Address namePointer = nameRef.getFromAddress();
            MemoryBlock nameBlock =
                currentProgram.getMemory().getBlock(namePointer);
            if (nameBlock == null ||
                !nameBlock.getName().contains(".data.rel.ro")) {
                continue;
            }
            try {
                // Itanium type_info begins with a vptr followed by the pointer
                // to this type-name string.
                Address typeInfo = namePointer.subtract(pointerSize);
                ReferenceIterator typeInfoRefs =
                    currentProgram.getReferenceManager().getReferencesTo(typeInfo);
                while (typeInfoRefs.hasNext()) {
                    Reference typeInfoRef = typeInfoRefs.next();
                    appendRttiVtableCandidate(
                        items, seen, typeInfo, namePointer,
                        typeInfoRef.getFromAddress(), pointerSize,
                        "reference_manager");
                }

                // Ghidra does not always create incoming references for
                // undefined user type_info objects in stripped binaries.
                // Scan only the same relocation-backed data block, aligned to
                // pointer width, for the exact type_info address.
                Address cursor = nameBlock.getStart();
                long misalignment = Math.floorMod(
                    cursor.getOffset(), (long) pointerSize);
                if (misalignment != 0) {
                    cursor = cursor.add(pointerSize - misalignment);
                }
                Address end = nameBlock.getEnd();
                while (cursor.compareTo(end) <= 0) {
                    if (cursor.add(pointerSize - 1).compareTo(end) > 0) break;
                    long pointerValue = pointerSize == 8
                        ? currentProgram.getMemory().getLong(cursor)
                        : Integer.toUnsignedLong(
                            currentProgram.getMemory().getInt(cursor));
                    if (pointerValue == typeInfo.getOffset()) {
                        appendRttiVtableCandidate(
                            items, seen, typeInfo, namePointer, cursor,
                            pointerSize, "aligned_pointer_scan");
                    }
                    cursor = cursor.add(pointerSize);
                }
            } catch (Throwable ignored) {
                // Malformed/partial RTTI stays as a raw string; no candidate is
                // emitted unless the complete structural conjunction holds.
            }
        }
        return arr(items);
    }

    private void appendRttiVtableCandidate(
        List<String> items,
        Set<String> seen,
        Address typeInfo,
        Address namePointer,
        Address rttiPointer,
        int pointerSize,
        String discovery
    ) {
        try {
            MemoryBlock refBlock =
                currentProgram.getMemory().getBlock(rttiPointer);
            if (refBlock == null ||
                !refBlock.getName().contains(".data.rel.ro")) {
                return;
            }
            Address vtable = rttiPointer.subtract(pointerSize);
            long offsetToTop = pointerSize == 8
                ? currentProgram.getMemory().getLong(vtable)
                : currentProgram.getMemory().getInt(vtable);
            // An Itanium table header is {offset-to-top, type_info*}, followed
            // by its address point.  Primary tables use zero; secondary tables
            // use an aligned negative subobject adjustment.  Positive words
            // are RTTI/base-array data, not vtable headers.
            if (offsetToTop > 0 ||
                Math.floorMod(offsetToTop, (long) pointerSize) != 0) {
                return;
            }
            Address addressPoint = rttiPointer.add(pointerSize);
            Address firstMethodTarget = referenceTargetOrPointer(
                addressPoint, pointerSize);
            if (!isCallableTarget(firstMethodTarget)) return;
            String tableKind =
                offsetToTop == 0 ? "primary" : "secondary";
            List<PrefixOffsetRecord> prefixRecords =
                offsetToTop == 0
                    ? primaryVbasePrefixRecords(
                        typeInfo, addressPoint, refBlock, pointerSize)
                    : secondaryPrefixRecords(
                        vtable, refBlock, pointerSize);
            List<String> prefixEntries = new ArrayList<>();
            for (int prefixIndex = 0;
                 prefixIndex < prefixRecords.size();
                 prefixIndex++) {
                PrefixOffsetRecord record = prefixRecords.get(prefixIndex);
                List<String> prefixFields = new ArrayList<>();
                prefixFields.add(kvn("entry_index", prefixIndex));
                prefixFields.add(kvn(
                    "relative_to_address_point",
                    record.pointerAddress.subtract(addressPoint)));
                prefixFields.add(kvs(
                    "pointer_address",
                    record.pointerAddress.toString()));
                prefixFields.add(kvn("value", record.value));
                prefixFields.add(kvs("entry_kind", record.entryKind));
                prefixFields.add(
                    record.baseTypeInfo == null
                        ? kv("base_typeinfo_address", "null")
                        : kvs(
                            "base_typeinfo_address",
                            record.baseTypeInfo.toString()));
                prefixEntries.add(obj(prefixFields));
            }
            String prefixBoundaryReason = prefixEntries.isEmpty()
                ? null
                : (
                    offsetToTop == 0
                        ? "vmi_virtual_base_slots"
                        : "preceding_callable_vtable_slot"
                );
            String vttCandidate = vttCandidateObj(
                typeInfo, addressPoint, refBlock, pointerSize);

            List<String> methodSlots = new ArrayList<>();
            Address slotAddress = addressPoint;
            long slotIndex = 0;
            String slotBoundaryReason = "memory_block_end";
            List<String> slotBoundaryReferences = new ArrayList<>();
            while (slotAddress.add(pointerSize - 1)
                    .compareTo(refBlock.getEnd()) <= 0) {
                List<Address> executableRefs =
                    executableReferencesTo(slotAddress);
                if (slotIndex > 0 && !executableRefs.isEmpty()) {
                    slotBoundaryReason =
                        "code_reference_to_next_data_object";
                    for (Address source : executableRefs) {
                        List<String> refFields = new ArrayList<>();
                        refFields.add(kvs(
                            "from_address", source.toString()));
                        slotBoundaryReferences.add(obj(refFields));
                    }
                    break;
                }
                Address target = referenceTargetOrPointer(
                    slotAddress, pointerSize);
                if (!isCallableTarget(target)) {
                    slotBoundaryReason = "non_callable_pointer";
                    break;
                }
                List<String> slotFields = new ArrayList<>();
                slotFields.add(kvn("slot_index", slotIndex));
                slotFields.add(kvn(
                    "method_offset", slotIndex * pointerSize));
                slotFields.add(kvs(
                    "pointer_address", slotAddress.toString()));
                slotFields.add(kvs(
                    "target_address", target.toString()));
                slotFields.add(kv(
                    "this_adjustment_candidates",
                    offsetToTop < 0
                        ? thunkAdjustmentCandidatesArr(target)
                        : arr(new ArrayList<>())));
                methodSlots.add(obj(slotFields));
                slotIndex++;
                slotAddress = slotAddress.add(pointerSize);
            }
            if (methodSlots.isEmpty()) return;

            String key = typeInfo.toString() + ":" + vtable.toString();
            if (!seen.add(key)) return;
            List<String> fields = new ArrayList<>();
            fields.add(kvs("typeinfo_address", typeInfo.toString()));
            fields.add(kvs("name_pointer_address", namePointer.toString()));
            fields.add(kvs("vtable_address", vtable.toString()));
            fields.add(kvs("rtti_pointer_address", rttiPointer.toString()));
            fields.add(kvs(
                "address_point_address", addressPoint.toString()));
            fields.add(kvs(
                "first_method_pointer_address",
                addressPoint.toString()));
            fields.add(kvs(
                "first_method_target_address",
                firstMethodTarget.toString()));
            fields.add(kvn("offset_to_top", offsetToTop));
            fields.add(kvs("table_kind", tableKind));
            fields.add(kvn("slot_count", methodSlots.size()));
            fields.add(kv("method_slots", arr(methodSlots)));
            fields.add(kvs(
                "slot_boundary_reason", slotBoundaryReason));
            fields.add(kvn(
                "prefix_entry_count", prefixEntries.size()));
            fields.add(kv("prefix_entries", arr(prefixEntries)));
            fields.add(
                prefixBoundaryReason == null
                    ? kv("prefix_boundary_reason", "null")
                    : kvs(
                        "prefix_boundary_reason",
                        prefixBoundaryReason));
            fields.add(kv("vtt_candidate", vttCandidate));
            fields.add(kv(
                "slot_boundary_references",
                arr(slotBoundaryReferences)));
            fields.add(kvs("memory_block", refBlock.getName()));
            fields.add(kvs("discovery", discovery));
            fields.add(kvs(
                "evidence",
                offsetToTop == 0
                    ? "itanium_name_pointer_and_zero_offset_vtable_header"
                    : "itanium_name_pointer_negative_offset_and_callable_vtable_header"));
            fields.add(kv(
                "confidence", offsetToTop == 0 ? "0.97" : "0.98"));
            items.add(obj(fields));
        } catch (Throwable ignored) {
            // Partial or unreadable data never becomes a recovery candidate.
        }
    }

    private long signedMangledOffset(String token) {
        return token.startsWith("n")
            ? -Long.parseLong(token.substring(1))
            : Long.parseLong(token);
    }

    private void addThunkAdjustmentCandidate(
        List<String> candidates,
        Set<String> seen,
        String kind,
        long fixedDelta,
        Long vcallOffsetSlot,
        String evidence,
        String sourceName,
        double confidence
    ) {
        String key = kind + ":" + fixedDelta + ":" + vcallOffsetSlot;
        if (!seen.add(key)) return;
        List<String> fields = new ArrayList<>();
        fields.add(kvs("kind", kind));
        fields.add(kvn("fixed_delta", fixedDelta));
        fields.add(
            vcallOffsetSlot == null
                ? kv("vcall_offset_slot", "null")
                : kvn("vcall_offset_slot", vcallOffsetSlot));
        fields.add(kvs("evidence", evidence));
        fields.add(
            sourceName == null
                ? kv("source_name", "null")
                : kvs("source_name", sourceName));
        fields.add(kv("confidence", Double.toString(confidence)));
        candidates.add(obj(fields));
    }

    private String thunkAdjustmentCandidatesArr(Address target) {
        List<String> candidates = new ArrayList<>();
        Set<String> seen = new java.util.HashSet<>();
        Pattern virtualPattern = Pattern.compile(
            "_ZTv(?<fixed>n?\\d+)_(?<vcall>n?\\d+)_");
        Pattern fixedPattern = Pattern.compile(
            "_ZTh(?<fixed>n?\\d+)_");
        try {
            Symbol[] symbols =
                currentProgram.getSymbolTable().getSymbols(target);
            for (Symbol symbol : symbols) {
                String name = symbol.getName();
                Matcher virtualMatcher = virtualPattern.matcher(name);
                Matcher fixedMatcher = fixedPattern.matcher(name);
                if (virtualMatcher.find()) {
                    addThunkAdjustmentCandidate(
                        candidates,
                        seen,
                        "virtual_vcall",
                        signedMangledOffset(
                            virtualMatcher.group("fixed")),
                        signedMangledOffset(
                            virtualMatcher.group("vcall")),
                        "itanium_mangled_thunk_symbol",
                        name,
                        1.0);
                } else if (fixedMatcher.find()) {
                    addThunkAdjustmentCandidate(
                        candidates,
                        seen,
                        "fixed",
                        signedMangledOffset(
                            fixedMatcher.group("fixed")),
                        null,
                        "itanium_mangled_thunk_symbol",
                        name,
                        1.0);
                }
            }
        } catch (Throwable ignored) {
            // Continue with instruction-level structural evidence.
        }

        Function function =
            currentProgram.getFunctionManager().getFunctionAt(target);
        if (function == null) return arr(candidates);
        Set<String> vptrRegisters = new java.util.HashSet<>();
        try {
            InstructionIterator instructions =
                currentProgram.getListing().getInstructions(
                    function.getBody(), true);
            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                String mnemonic =
                    instruction.getMnemonicString().toLowerCase();
                Register destination = instruction.getRegister(0);
                String destinationName = destination == null
                    ? ""
                    : destination.getName().toUpperCase();
                Object[] sourceObjects = instruction.getOpObjects(1);
                Register sourceRegister = null;
                Scalar sourceScalar = null;
                for (Object object : sourceObjects) {
                    if (object instanceof Register) {
                        sourceRegister = (Register) object;
                    } else if (object instanceof Scalar) {
                        sourceScalar = (Scalar) object;
                    }
                }
                String sourceRepresentation =
                    instruction.getDefaultOperandRepresentation(1);
                if ("mov".equals(mnemonic) &&
                    destination != null &&
                    sourceRegister != null &&
                    ("RDI".equalsIgnoreCase(sourceRegister.getName()) ||
                     "EDI".equalsIgnoreCase(sourceRegister.getName())) &&
                    sourceRepresentation.contains("[")) {
                    vptrRegisters.add(destinationName);
                    continue;
                }
                if ("sub".equals(mnemonic) &&
                    ("RDI".equals(destinationName) ||
                     "EDI".equals(destinationName)) &&
                    sourceScalar != null &&
                    sourceScalar.getSignedValue() > 0) {
                    addThunkAdjustmentCandidate(
                        candidates,
                        seen,
                        "fixed",
                        -sourceScalar.getSignedValue(),
                        null,
                        "x86_sysv_this_adjustment_instruction_pattern",
                        null,
                        0.99);
                    continue;
                }
                if ("add".equals(mnemonic) &&
                    ("RDI".equals(destinationName) ||
                     "EDI".equals(destinationName)) &&
                    sourceRegister != null &&
                    vptrRegisters.contains(
                        sourceRegister.getName().toUpperCase()) &&
                    sourceScalar != null &&
                    sourceRepresentation.contains("[")) {
                    addThunkAdjustmentCandidate(
                        candidates,
                        seen,
                        "virtual_vcall",
                        0,
                        sourceScalar.getSignedValue(),
                        "x86_sysv_this_adjustment_instruction_pattern",
                        null,
                        0.99);
                }
            }
        } catch (Throwable ignored) {
            // Unrecognized code remains context-only instead of guessed.
        }
        return arr(candidates);
    }

    private long signedWord(Address address, int pointerSize) throws Exception {
        return pointerSize == 8
            ? currentProgram.getMemory().getLong(address)
            : currentProgram.getMemory().getInt(address);
    }

    private List<PrefixOffsetRecord> primaryVbasePrefixRecords(
        Address typeInfo,
        Address addressPoint,
        MemoryBlock tableBlock,
        int pointerSize
    ) {
        List<PrefixOffsetRecord> records = new ArrayList<>();
        try {
            Address vptrTarget = referenceTargetOrPointer(
                typeInfo, pointerSize);
            if (!"vmi_class_type_info".equals(
                    itaniumTypeInfoKind(vptrTarget, pointerSize))) {
                return records;
            }
            Address countAddress = typeInfo.add(2L * pointerSize + 4L);
            Address baseArray = typeInfo.add(2L * pointerSize + 8L);
            long baseCount = Integer.toUnsignedLong(
                currentProgram.getMemory().getInt(countAddress));
            MemoryBlock typeInfoBlock =
                currentProgram.getMemory().getBlock(typeInfo);
            long recordSize = 2L * pointerSize;
            long available = typeInfoBlock == null
                ? 0
                : Math.max(
                    0,
                    typeInfoBlock.getEnd().getOffset()
                        - baseArray.getOffset() + 1);
            if (baseCount <= 0 || baseCount > available / recordSize) {
                return records;
            }
            for (long index = 0; index < baseCount; index++) {
                Address recordAddress =
                    baseArray.add(index * recordSize);
                Address offsetFlagsAddress =
                    recordAddress.add(pointerSize);
                long offsetFlags = signedWord(
                    offsetFlagsAddress, pointerSize);
                long flags = offsetFlags & 0xffL;
                if ((flags & 0x1L) == 0) continue;
                long slotOffset = offsetFlags >> 8;
                Address slotAddress = addressPoint.add(slotOffset);
                if (slotOffset >= -2L * pointerSize ||
                    slotAddress.compareTo(tableBlock.getStart()) < 0 ||
                    slotAddress.add(pointerSize - 1)
                        .compareTo(tableBlock.getEnd()) > 0) {
                    records.clear();
                    return records;
                }
                records.add(new PrefixOffsetRecord(
                    slotAddress,
                    signedWord(slotAddress, pointerSize),
                    "vbase_offset",
                    referenceTargetOrPointer(
                        recordAddress, pointerSize)));
            }
            records.sort((left, right) ->
                left.pointerAddress.compareTo(right.pointerAddress));
        } catch (Throwable ignored) {
            records.clear();
        }
        return records;
    }

    private List<PrefixOffsetRecord> secondaryPrefixRecords(
        Address vtable,
        MemoryBlock tableBlock,
        int pointerSize
    ) {
        List<PrefixOffsetRecord> reverseRecords = new ArrayList<>();
        boolean precedingCallable = false;
        try {
            Address cursor = vtable.subtract(pointerSize);
            while (cursor.compareTo(tableBlock.getStart()) >= 0) {
                Address target = referenceTargetOrPointer(
                    cursor, pointerSize);
                if (isCallableTarget(target)) {
                    precedingCallable = true;
                    break;
                }
                if (target != null &&
                    currentProgram.getMemory().getBlock(target) != null) {
                    reverseRecords.clear();
                    return reverseRecords;
                }
                reverseRecords.add(new PrefixOffsetRecord(
                    cursor,
                    signedWord(cursor, pointerSize),
                    "vcall_or_vbase_offset",
                    null));
                cursor = cursor.subtract(pointerSize);
            }
        } catch (Throwable ignored) {
            reverseRecords.clear();
            return reverseRecords;
        }
        if (!precedingCallable || reverseRecords.isEmpty()) {
            reverseRecords.clear();
            return reverseRecords;
        }
        java.util.Collections.reverse(reverseRecords);
        return reverseRecords;
    }

    private List<Address> directBaseTypeInfos(
        Address typeInfo,
        int pointerSize
    ) {
        List<Address> bases = new ArrayList<>();
        try {
            MemoryBlock block =
                currentProgram.getMemory().getBlock(typeInfo);
            if (block == null ||
                !block.getName().contains(".data.rel.ro")) {
                return null;
            }
            String kind = itaniumTypeInfoKind(
                referenceTargetOrPointer(typeInfo, pointerSize),
                pointerSize);
            if ("class_type_info".equals(kind)) return bases;
            if ("si_class_type_info".equals(kind)) {
                Address base = referenceTargetOrPointer(
                    typeInfo.add(2L * pointerSize), pointerSize);
                MemoryBlock baseBlock = base == null
                    ? null : currentProgram.getMemory().getBlock(base);
                if (baseBlock == null ||
                    !baseBlock.getName().contains(".data.rel.ro")) {
                    return null;
                }
                bases.add(base);
                return bases;
            }
            if (!"vmi_class_type_info".equals(kind)) return bases;
            Address flagsAddress = typeInfo.add(2L * pointerSize);
            Address countAddress = flagsAddress.add(4L);
            Address baseArrayAddress = flagsAddress.add(8L);
            long baseCount = Integer.toUnsignedLong(
                currentProgram.getMemory().getInt(countAddress));
            long recordSize = 2L * pointerSize;
            long available =
                block.getEnd().subtract(baseArrayAddress) + 1L;
            if (baseCount <= 0 || available < 0 ||
                baseCount > available / recordSize) {
                return null;
            }
            for (long index = 0; index < baseCount; index++) {
                Address base = referenceTargetOrPointer(
                    baseArrayAddress.add(index * recordSize),
                    pointerSize);
                MemoryBlock baseBlock = base == null
                    ? null : currentProgram.getMemory().getBlock(base);
                if (baseBlock == null ||
                    !baseBlock.getName().contains(".data.rel.ro")) {
                    return null;
                }
                bases.add(base);
            }
            return bases;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private Set<String> baseTypeInfoClosure(
        Address rootTypeInfo,
        int pointerSize
    ) {
        Set<String> allowed = new java.util.HashSet<>();
        List<Address> pending = new ArrayList<>();
        allowed.add(rootTypeInfo.toString());
        pending.add(rootTypeInfo);
        for (int pendingIndex = 0;
             pendingIndex < pending.size();
             pendingIndex++) {
            List<Address> bases = directBaseTypeInfos(
                pending.get(pendingIndex), pointerSize);
            if (bases == null) {
                allowed.clear();
                allowed.add(rootTypeInfo.toString());
                return allowed;
            }
            for (Address base : bases) {
                if (allowed.add(base.toString())) pending.add(base);
            }
        }
        return allowed;
    }

    private boolean typeInfoHasVirtualBase(
        Address typeInfo,
        int pointerSize,
        Set<String> visiting
    ) {
        if (typeInfo == null || visiting.contains(typeInfo.toString())) {
            return false;
        }
        Set<String> active = new java.util.HashSet<>(visiting);
        active.add(typeInfo.toString());
        List<Address> bases = directBaseTypeInfos(typeInfo, pointerSize);
        if (bases == null) return false;
        String kind = itaniumTypeInfoKind(
            referenceTargetOrPointer(typeInfo, pointerSize),
            pointerSize);
        try {
            if ("vmi_class_type_info".equals(kind)) {
                Address baseArrayAddress =
                    typeInfo.add(2L * pointerSize + 8L);
                for (int index = 0; index < bases.size(); index++) {
                    Address offsetFlagsAddress = baseArrayAddress.add(
                        (long) index * 2L * pointerSize + pointerSize);
                    long offsetFlags = signedWord(
                        offsetFlagsAddress, pointerSize);
                    if ((offsetFlags & 0x1L) != 0 ||
                        typeInfoHasVirtualBase(
                            bases.get(index), pointerSize, active)) {
                        return true;
                    }
                }
            } else if ("si_class_type_info".equals(kind) &&
                       !bases.isEmpty()) {
                return typeInfoHasVirtualBase(
                    bases.get(0), pointerSize, active);
            }
        } catch (Throwable ignored) {
            return false;
        }
        return false;
    }

    private VtableAddressPointRecord validatedAddressPoint(
        Address target,
        Address rootTypeInfo,
        Set<String> allowedTypeInfos,
        int pointerSize
    ) {
        if (target == null) return null;
        try {
            MemoryBlock block = currentProgram.getMemory().getBlock(target);
            if (block == null ||
                !block.getName().contains(".data.rel.ro")) {
                return null;
            }
            Address rttiPointer = target.subtract(pointerSize);
            Address vtable = target.subtract(2L * pointerSize);
            Address entryTypeInfo = referenceTargetOrPointer(
                rttiPointer, pointerSize);
            if (vtable.compareTo(block.getStart()) < 0 ||
                entryTypeInfo == null ||
                !allowedTypeInfos.contains(entryTypeInfo.toString())) {
                return null;
            }
            long offsetToTop = signedWord(vtable, pointerSize);
            if (offsetToTop > 0 ||
                Math.floorMod(offsetToTop, (long) pointerSize) != 0) {
                return null;
            }
            String tableRole = entryTypeInfo.equals(rootTypeInfo)
                ? "complete_object" : "construction";
            if ("construction".equals(tableRole) &&
                !typeInfoHasVirtualBase(
                    entryTypeInfo,
                    pointerSize,
                    new java.util.HashSet<>())) {
                return null;
            }
            int leadingNullSlotCount = 0;
            Address firstTarget = referenceTargetOrPointer(
                target, pointerSize);
            while (!isCallableTarget(firstTarget) &&
                   leadingNullSlotCount < 2 &&
                   (firstTarget == null ||
                    firstTarget.getOffset() == 0)) {
                leadingNullSlotCount++;
                firstTarget = referenceTargetOrPointer(
                    target.add(
                        (long) leadingNullSlotCount * pointerSize),
                    pointerSize);
            }
            if (!isCallableTarget(firstTarget) ||
                ("complete_object".equals(tableRole) &&
                 leadingNullSlotCount != 0)) {
                return null;
            }
            return new VtableAddressPointRecord(
                target,
                vtable,
                entryTypeInfo,
                offsetToTop,
                tableRole,
                leadingNullSlotCount);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private String serializedVttRun(
        List<Address> pointerAddresses,
        List<VtableAddressPointRecord> records,
        Address currentAddressPoint
    ) {
        if (records.size() < 2) return null;
        VtableAddressPointRecord first = records.get(0);
        if (!"complete_object".equals(first.tableRole) ||
            first.offsetToTop != 0) {
            return null;
        }
        Set<String> distinctTargets = new java.util.HashSet<>();
        boolean containsCurrent = false;
        boolean containsConstruction = false;
        for (VtableAddressPointRecord record : records) {
            distinctTargets.add(record.addressPoint.toString());
            if ("construction".equals(record.tableRole)) {
                containsConstruction = true;
            }
            if (record.addressPoint.equals(currentAddressPoint)) {
                containsCurrent = true;
            }
        }
        if (!containsCurrent || distinctTargets.size() < 2) return null;
        List<String> entries = new ArrayList<>();
        for (int index = 0; index < records.size(); index++) {
            VtableAddressPointRecord record = records.get(index);
            List<String> entryFields = new ArrayList<>();
            entryFields.add(kvn("entry_index", index));
            entryFields.add(kvs(
                "pointer_address",
                pointerAddresses.get(index).toString()));
            entryFields.add(kvs(
                "address_point_address",
                record.addressPoint.toString()));
            entryFields.add(kvs(
                "vtable_address",
                record.vtable.toString()));
            entryFields.add(kvs(
                "typeinfo_address",
                record.typeInfo.toString()));
            entryFields.add(kvn(
                "offset_to_top",
                record.offsetToTop));
            entryFields.add(kvs(
                "table_kind",
                record.tableKind));
            entryFields.add(kvs(
                "table_role",
                record.tableRole));
            entryFields.add(kvn(
                "leading_null_slot_count",
                record.leadingNullSlotCount));
            entries.add(obj(entryFields));
        }
        List<String> fields = new ArrayList<>();
        fields.add(kvs(
            "vtt_address",
            pointerAddresses.get(0).toString()));
        fields.add(kvn("entry_count", entries.size()));
        fields.add(kv("entries", arr(entries)));
        fields.add(kvs(
            "evidence",
            containsConstruction
                ? "contiguous_data_pointers_start_at_complete_object_and_cover_valid_base_construction_address_points"
                : "contiguous_data_pointers_cover_distinct_same_rtti_vtable_address_points"));
        fields.add(kv("confidence", "0.99"));
        return obj(fields);
    }

    private String vttCandidateObj(
        Address typeInfo,
        Address currentAddressPoint,
        MemoryBlock block,
        int pointerSize
    ) {
        List<String> candidates = new ArrayList<>();
        List<Address> pointerAddresses = new ArrayList<>();
        List<VtableAddressPointRecord> records = new ArrayList<>();
        Set<String> allowedTypeInfos =
            baseTypeInfoClosure(typeInfo, pointerSize);
        try {
            Address cursor = block.getStart();
            long misalignment = Math.floorMod(
                cursor.getOffset(), (long) pointerSize);
            if (misalignment != 0) {
                cursor = cursor.add(pointerSize - misalignment);
            }
            while (cursor.add(pointerSize - 1)
                    .compareTo(block.getEnd()) <= 0) {
                VtableAddressPointRecord record = validatedAddressPoint(
                    referenceTargetOrPointer(cursor, pointerSize),
                    typeInfo,
                    allowedTypeInfos,
                    pointerSize);
                if (record == null) {
                    String candidate = serializedVttRun(
                        pointerAddresses,
                        records,
                        currentAddressPoint);
                    if (candidate != null) candidates.add(candidate);
                    pointerAddresses.clear();
                    records.clear();
                } else {
                    pointerAddresses.add(cursor);
                    records.add(record);
                }
                cursor = cursor.add(pointerSize);
            }
            String candidate = serializedVttRun(
                pointerAddresses,
                records,
                currentAddressPoint);
            if (candidate != null) candidates.add(candidate);
        } catch (Throwable ignored) {
            return "null";
        }
        return candidates.size() == 1 ? candidates.get(0) : "null";
    }

    private boolean isCallableTarget(Address target) {
        if (target == null) return false;
        try {
            Function function = currentProgram.getFunctionManager()
                .getFunctionAt(target);
            if (function != null) return true;
            MemoryBlock block =
                currentProgram.getMemory().getBlock(target);
            return block != null && block.isExecute();
        } catch (Throwable ignored) {
            return false;
        }
    }

    private List<Address> executableReferencesTo(Address target) {
        List<Address> sources = new ArrayList<>();
        try {
            ReferenceIterator refs = currentProgram.getReferenceManager()
                .getReferencesTo(target);
            while (refs.hasNext()) {
                Reference ref = refs.next();
                MemoryBlock fromBlock = currentProgram.getMemory()
                    .getBlock(ref.getFromAddress());
                Instruction instruction = currentProgram.getListing()
                    .getInstructionAt(ref.getFromAddress());
                FlowType flow = instruction == null
                    ? null
                    : instruction.getPrototype().getFlowType(
                        instruction.getInstructionContext());
                boolean controlFlowInstruction = flow != null &&
                    (flow.isCall() || flow.isJump());
                if (fromBlock != null && fromBlock.isExecute() &&
                    !ref.getReferenceType().isFlow() &&
                    !controlFlowInstruction) {
                    sources.add(ref.getFromAddress());
                }
            }
        } catch (Throwable ignored) {
            return sources;
        }
        return sources;
    }

    private String rttiTypeInfoCandidatesArr(Address typeName, String value) {
        List<String> items = new ArrayList<>();
        if (value == null ||
            !value.matches("N(?:\\d+[A-Za-z_][A-Za-z0-9_]*)+E")) {
            return arr(items);
        }
        int pointerSize = currentProgram.getDefaultPointerSize();
        if (pointerSize != 4 && pointerSize != 8) return arr(items);
        Set<String> seen = new java.util.HashSet<>();
        ReferenceIterator nameRefs =
            currentProgram.getReferenceManager().getReferencesTo(typeName);
        while (nameRefs.hasNext()) {
            Reference nameRef = nameRefs.next();
            Address namePointer = nameRef.getFromAddress();
            MemoryBlock block = currentProgram.getMemory().getBlock(namePointer);
            if (block == null ||
                !block.getName().contains(".data.rel.ro")) {
                continue;
            }
            try {
                Address typeInfo = namePointer.subtract(pointerSize);
                if (!seen.add(typeInfo.toString())) continue;
                Address vptrTarget =
                    referenceTargetOrPointer(typeInfo, pointerSize);
                String kind = itaniumTypeInfoKind(vptrTarget, pointerSize);
                Address basePointer = typeInfo.add(2L * pointerSize);
                Address baseTypeInfo = "si_class_type_info".equals(kind)
                    ? referenceTargetOrPointer(basePointer, pointerSize)
                    : null;
                MemoryBlock baseBlock = baseTypeInfo == null
                    ? null : currentProgram.getMemory().getBlock(baseTypeInfo);
                if ("si_class_type_info".equals(kind) &&
                    (baseBlock == null ||
                     !baseBlock.getName().contains(".data.rel.ro"))) {
                    continue;
                }
                long vmiFlags = 0;
                long vmiBaseCount = 0;
                List<String> vmiBases = new ArrayList<>();
                if ("vmi_class_type_info".equals(kind)) {
                    Address flagsAddress = typeInfo.add(2L * pointerSize);
                    Address countAddress = flagsAddress.add(4L);
                    Address baseArrayAddress = flagsAddress.add(8L);
                    vmiFlags = Integer.toUnsignedLong(
                        currentProgram.getMemory().getInt(flagsAddress));
                    vmiBaseCount = Integer.toUnsignedLong(
                        currentProgram.getMemory().getInt(countAddress));
                    long recordSize = 2L * pointerSize;
                    long available = block.getEnd().subtract(baseArrayAddress) + 1L;
                    if (vmiBaseCount <= 0 || available < 0 ||
                        vmiBaseCount > available / recordSize) {
                        continue;
                    }
                    boolean validBases = true;
                    for (long index = 0; index < vmiBaseCount; index++) {
                        Address recordAddress = baseArrayAddress.add(
                            index * recordSize);
                        Address offsetFlagsAddress =
                            recordAddress.add(pointerSize);
                        Address vmiBaseTypeInfo = referenceTargetOrPointer(
                            recordAddress, pointerSize);
                        MemoryBlock vmiBaseBlock = vmiBaseTypeInfo == null
                            ? null
                            : currentProgram.getMemory().getBlock(vmiBaseTypeInfo);
                        if (vmiBaseBlock == null ||
                            !vmiBaseBlock.getName().contains(".data.rel.ro")) {
                            validBases = false;
                            break;
                        }
                        long offsetFlags = pointerSize == 8
                            ? currentProgram.getMemory().getLong(
                                offsetFlagsAddress)
                            : currentProgram.getMemory().getInt(
                                offsetFlagsAddress);
                        long baseFlags = offsetFlags & 0xffL;
                        long baseOffset = offsetFlags >> 8;
                        boolean virtualBase = (baseFlags & 0x1L) != 0;
                        List<String> baseFields = new ArrayList<>();
                        baseFields.add(kvs(
                            "base_pointer_address",
                            recordAddress.toString()));
                        baseFields.add(kvs(
                            "base_typeinfo_address",
                            vmiBaseTypeInfo.toString()));
                        baseFields.add(kvs(
                            "offset_flags_address",
                            offsetFlagsAddress.toString()));
                        baseFields.add(kv(
                            "offset", Long.toString(baseOffset)));
                        baseFields.add(kvs(
                            "offset_kind",
                            virtualBase
                                ? "vbase_offset_slot"
                                : "object_offset"));
                        baseFields.add(kv(
                            "object_offset",
                            virtualBase
                                ? "null" : Long.toString(baseOffset)));
                        baseFields.add(kv(
                            "vbase_offset_slot_offset",
                            virtualBase
                                ? Long.toString(baseOffset) : "null"));
                        baseFields.add(kv(
                            "flags", Long.toString(baseFlags)));
                        baseFields.add(kvb(
                            "is_virtual", virtualBase));
                        baseFields.add(kvb(
                            "is_public", (baseFlags & 0x2L) != 0));
                        vmiBases.add(obj(baseFields));
                    }
                    if (!validBases ||
                        vmiBases.size() != (int) vmiBaseCount) {
                        continue;
                    }
                }
                List<String> fields = new ArrayList<>();
                fields.add(kvs("typeinfo_address", typeInfo.toString()));
                fields.add(kvs("name_pointer_address", namePointer.toString()));
                fields.add(kvs(
                    "vptr_target_address",
                    vptrTarget != null ? vptrTarget.toString() : ""));
                fields.add(kvs("typeinfo_kind", kind));
                fields.add(kvs(
                    "base_pointer_address",
                    "si_class_type_info".equals(kind)
                        ? basePointer.toString() : ""));
                fields.add(kvs(
                    "base_typeinfo_address",
                    baseTypeInfo != null ? baseTypeInfo.toString() : ""));
                fields.add(kv(
                    "vmi_flags", Long.toString(vmiFlags)));
                fields.add(kv(
                    "base_count", Long.toString(vmiBaseCount)));
                fields.add(kv("bases", arr(vmiBases)));
                fields.add(kvs("memory_block", block.getName()));
                fields.add(kvs(
                    "evidence",
                    "vmi_class_type_info".equals(kind)
                        ? "itanium_type_name_vptr_kind_and_base_array"
                        : "itanium_type_name_vptr_kind_and_base_pointer"));
                fields.add(kv(
                    "confidence",
                    ("si_class_type_info".equals(kind) ||
                     "class_type_info".equals(kind) ||
                     "vmi_class_type_info".equals(kind))
                        ? "1.0" : "0.5"));
                items.add(obj(fields));
            } catch (Throwable ignored) {
                // A partial object remains a raw RTTI string only.
            }
        }
        return arr(items);
    }

    private Address referenceTargetOrPointer(Address from, int pointerSize) {
        try {
            Reference[] refs =
                currentProgram.getReferenceManager().getReferencesFrom(from);
            for (Reference ref : refs) {
                if (ref.getToAddress() != null) return ref.getToAddress();
            }
        } catch (Throwable ignored) {
            // Fall through to the relocated pointer value.
        }
        try {
            long value = pointerSize == 8
                ? currentProgram.getMemory().getLong(from)
                : Integer.toUnsignedLong(currentProgram.getMemory().getInt(from));
            if (value == 0) return null;
            return currentProgram.getAddressFactory()
                .getDefaultAddressSpace().getAddress(value);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private String itaniumTypeInfoKind(Address vptrTarget, int pointerSize) {
        if (vptrTarget == null) return "unknown";
        for (long delta : new long[] {0L, -2L * pointerSize}) {
            try {
                Address symbolAddress = vptrTarget.add(delta);
                Symbol[] symbols =
                    currentProgram.getSymbolTable().getSymbols(symbolAddress);
                for (Symbol symbol : symbols) {
                    String name = symbol.getName();
                    if (name.contains("__vmi_class_type_info")) {
                        return "vmi_class_type_info";
                    }
                    if (name.contains("__si_class_type_info")) {
                        return "si_class_type_info";
                    }
                    if (name.contains("__class_type_info")) {
                        return "class_type_info";
                    }
                }
            } catch (Throwable ignored) {
                // Try the next ABI-relative symbol location.
            }
        }
        return "unknown";
    }

    // --------------------------------------------------------------- imports

    private String importsArr() {
        List<String> items = new ArrayList<>();
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator si = st.getExternalSymbols();
        while (si.hasNext()) {
            Symbol s = si.next();
            List<String> f = new ArrayList<>();
            f.add(kvs("name", s.getName()));
            f.add(kvs("library", s.getParentNamespace() != null ? s.getParentNamespace().getName() : ""));
            f.add(kvs("type", s.getSymbolType().toString()));
            items.add(obj(f));
        }
        return arr(items);
    }

    private String exportsArr() {
        List<String> items = new ArrayList<>();
        SymbolTable st = currentProgram.getSymbolTable();
        AddressIterator ai = st.getExternalEntryPointIterator();
        while (ai.hasNext()) {
            Address a = ai.next();
            Symbol s = st.getPrimarySymbol(a);
            List<String> f = new ArrayList<>();
            f.add(kvs("address", a.toString()));
            f.add(kvs("name", s != null ? s.getName() : ""));
            items.add(obj(f));
        }
        return arr(items);
    }

    private String symbolsArr() {
        List<String> items = new ArrayList<>();
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator si = st.getSymbolIterator(true);
        int n = 0;
        while (si.hasNext()) {
            Symbol s = si.next();
            if (s.isExternal()) continue;
            List<String> f = new ArrayList<>();
            f.add(kvs("name", s.getName()));
            f.add(kvs("address", s.getAddress().toString()));
            f.add(kvs("type", s.getSymbolType().toString()));
            f.add(kvb("primary", s.isPrimary()));
            items.add(obj(f));
            if (++n >= 8000) break;
        }
        return arr(items);
    }

    // ------------------------------------------------------------- function mode

    private String buildFunctionJson(String target) throws Exception {
        Function fn = resolveFunction(target);
        List<String> top = new ArrayList<>();
        top.add(kv("range_authority_sha256", restrictedMode ? q(rangeAuthoritySha256) : "null"));
        top.add(kv("schema", q("angerona/1")));
        top.add(kv("mode", q("function")));
        if (fn == null) {
            top.add(kvs("error", "function not found: " + nz(target)));
            top.add(kv("available_hint", q("use list_functions to see names/addresses")));
            return obj(top);
        }
        top.add(kvs("name", fn.getName()));
        top.add(kvs("entry", fn.getEntryPoint().toString()));
        top.add(kvn("size", fn.getBody().getNumAddresses()));
        top.add(kv("body_ranges", bodyRangesArr(fn)));
        top.add(kvs("signature", fn.getSignature().getPrototypeString()));
        top.add(kvs("calling_convention", nz(fn.getCallingConventionName())));
        top.add(kv("callees", nameSetArr(safeCalled(fn))));
        top.add(kv("callers", nameSetArr(safeCallers(fn))));
        top.add(kv("xrefs_to", xrefsArr(fn.getEntryPoint())));

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        String c = decompileC(decomp, fn, true);
        decomp.dispose();
        top.add(kvs("decompiled", restrictedText(nz(c))));
        top.add(kvb("decompilation_complete", decompilationSucceeded(c)));

        top.add(kv("disassembly", disassemblyArr(fn)));
        top.add(kv("pcode", pcodeArr(fn)));
        return obj(top);
    }

    private boolean decompilationSucceeded(String c) {
        return c != null
            && !c.startsWith("/* decompile failed:")
            && !c.contains("truncated by Angerona");
    }

    private String disassemblyArr(Function fn) {
        List<String> items = new ArrayList<>();
        Listing listing = currentProgram.getListing();
        InstructionIterator ii = listing.getInstructions(fn.getBody(), true);
        while (ii.hasNext()) {
            Instruction in = ii.next();
            if (restrictedMode && !isAllowed(in.getAddress())) continue;
            List<String> f = new ArrayList<>();
            f.add(kvs("address", in.getAddress().toString()));
            f.add(kvs("mnemonic", in.getMnemonicString()));
            f.add(kvs("text", restrictedText(in.toString())));
            items.add(obj(f));
        }
        return arr(items);
    }

    private String pcodeArr(Function fn) {
        List<String> items = new ArrayList<>();
        Listing listing = currentProgram.getListing();
        InstructionIterator ii = listing.getInstructions(fn.getBody(), true);
        while (ii.hasNext()) {
            Instruction in = ii.next();
            if (restrictedMode && !isAllowed(in.getAddress())) continue;
            ghidra.program.model.pcode.PcodeOp[] ops = in.getPcode();
            for (ghidra.program.model.pcode.PcodeOp op : ops) {
                List<String> f = new ArrayList<>();
                f.add(kvs("address", in.getAddress().toString()));
                f.add(kvs("op", restrictedText(op.toString())));
                items.add(obj(f));
            }
        }
        return arr(items);
    }

    private Function resolveFunction(String target) {
        if (target == null || target.isEmpty()) return null;
        // address form
        if (target.startsWith("0x") || target.matches("[0-9a-fA-F]{4,}")) {
            try {
                Address a = currentProgram.getAddressFactory().getAddress(target.replaceFirst("^0x", ""));
                if (a != null) {
                    Function f = getFunctionAt(a);
                    if (f == null) f = getFunctionContaining(a);
                    if (f != null && (!restrictedMode || isAllowed(f.getEntryPoint()))) return f;
                }
            } catch (Throwable ignore) {}
        }
        // name form
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f.getName().equals(target) && (!restrictedMode || isAllowed(f.getEntryPoint()))) return f;
        }
        return null;
    }

    private String restrictedText(String value) {
        if (!restrictedMode || value == null || value.isEmpty()) return value;
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(
            "(0x|FUN_|DAT_|PTR_|LAB_|sub_|off_|loc_)([0-9a-fA-F]{4,16})"
        );
        java.util.regex.Matcher matcher = pattern.matcher(value);
        StringBuffer output = new StringBuffer();
        while (matcher.find()) {
            boolean allowed = false;
            try {
                Address address = currentProgram.getAddressFactory().getAddress(matcher.group(2));
                allowed = address != null && isAllowed(address);
            } catch (Throwable ignored) {}
            matcher.appendReplacement(output, java.util.regex.Matcher.quoteReplacement(
                allowed ? matcher.group(0) : "REDACTED_OUTSIDE_NATIVE_AUTHORITY"
            ));
        }
        matcher.appendTail(output);
        return output.toString();
    }

    // ------------------------------------------------------------------- json

    private String obj(List<String> fields) { return "{" + String.join(",", fields) + "}"; }
    private String arr(List<String> items) { return "[" + String.join(",", items) + "]"; }
    private String kv(String k, String rawJsonValue) { return q(k) + ":" + rawJsonValue; }
    private String kvs(String k, String s) { return q(k) + ":" + q(s); }
    private String kvn(String k, long n) { return q(k) + ":" + n; }
    private String kvb(String k, boolean b) { return q(k) + ":" + (b ? "true" : "false"); }
    private String nz(String s) { return s == null ? "" : s; }

    private String q(String s) {
        if (s == null) return "\"\"";
        StringBuilder b = new StringBuilder(s.length() + 2);
        b.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                case '\b': b.append("\\b"); break;
                case '\f': b.append("\\f"); break;
                default:
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }
        b.append('"');
        return b.toString();
    }
}
