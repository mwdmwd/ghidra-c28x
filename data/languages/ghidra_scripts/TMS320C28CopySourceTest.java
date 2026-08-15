// Validate explicit proved inert copy-source cleanup in a fresh synthetic project.
// @category TMS320C28

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

public class TMS320C28CopySourceTest extends GhidraScript {
    private static final long FLASH_SOURCE = 0x1040;
    private static final long DESTINATION = 0x2040;
    private static final long AUX_SOURCE = 0x3000;
    private static final long COPY_WORDS = 0x10;

    private AddressSet sourceRange;
    private AddressSet destinationRange;
    private long sourceWord;
    private Memory memory;
    private Listing listing;
    private FunctionManager functions;
    private ReferenceManager references;
    private SymbolTable symbols;
    private BookmarkManager bookmarks;

    @Override
    public void run() throws Exception {
        Map<String, String> args = parseArgs(getScriptArgs());
        String mode = required(args, "mode");
        String profile = required(args, "profile");
        String baseline = required(args, "baseline");
        String workspace = required(args, "workspace");
        String absent = required(args, "absent");
        sourceWord = Long.decode(required(args, "source"));

        require(currentProgram.getAddressFactory().getDefaultAddressSpace()
            .getAddressableUnitSize() == 2, "expected two-byte C28x address units");
        memory = currentProgram.getMemory();
        listing = currentProgram.getListing();
        functions = currentProgram.getFunctionManager();
        references = currentProgram.getReferenceManager();
        symbols = currentProgram.getSymbolTable();
        bookmarks = currentProgram.getBookmarkManager();
        sourceRange = exactWordRange(sourceWord, COPY_WORDS);
        destinationRange = exactWordRange(DESTINATION, COPY_WORDS);

        runProfile(profile, null);
        if ("source-executable-destination".equals(mode)) {
            runProfile(profile, baseline);
            setupSourceEvidence(sourceWord, false);
        }
        else {
            setupSourceEvidence(sourceWord, true);
            runProfile(profile, baseline);
        }
        setupDestinationEvidence();
        setupNearMiss(mode);

        String sourceBefore = evidenceSignature(sourceRange);
        String destinationBefore = evidenceSignature(destinationRange);
        int blockCountBefore = memory.getBlocks().length;

        boolean failed = false;
        Exception failure = null;
        try {
            runProfile(profile, workspace);
        }
        catch (Exception error) {
            failed = true;
            failure = error;
        }

        boolean fatal = isFatal(mode);
        require(failed == fatal,
            "workspace failure mismatch for " + mode + ": failed=" + failed +
            (failure == null ? "" : " error=" + failure));

        if ("positive".equals(mode)) {
            checkPositive(profile, workspace, absent, destinationBefore, blockCountBefore);
        }
        else {
            require(sourceBefore.equals(evidenceSignature(sourceRange)),
                "rejected case changed source evidence: " + mode);
            require(destinationBefore.equals(evidenceSignature(destinationRange)),
                "rejected case changed valid live destination: " + mode);
            require(memory.getBlocks().length == blockCountBefore,
                "rejected case partially split memory: " + mode);
            MemoryBlock sourceBlock = memory.getBlock(sourceRange.getMinAddress());
            if (sourceBlock != null) {
                require(sourceBlock.isExecute(),
                    "rejected case changed source execute permission: " + mode);
            }
        }

        println("COPY_SOURCE_CASE_MODE=" + mode);
        println("COPY_SOURCE_CASE_SOURCE=0x" + Long.toHexString(sourceWord));
        println("COPY_SOURCE_CASE_PASS=" + mode);
    }

    private void runProfile(String profile, String workspace) throws Exception {
        String[] base = {
            "profile=" + profile,
            "strictFirmware=true",
            "recoverCopies=true",
            "seedAnalysis=true",
            "applyRegisterTypes=false",
            "verboseCopies=false",
        };
        if (workspace == null) {
            runScript("TMS320C28DeviceProfile.java", base);
            return;
        }
        String[] withWorkspace = Arrays.copyOf(base, base.length + 1);
        withWorkspace[base.length] = "workspace=" + workspace;
        runScript("TMS320C28DeviceProfile.java", withWorkspace);
    }

    private void setupSourceEvidence(long startWord, boolean includeEdges) throws Exception {
        Address start = wordAddress(startWord);
        Address end = wordAddress(startWord + COPY_WORDS).subtract(1);
        require(memory.getBlock(start) != null && memory.getBlock(start).isInitialized(),
            "source fixture is not initialized");
        require(disassemble(start), "failed to disassemble source fixture");

        Address dataStart = wordAddress(startWord + 6);
        Address dataEnd = wordAddress(startWord + 8).subtract(1);
        listing.clearCodeUnits(dataStart, dataEnd, false, monitor);
        Data data = listing.createData(dataStart, DWordDataType.dataType);
        require(data != null && data.getLength() == 4, "failed to create source data island");
        require(disassemble(wordAddress(startWord + 8)),
            "failed to resume source disassembly after data island");

        if (includeEdges) {
            require(disassemble(wordAddress(0x1030)), "failed to decode executable prefix");
            require(disassemble(wordAddress(0x1060)), "failed to decode executable suffix");
        }

        Namespace namespace = symbols.getNamespace("COPY_SOURCE_USER", currentProgram.getGlobalNamespace());
        if (namespace == null) {
            namespace = symbols.createNameSpace(currentProgram.getGlobalNamespace(),
                "COPY_SOURCE_USER", SourceType.USER_DEFINED);
        }
        Address labelAddress = wordAddress(startWord + 2);
        Symbol label = symbols.getSymbol("copy_source_user_label", labelAddress, namespace);
        if (label == null) {
            label = symbols.createLabel(labelAddress, "copy_source_user_label", namespace,
                SourceType.USER_DEFINED);
        }
        label.setPrimary();
        label.setPinned(true);
        listing.setComment(wordAddress(startWord + 3), CommentType.EOL,
            "copy-source-user-comment");
        bookmarks.setBookmark(wordAddress(startWord + 4), BookmarkType.NOTE,
            "copy-source", "copy-source-user-bookmark");

        references.addMemoryReference(wordAddress(startWord + 1), wordAddress(0x1100),
            RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, 0);
        references.addMemoryReference(wordAddress(startWord + 2), wordAddress(0x1101),
            RefType.UNCONDITIONAL_JUMP, SourceType.ANALYSIS, 0);
        references.addMemoryReference(wordAddress(startWord + 3), wordAddress(0x1102),
            RefType.DATA, SourceType.ANALYSIS, 0);
        references.addMemoryReference(wordAddress(0x1010), wordAddress(startWord + 5),
            RefType.PARAM, SourceType.USER_DEFINED, 0);

        require(countInstructions(sourceRange) > 0, "source did not retain decoded instructions");
        require(countReferencesFrom(sourceRange) >= 3,
            "source fixture lacks outgoing call/flow/data references");
        require(countExternalIncomingNonFlow(sourceRange) == 1,
            "source fixture lacks exact external non-flow evidence");
        require(listing.getCodeUnitContaining(end) != null,
            "source fixture lost final code unit");
    }

    private void setupDestinationEvidence() {
        require(memory.getBlock(wordAddress(DESTINATION)) != null &&
            memory.getBlock(wordAddress(DESTINATION)).isInitialized() &&
            memory.getBlock(wordAddress(DESTINATION)).isExecute(),
            "baseline did not materialize executable destination");
        if (listing.getInstructionAt(wordAddress(DESTINATION)) == null) {
            disassemble(wordAddress(DESTINATION));
        }
        Function destinationFunction = functions.getFunctionAt(wordAddress(DESTINATION));
        if (destinationFunction == null) {
            destinationFunction = createFunction(wordAddress(DESTINATION), null);
        }
        require(destinationFunction != null, "baseline destination is not function-backed");
        references.addMemoryReference(wordAddress(DESTINATION + 1), wordAddress(0x1100),
            RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, 0);
        references.addMemoryReference(wordAddress(DESTINATION + 2), wordAddress(0x1101),
            RefType.UNCONDITIONAL_JUMP, SourceType.ANALYSIS, 0);
        references.addMemoryReference(wordAddress(DESTINATION + 3), wordAddress(0x1102),
            RefType.DATA, SourceType.ANALYSIS, 0);
        require(countInstructions(destinationRange) > 0,
            "baseline destination has no instructions");
        require(countReferencesFrom(destinationRange) >= 3,
            "baseline destination has no ordinary references");
    }

    private void setupNearMiss(String mode) throws Exception {
        Address source = wordAddress(sourceWord);
        switch (mode) {
            case "incompatible-destination" -> {
                functions.removeFunction(wordAddress(DESTINATION));
                listing.clearCodeUnits(destinationRange.getMinAddress(),
                    destinationRange.getMaxAddress(), false, monitor);
                memory.setBytes(wordAddress(DESTINATION), new byte[] { 1, 2, 3, 4 });
                listing.createData(wordAddress(DESTINATION), DWordDataType.dataType);
            }
            case "function-entry" -> {
                Function function = functions.getFunctionAt(source);
                if (function == null) {
                    function = createFunction(source, null);
                }
                require(function != null, "failed to create source function entry");
            }
            case "function-body" -> {
                Address entry = wordAddress(0x1030);
                Function function = functions.getFunctionAt(entry);
                if (function == null) {
                    function = createFunction(entry, null);
                }
                require(function != null, "failed to create intersecting function");
                function.setBody(new AddressSet(entry,
                    wordAddress(sourceWord + 2).subtract(1)));
                require(function.getBody().intersects(sourceRange),
                    "function body does not intersect source");
            }
            case "external-entry" -> symbols.addExternalEntryPoint(wordAddress(sourceWord + 1));
            case "external-call" -> references.addMemoryReference(wordAddress(0x1020),
                wordAddress(sourceWord + 1), RefType.UNCONDITIONAL_CALL,
                SourceType.USER_DEFINED, 0);
            case "external-jump" -> references.addMemoryReference(wordAddress(0x1020),
                wordAddress(sourceWord + 1), RefType.UNCONDITIONAL_JUMP,
                SourceType.USER_DEFINED, 0);
            case "external-conditional" -> references.addMemoryReference(wordAddress(0x1020),
                wordAddress(sourceWord + 1), RefType.CONDITIONAL_JUMP,
                SourceType.USER_DEFINED, 0);
            case "external-fallthrough" -> {
                require(disassemble(wordAddress(sourceWord - 1)),
                    "failed to create external fall-through predecessor");
                Instruction first = listing.getInstructionAt(source);
                require(first != null && wordAddress(sourceWord - 1).equals(first.getFallFrom()),
                    "fixture did not create implicit external fall-through");
            }
            case "isolation-boundary" -> {
                Address crossingStart = wordAddress(sourceWord - 1);
                Address crossingEnd = wordAddress(sourceWord + 1).subtract(1);
                listing.clearCodeUnits(crossingStart, crossingEnd, false, monitor);
                Data crossing = listing.createData(crossingStart, DWordDataType.dataType);
                require(crossing != null && crossing.getMaxAddress().compareTo(source) >= 0,
                    "fixture did not create a boundary-crossing code unit");
            }
            default -> {
                // Policy/schema and ordinary range negatives are JSON-owned.
            }
        }
    }

    private void checkPositive(String profile, String workspace, String absent,
            String destinationBefore, int blockCountBefore) throws Exception {
        checkExactInertSource();
        require(destinationBefore.equals(evidenceSignature(destinationRange)),
            "cleanup changed live destination listing/functions/references");
        int isolatedBlockCount = memory.getBlocks().length;
        require(isolatedBlockCount == blockCountBefore + 2,
            "strict subrange isolation did not produce exact prefix/source/suffix split");

        MemoryBlock sourceBlock = memory.getBlock(sourceRange.getMinAddress());
        String marker = sourceBlock.getSourceName();
        String comment = sourceBlock.getComment();
        require(marker != null && marker.contains(":COPY_SOURCE:EXPLICIT:TEST_LIVE_COPY:INERT_STORAGE"),
            "source lacks stable workspace-owned provenance marker");
        require(countOccurrences(comment, "explicit copy source TEST_LIVE_COPY") == 1,
            "source block metadata was duplicated");

        String sourceAfter = evidenceSignature(sourceRange);
        runProfile(profile, workspace);
        require(memory.getBlocks().length == isolatedBlockCount,
            "second workspace application added source splits");
        require(sourceAfter.equals(evidenceSignature(sourceRange)),
            "second workspace application changed inert source evidence");
        sourceBlock = memory.getBlock(sourceRange.getMinAddress());
        require(countOccurrences(sourceBlock.getComment(),
            "explicit copy source TEST_LIVE_COPY") == 1,
            "second workspace application duplicated provenance metadata");

        // Cleanup is deliberately monotonic: removing the policy later does
        // not pretend that deleted analysis state can be reconstructed.
        runProfile(profile, absent);
        require(sourceAfter.equals(evidenceSignature(sourceRange)),
            "policy removal implicitly restored source execution/listing");

        analyzeAll(currentProgram);
        require(countInstructions(sourceRange) == 0,
            "full auto-analysis recreated source instructions");
        require(functions.getFunctionsOverlapping(sourceRange).hasNext() == false,
            "full auto-analysis recreated source functions");
        require(countReferencesFrom(sourceRange) == 0,
            "full auto-analysis recreated source outgoing references");
        checkDestinationAlive();

        Options options = currentProgram.getOptions("TMS320C28 Firmware Workspace");
        require(options.getInt("Inert Source Cleanups", -1) >= 0,
            "workspace did not record inert-source metrics");
        println("COPY_SOURCE_POSITIVE_SOURCE_INSTRUCTIONS=0");
        println("COPY_SOURCE_POSITIVE_SOURCE_EXTERNAL_NONFLOW=1");
        println("COPY_SOURCE_POSITIVE_IDEMPOTENT=1");
        println("COPY_SOURCE_POSITIVE_MONOTONIC=1");
    }

    private void checkExactInertSource() throws Exception {
        MemoryBlock source = memory.getBlock(sourceRange.getMinAddress());
        require(source != null, "missing isolated source block");
        require(source.getStart().equals(sourceRange.getMinAddress()) &&
            source.getEnd().equals(sourceRange.getMaxAddress()),
            "source block is not the exact selected range");
        require(source.isInitialized() && source.isRead() && !source.isWrite() &&
            !source.isExecute() && !source.isVolatile(),
            "source permissions/state changed beyond execute");
        require(countInstructions(sourceRange) == 0, "source instructions remain");
        require(!functions.getFunctionsOverlapping(sourceRange).hasNext(),
            "source still intersects a function");
        require(countReferencesFrom(sourceRange) == 0,
            "outgoing references from removed source code remain");
        require(bytes(sourceRange).equals(bytes(destinationRange)),
            "source/destination bytes differ after cleanup");

        Symbol label = symbols.getSymbol("copy_source_user_label",
            wordAddress(sourceWord + 2),
            symbols.getNamespace("COPY_SOURCE_USER", currentProgram.getGlobalNamespace()));
        require(label != null && label.getSource() == SourceType.USER_DEFINED &&
            label.isPrimary() && label.isPinned(), "source user label did not survive");
        require("copy-source-user-comment".equals(
            listing.getComment(CommentType.EOL, wordAddress(sourceWord + 3))),
            "source listing comment did not survive");
        Bookmark bookmark = bookmarks.getBookmark(wordAddress(sourceWord + 4),
            BookmarkType.NOTE, "copy-source");
        require(bookmark != null && "copy-source-user-bookmark".equals(bookmark.getComment()),
            "source bookmark did not survive");
        Data data = listing.getDefinedDataAt(wordAddress(sourceWord + 6));
        require(data != null && data.getLength() == 4,
            "source defined-data island did not survive");
        require(countExternalIncomingNonFlow(sourceRange) == 1,
            "external non-flow evidence did not survive");

        MemoryBlock prefix = memory.getBlock(wordAddress(0x1030));
        MemoryBlock suffix = memory.getBlock(wordAddress(0x1060));
        require(prefix != null && prefix.isInitialized() && prefix.isRead() &&
            !prefix.isWrite() && prefix.isExecute(),
            "executable Flash prefix changed");
        require(suffix != null && suffix.isInitialized() && suffix.isRead() &&
            !suffix.isWrite() && suffix.isExecute(),
            "executable Flash suffix changed");
        require(listing.getInstructionAt(wordAddress(0x1030)) != null,
            "prefix listing was cleared");
        require(listing.getInstructionAt(wordAddress(0x1060)) != null,
            "suffix listing was cleared");
        checkDestinationAlive();
    }

    private void checkDestinationAlive() {
        MemoryBlock destination = memory.getBlock(destinationRange.getMinAddress());
        require(destination != null && destination.isInitialized() &&
            destination.isRead() && destination.isWrite() && destination.isExecute(),
            "live destination permissions/state changed");
        require(countInstructions(destinationRange) > 0,
            "live destination lost instructions");
        require(functions.getFunctionsOverlapping(destinationRange).hasNext(),
            "live destination lost functions");
        require(countReferencesFrom(destinationRange) > 0,
            "live destination lost ordinary references");
    }

    private String evidenceSignature(AddressSetView range) {
        Set<String> parts = new TreeSet<>();
        Address min = range.getMinAddress();
        Address max = range.getMaxAddress();
        Address cursor = min;
        while (cursor.compareTo(max) <= 0) {
            MemoryBlock block = memory.getBlock(cursor);
            if (block == null) {
                parts.add("BLOCK|UNMAPPED|" + cursor);
                break;
            }
            Address clippedEnd = block.getEnd().compareTo(max) < 0 ? block.getEnd() : max;
            parts.add("BLOCK|" + cursor + "|" + clippedEnd + "|" + block.getName() + "|" +
                block.isInitialized() + "|" + block.isRead() + "|" + block.isWrite() + "|" +
                block.isExecute() + "|" + block.isVolatile() + "|" + block.getSourceName() + "|" +
                block.getComment());
            if (clippedEnd.equals(max)) {
                break;
            }
            cursor = clippedEnd.add(1);
        }
        parts.add("BYTES|" + bytes(range));

        InstructionIterator instructions = listing.getInstructions(range, true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            parts.add("INS|" + instruction.getMinAddress() + "|" +
                instruction.getMaxAddress() + "|" + instruction.toString());
        }
        DataIterator data = listing.getDefinedData(range, true);
        while (data.hasNext()) {
            Data item = data.next();
            parts.add("DATA|" + item.getMinAddress() + "|" + item.getMaxAddress() + "|" +
                item.getDataType().getPathName());
        }
        SymbolIterator symbolIterator = symbols.getDefinedSymbols();
        while (symbolIterator.hasNext()) {
            Symbol symbol = symbolIterator.next();
            if (!range.contains(symbol.getAddress()) || symbol.isDynamic()) {
                continue;
            }
            parts.add("SYM|" + symbol.getAddress() + "|" + symbol.getName(true) + "|" +
                symbol.getSymbolType() + "|" + symbol.getSource() + "|" +
                symbol.isPrimary() + "|" + symbol.isPinned());
        }
        AddressIterator comments = listing.getCommentAddressIterator(range, true);
        while (comments.hasNext()) {
            Address address = comments.next();
            for (CommentType type : CommentType.values()) {
                String text = listing.getComment(type, address);
                if (text != null) {
                    parts.add("COMMENT|" + address + "|" + type + "|" + text);
                }
            }
        }
        Iterator<Bookmark> bookmarkIterator = bookmarks.getBookmarksIterator(min, true);
        while (bookmarkIterator.hasNext()) {
            Bookmark bookmark = bookmarkIterator.next();
            if (bookmark.getAddress().compareTo(max) > 0) {
                break;
            }
            if (range.contains(bookmark.getAddress())) {
                parts.add("BOOKMARK|" + bookmark.getAddress() + "|" +
                    bookmark.getTypeString() + "|" + bookmark.getCategory() + "|" +
                    bookmark.getComment());
            }
        }
        Iterator<Function> functionIterator = functions.getFunctionsOverlapping(range);
        while (functionIterator.hasNext()) {
            Function function = functionIterator.next();
            parts.add("FUNCTION|" + function.getEntryPoint() + "|" + function.getBody());
        }
        AddressIterator sources = references.getReferenceSourceIterator(range, true);
        while (sources.hasNext()) {
            Address from = sources.next();
            for (Reference reference : references.getReferencesFrom(from)) {
                parts.add(referenceSignature("OUT", reference));
            }
        }
        AddressIterator destinations = references.getReferenceDestinationIterator(range, true);
        while (destinations.hasNext()) {
            ReferenceIterator incoming = references.getReferencesTo(destinations.next());
            while (incoming.hasNext()) {
                Reference reference = incoming.next();
                if (!range.contains(reference.getFromAddress())) {
                    parts.add(referenceSignature("IN", reference));
                }
            }
        }
        return String.join("\n", parts);
    }

    private String bytes(AddressSetView range) {
        Address start = range.getMinAddress();
        MemoryBlock block = memory.getBlock(start);
        if (block == null || !block.isInitialized()) {
            return "UNINITIALIZED";
        }
        long length = range.getMaxAddress().subtract(start) + 1;
        if (length > Integer.MAX_VALUE) {
            return "TOO_LARGE";
        }
        byte[] data = new byte[(int) length];
        try {
            int count = memory.getBytes(start, data);
            return count + ":" + hex(data);
        }
        catch (MemoryAccessException error) {
            return "READ_ERROR:" + error.getMessage();
        }
    }

    private String referenceSignature(String direction, Reference reference) {
        return direction + "|" + reference.getFromAddress() + "|" +
            reference.getToAddress() + "|" + reference.getReferenceType() + "|" +
            reference.getSource() + "|" + reference.getOperandIndex() + "|" +
            reference.isPrimary();
    }

    private long countInstructions(AddressSetView range) {
        long count = 0;
        InstructionIterator iterator = listing.getInstructions(range, true);
        while (iterator.hasNext()) {
            iterator.next();
            count++;
        }
        return count;
    }

    private long countReferencesFrom(AddressSetView range) {
        long count = 0;
        AddressIterator iterator = references.getReferenceSourceIterator(range, true);
        while (iterator.hasNext()) {
            count += references.getReferencesFrom(iterator.next()).length;
        }
        return count;
    }

    private long countExternalIncomingNonFlow(AddressSetView range) {
        long count = 0;
        AddressIterator destinations = references.getReferenceDestinationIterator(range, true);
        while (destinations.hasNext()) {
            ReferenceIterator incoming = references.getReferencesTo(destinations.next());
            while (incoming.hasNext()) {
                Reference reference = incoming.next();
                if (!range.contains(reference.getFromAddress()) &&
                        !reference.getReferenceType().isFlow()) {
                    count++;
                }
            }
        }
        return count;
    }

    private AddressSet exactWordRange(long startWord, long words) {
        return new AddressSet(wordAddress(startWord),
            wordAddress(Math.addExact(startWord, words)).subtract(1));
    }

    private Address wordAddress(long word) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace()
            .getAddress(Math.multiplyExact(word, 2L));
    }

    private static boolean isFatal(String mode) {
        return Set.of("empty", "overflow", "overlap", "unmapped-source",
            "uninitialized-source", "unmapped-destination",
            "incompatible-destination").contains(mode);
    }

    private static int countOccurrences(String text, String needle) {
        if (text == null || needle.isEmpty()) {
            return 0;
        }
        int count = 0;
        int offset = 0;
        while ((offset = text.indexOf(needle, offset)) >= 0) {
            count++;
            offset += needle.length();
        }
        return count;
    }

    private static String hex(byte[] data) {
        StringBuilder result = new StringBuilder(data.length * 2);
        for (byte value : data) {
            result.append(String.format(Locale.ROOT, "%02x", value & 0xff));
        }
        return result.toString();
    }

    private static Map<String, String> parseArgs(String[] raw) {
        Map<String, String> result = new LinkedHashMap<>();
        for (String arg : raw) {
            int equals = arg.indexOf('=');
            if (equals <= 0) {
                throw new IllegalArgumentException(
                    "COPY_SOURCE_TEST_ERROR: expected key=value argument: " + arg);
            }
            result.put(arg.substring(0, equals), arg.substring(equals + 1));
        }
        return result;
    }

    private static String required(Map<String, String> args, String name) {
        String value = args.get(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("COPY_SOURCE_TEST_ERROR: missing " + name);
        }
        return value;
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException("COPY_SOURCE_TEST_ERROR: " + message);
        }
    }
}
