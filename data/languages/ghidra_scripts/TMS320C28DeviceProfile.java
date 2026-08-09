// Apply a checked F2837xS-compatible memory/register profile.  An optional,
// separately maintained firmware workspace may validate an image and recover
// image-specific initialized sections and analysis seeds.
// @category TMS320C28

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.InvalidInputException;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class TMS320C28DeviceProfile extends GhidraScript {
    private static final String SCHEMA = "tms320c28-device-profile";
    private static final String WORKSPACE_SCHEMA = "tms320c28-firmware-workspace";
    private static final String SOURCE_PREFIX = "TMS320C28_DEVICE_PROFILE:";
    private static final String WORKSPACE_SOURCE_PREFIX = "TMS320C28_FIRMWARE_WORKSPACE:";
    private static final String ROM_SOURCE_PREFIX = "TMS320C28_ROM_EVIDENCE:";
    private static final String COMMENT_PREFIX = "[TMS320C28 device profile]";
    private static final int COPY_CHUNK_BYTES = 64 * 1024;

    private JsonObject profile;
    private JsonObject workspace;
    private Memory memory;
    private Listing listing;
    private SymbolTable symbols;
    private AddressSpace space;
    private int addressUnitBytes;
    private String profileName;
    private String workspaceName;
    private Namespace rootNamespace;
    private final Map<String, Namespace> namespaceCache = new HashMap<>();

    private int createdBlocks;
    private int reusedBlocks;
    private int labelsCreated;
    private int labelsReused;
    private int labelsPromoted;
    private int dataCreated;
    private int dataSkipped;
    private int explicitCopies;
    private int cinitRecords;
    private long recoveredWords;
    private int disassemblySeeds;
    private int functionSeeds;
    private boolean verboseCopies;

    private static final class CopyRecord {
        final String name;
        final long sourceWord;
        final long destinationWord;
        final long words;
        final boolean executable;
        final String evidence;

        CopyRecord(String name, long sourceWord, long destinationWord, long words,
                boolean executable, String evidence) {
            this.name = name;
            this.sourceWord = sourceWord;
            this.destinationWord = destinationWord;
            this.words = words;
            this.executable = executable;
            this.evidence = evidence;
        }
    }

    @Override
    public void run() throws Exception {
        Map<String, String> args = parseArgs(getScriptArgs());
        String profilePath = args.get("profile");
        if (profilePath == null || profilePath.isBlank()) {
            fail("missing required script argument profile=/absolute/path/profile.json");
        }
        boolean strictFirmware = parseBoolean(args, "strictFirmware", true);
        boolean recoverCopies = parseBoolean(args, "recoverCopies", true);
        boolean seedAnalysis = parseBoolean(args, "seedAnalysis", true);
        boolean applyRegisterTypes = parseBoolean(args, "applyRegisterTypes", true);
        verboseCopies = parseBoolean(args, "verboseCopies", false);

        File file = new File(profilePath).getCanonicalFile();
        if (!file.isFile()) {
            fail("profile does not exist: " + file);
        }
        try (BufferedReader reader = new BufferedReader(new FileReader(file, StandardCharsets.UTF_8))) {
            profile = JsonParser.parseReader(reader).getAsJsonObject();
        }

        File workspaceFile = null;
        String workspacePath = args.get("workspace");
        if (workspacePath != null && !workspacePath.isBlank()) {
            workspaceFile = new File(workspacePath).getCanonicalFile();
            if (!workspaceFile.isFile()) {
                fail("firmware workspace does not exist: " + workspaceFile);
            }
            try (BufferedReader reader = new BufferedReader(
                    new FileReader(workspaceFile, StandardCharsets.UTF_8))) {
                workspace = JsonParser.parseReader(reader).getAsJsonObject();
            }
        }

        validateProfileHeader();
        memory = currentProgram.getMemory();
        listing = currentProgram.getListing();
        symbols = currentProgram.getSymbolTable();
        space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        addressUnitBytes = space.getAddressableUnitSize();
        profileName = requiredString(profile, "profileName");
        if (workspace != null) {
            validateWorkspaceHeader();
            workspaceName = requiredString(workspace, "workspaceName");
        }

        int declaredUnit = requiredInt(profile, "addressUnitBytes");
        if (addressUnitBytes != declaredUnit) {
            fail("addressable-unit mismatch: program=" + addressUnitBytes + " profile=" + declaredUnit);
        }
        if (addressUnitBytes != 2) {
            fail("this profile requires a C28x 16-bit addressable unit, got " + addressUnitBytes + " bytes");
        }

        println("DEVICE_PROFILE_BEGIN=" + profileName);
        println("DEVICE_PROFILE_FILE=" + file);
        println("DEVICE_PROFILE_ADDRESS_UNIT_BYTES=" + addressUnitBytes);

        applyMemoryBlocks();
        createNamespaces();
        createMemoryLabels();
        createBaseLabels();
        createRegisterLabelsAndTypes(applyRegisterTypes);

        if (workspace != null) {
            applyFirmwareIdentity(strictFirmware);
            if (recoverCopies && workspace.has("copyRecovery")) {
                recoverInitializedSections();
            }
            if (seedAnalysis) {
                seedKnownAnalysis();
            }
        }

        recordProgramOptions(file, workspaceFile, strictFirmware, recoverCopies);
        printMetrics();
    }

    private void validateProfileHeader() {
        String schema = requiredString(profile, "schema");
        if (!SCHEMA.equals(schema)) {
            fail("unsupported profile schema: " + schema);
        }
        int version = requiredInt(profile, "version");
        if (version != 1) {
            fail("unsupported profile version: " + version);
        }
        requiredArray(profile, "blocks");
        requiredArray(profile, "baseLabels");
        requiredArray(profile, "registers");
    }

    private void validateWorkspaceHeader() {
        String schema = requiredString(workspace, "schema");
        if (!WORKSPACE_SCHEMA.equals(schema)) {
            fail("unsupported firmware workspace schema: " + schema);
        }
        int version = requiredInt(workspace, "version");
        if (version != 1) {
            fail("unsupported firmware workspace version: " + version);
        }
        String deviceProfile = requiredString(workspace, "deviceProfile");
        if (!profileName.equals(deviceProfile)) {
            fail("firmware workspace requires device profile " + deviceProfile +
                ", not " + profileName);
        }
        requiredObject(workspace, "firmware");
    }

    private void applyFirmwareIdentity(boolean strictFirmware) throws Exception {
        JsonObject fw = requiredObject(workspace, "firmware");
        long baseWord = requiredLong(fw, "wordBase");
        long byteLength = requiredLong(fw, "byteLength");
        String expectedHash = requiredString(fw, "sha256").toLowerCase(Locale.ROOT);
        String desiredName = requiredString(fw, "blockName");

        if (byteLength <= 0 || byteLength % addressUnitBytes != 0) {
            fail("firmware byteLength must be a positive whole number of C28x words: " + byteLength);
        }
        Address start = wordAddress(baseWord);
        Address endExclusive = start.add(byteLength);
        requireRangeMapped(start, endExclusive, true, "firmware image");

        String actualHash = sha256Memory(start, byteLength);
        println("FIRMWARE_WORKSPACE_SHA256=" + actualHash);
        if (!actualHash.equals(expectedHash)) {
            String message = "firmware SHA-256 mismatch: expected=" + expectedHash + " actual=" + actualHash;
            if (strictFirmware) {
                fail(message);
            }
            printerr("DEVICE_PROFILE_WARNING=" + message);
        }

        List<MemoryBlock> blocks = isolateRange(start, endExclusive, "firmware image");
        int index = 0;
        for (MemoryBlock block : blocks) {
            if (!block.isInitialized()) {
                fail("firmware image contains an uninitialized block: " + describeBlock(block));
            }
            String name = index == 0 ? desiredName : desiredName + "_PART" + index;
            safeRename(block, name);
            block.setPermissions(getBoolean(fw, "read", true), getBoolean(fw, "write", false),
                getBoolean(fw, "execute", true));
            block.setVolatile(false);
            block.setSourceName(WORKSPACE_SOURCE_PREFIX + workspaceName + ":FIRMWARE");
            block.setComment(COMMENT_PREFIX + " validated firmware workspace " + workspaceName +
                "; SHA-256 " + actualHash);
            index++;
        }
        createStableLabel(start, sanitizeSymbol(desiredName + "_BASE"), childNamespace("MEMORY"));
        println("FIRMWARE_WORKSPACE_WORD_BASE=0x" + Long.toHexString(baseWord));
        println("FIRMWARE_WORKSPACE_WORDS=" + (byteLength / addressUnitBytes));
    }

    private void applyMemoryBlocks() throws Exception {
        JsonArray blocks = requiredArray(profile, "blocks");
        List<JsonObject> sorted = new ArrayList<>();
        for (JsonElement e : blocks) {
            sorted.add(e.getAsJsonObject());
        }
        sorted.sort(Comparator.comparingLong(o -> requiredLong(o, "start")));

        long previousEnd = -1;
        String previousName = null;
        for (JsonObject b : sorted) {
            long startWord = requiredLong(b, "start");
            long words = requiredLong(b, "words");
            String name = requiredString(b, "name");
            if (words <= 0 || addExact(startWord, words, "profile block " + name) > unsignedSpaceWordLimit()) {
                fail("invalid profile block range: " + name);
            }
            if (previousEnd > startWord) {
                fail("profile blocks overlap: " + previousName + " and " + name);
            }
            previousEnd = startWord + words;
            previousName = name;
            applyOneMemoryBlock(b);
        }
    }

    private void applyOneMemoryBlock(JsonObject spec) throws Exception {
        String desiredName = requiredString(spec, "name");
        long startWord = requiredLong(spec, "start");
        long words = requiredLong(spec, "words");
        Address start = wordAddress(startWord);
        Address endExclusive = wordAddress(addExact(startWord, words, desiredName));
        boolean read = getBoolean(spec, "read", true);
        boolean write = getBoolean(spec, "write", false);
        boolean execute = getBoolean(spec, "execute", false);
        boolean volatileBlock = getBoolean(spec, "volatile", false);
        String kind = requiredString(spec, "kind");
        String source = getString(spec, "source", "profile metadata");

        Address cursor = start;
        int part = 0;
        while (cursor.compareTo(endExclusive) < 0) {
            monitor.checkCancelled();
            MemoryBlock existing = memory.getBlock(cursor);
            if (existing == null) {
                Address gapEnd = nextBlockStart(cursor, endExclusive);
                long byteLength = gapEnd.subtract(cursor);
                String name = uniqueBlockName(part == 0 && cursor.equals(start) && gapEnd.equals(endExclusive)
                    ? desiredName : desiredName + "_PART" + part);
                existing = memory.createUninitializedBlock(name, cursor, byteLength, false);
                createdBlocks++;
            }
            else {
                if (existing.getStart().compareTo(cursor) < 0) {
                    memory.split(existing, cursor);
                    existing = memory.getBlock(cursor);
                }
                if (existing.getEnd().compareTo(endExclusive) >= 0 && !existing.getStart().equals(endExclusive)) {
                    if (existing.getStart().compareTo(endExclusive) < 0) {
                        memory.split(existing, endExclusive);
                        existing = memory.getBlock(cursor);
                    }
                }
                reusedBlocks++;
            }

            Address segmentEndExclusive = minAddress(existing.getEnd().add(1), endExclusive);
            if (existing.isMapped()) {
                fail("mapped block overlaps profile range " + desiredName + ": " + describeBlock(existing));
            }
            boolean externalEvidence = isWorkspaceOwned(existing) || isRomEvidenceOwned(existing);
            if (existing.isInitialized() && !isProfileOwned(existing) && !externalEvidence && write) {
                fail("incompatible initialized writable overlap in " + desiredName + ": " +
                    describeBlock(existing));
            }

            if (!externalEvidence) {
                existing.setPermissions(read, write, execute);
                existing.setVolatile(volatileBlock);
                if (!existing.isInitialized() || isProfileOwned(existing)) {
                    existing.setSourceName(SOURCE_PREFIX + profileName + ":MAP:" + desiredName);
                }
                appendBlockComment(existing, COMMENT_PREFIX + " " + kind + " block " +
                    desiredName + "; source: " + source);
            }
            if (existing.getStart().equals(start) && segmentEndExclusive.equals(endExclusive) &&
                    !externalEvidence) {
                safeRename(existing, desiredName);
            }
            cursor = segmentEndExclusive;
            part++;
        }
    }

    private void createNamespaces() throws Exception {
        Namespace global = currentProgram.getGlobalNamespace();
        rootNamespace = symbols.getOrCreateNameSpace(global, "F2837xS_COMPAT", SourceType.ANALYSIS);
        namespaceCache.put("", rootNamespace);
        childNamespace("MEMORY");
        childNamespace("BASES");
        childNamespace("PERIPHERALS");
        childNamespace("RECOVERED");
    }

    private Namespace childNamespace(String path) throws Exception {
        Namespace cached = namespaceCache.get(path);
        if (cached != null) {
            return cached;
        }
        Namespace parent = rootNamespace;
        String accumulated = "";
        for (String component : path.split("/")) {
            if (component.isBlank()) {
                continue;
            }
            accumulated = accumulated.isEmpty() ? component : accumulated + "/" + component;
            Namespace ns = namespaceCache.get(accumulated);
            if (ns == null) {
                ns = symbols.getOrCreateNameSpace(parent, sanitizeSymbol(component), SourceType.ANALYSIS);
                namespaceCache.put(accumulated, ns);
            }
            parent = ns;
        }
        return parent;
    }

    private void createMemoryLabels() throws Exception {
        Namespace ns = childNamespace("MEMORY");
        for (JsonElement e : requiredArray(profile, "blocks")) {
            JsonObject b = e.getAsJsonObject();
            createStableLabel(wordAddress(requiredLong(b, "start")),
                sanitizeSymbol(requiredString(b, "name") + "_BASE"), ns);
        }
    }

    private void createBaseLabels() throws Exception {
        Namespace ns = childNamespace("BASES");
        for (JsonElement e : requiredArray(profile, "baseLabels")) {
            JsonObject b = e.getAsJsonObject();
            Address address = wordAddress(requiredLong(b, "address"));
            if (memory.getBlock(address) == null) {
                fail("base label is outside mapped memory: " + requiredString(b, "symbol") + " at " + address);
            }
            createStableLabel(address, sanitizeSymbol(requiredString(b, "symbol")), ns);
            String display = getString(b, "displayName", "");
            if (!display.isBlank()) {
                appendComment(address, COMMENT_PREFIX + " TI peripheral base: " + display);
            }
        }
    }

    private void createRegisterLabelsAndTypes(boolean applyTypes) throws Exception {
        Namespace peripheralRoot = childNamespace("PERIPHERALS");
        Set<String> typedRanges = new HashSet<>();
        for (JsonElement e : requiredArray(profile, "registers")) {
            monitor.checkCancelled();
            JsonObject r = e.getAsJsonObject();
            String module = sanitizeSymbol(requiredString(r, "namespace"));
            Namespace ns = symbols.getOrCreateNameSpace(peripheralRoot, module, SourceType.ANALYSIS);
            Address address = wordAddress(requiredLong(r, "address"));
            MemoryBlock block = memory.getBlock(address);
            if (block == null) {
                fail("register is outside mapped memory: " + module + "::" + requiredString(r, "name") +
                    " at " + address);
            }
            String registerName = sanitizeSymbol(requiredString(r, "name"));
            createStableLabel(address, registerName, ns, true);

            int widthBits = requiredInt(r, "widthBits");
            String rangeKey = address.getOffset() + ":" + widthBits;
            if (applyTypes && (widthBits == 16 || widthBits == 32) && typedRanges.add(rangeKey)) {
                applyRegisterType(address, widthBits);
            }
            appendComment(address, formatRegisterComment(module, registerName, r));
        }
    }

    private void applyRegisterType(Address address, int widthBits) {
        DataType type = widthBits == 16 ? UnsignedShortDataType.dataType : DWordDataType.dataType;
        Address end = address.add(type.getLength() - 1L);
        if (memory.getBlock(end) == null) {
            dataSkipped++;
            return;
        }
        Data existing = listing.getDefinedDataAt(address);
        if (existing != null) {
            if (existing.getLength() == type.getLength()) {
                dataSkipped++;
                return;
            }
            dataSkipped++;
            return;
        }
        if (!listing.isUndefined(address, end)) {
            dataSkipped++;
            return;
        }
        try {
            listing.createData(address, type);
            dataCreated++;
        }
        catch (Exception ex) {
            dataSkipped++;
        }
    }

    private String formatRegisterComment(String module, String registerName, JsonObject r) {
        StringBuilder sb = new StringBuilder();
        sb.append(COMMENT_PREFIX).append(' ').append(module).append("::").append(registerName);
        String description = getString(r, "description", "");
        if (!description.isBlank()) {
            sb.append(" — ").append(description);
        }
        sb.append("; width ").append(requiredInt(r, "widthBits")).append(" bits");
        JsonArray fields = r.has("fields") ? r.getAsJsonArray("fields") : new JsonArray();
        int added = 0;
        for (JsonElement element : fields) {
            JsonObject f = element.getAsJsonObject();
            if (added >= 48 || sb.length() > 3500) {
                sb.append("; …");
                break;
            }
            sb.append("\n  ").append(requiredString(f, "name"))
                .append(" bits ").append(requiredInt(f, "shift"));
            int size = requiredInt(f, "size");
            if (size > 1) {
                sb.append('-').append(requiredInt(f, "shift") + size - 1);
            }
            String fd = getString(f, "description", "");
            if (!fd.isBlank()) {
                sb.append(": ").append(fd);
            }
            added++;
        }
        return sb.toString();
    }

    private void recoverInitializedSections() throws Exception {
        JsonObject recovery = requiredObject(workspace, "copyRecovery");
        JsonObject cinit = recovery.has("cinit") ? recovery.getAsJsonObject("cinit") : null;
        if (cinit != null) {
            recoverCinit(cinit);
        }
        if (recovery.has("explicit")) {
            int index = 0;
            for (JsonElement e : recovery.getAsJsonArray("explicit")) {
                JsonObject c = e.getAsJsonObject();
                CopyRecord record = new CopyRecord(
                    requiredString(c, "name"), requiredLong(c, "source"),
                    requiredLong(c, "destination"), requiredLong(c, "words"),
                    getBoolean(c, "executable", false), getString(c, "evidence", "explicit copy evidence"));
                if (record.words == 0) {
                    index++;
                    continue;
                }
                recoverCopy(record, "EXPLICIT", index++);
                explicitCopies++;
            }
        }
    }

    private void recoverCinit(JsonObject spec) throws Exception {
        long pointer = requiredLong(spec, "table");
        int maxRecords = requiredInt(spec, "maxRecords");
        long maxWords = requiredLong(spec, "maxWordsPerRecord");
        if (maxRecords <= 0 || maxWords <= 0) {
            fail("invalid cinit safety bounds");
        }
        List<long[]> allowed = parseAllowedRanges(requiredArray(spec, "allowedDestinationRanges"));
        List<long[]> destinations = new ArrayList<>();
        List<CopyRecord> records = new ArrayList<>();
        String evidence = getString(spec, "evidence", "cinit parser evidence");
        Namespace recovered = childNamespace("RECOVERED");
        long terminator = -1;

        for (int recordIndex = 0; recordIndex < maxRecords; recordIndex++) {
            monitor.checkCancelled();
            int rawLength = readWord(pointer, "cinit length");
            pointer++;
            short signedLength = (short) rawLength;
            if (signedLength == 0) {
                terminator = pointer - 1;
                break;
            }

            long words = signedLength < 0 ? -(long) signedLength : signedLength;
            if (words <= 0 || words > maxWords) {
                fail("cinit record " + recordIndex + " violates maxWordsPerRecord: " + words);
            }
            long destination;
            String destinationEncoding;
            if (signedLength > 0) {
                destination = readWord(pointer, "cinit 16-bit destination");
                pointer++;
                destinationEncoding = "16-bit destination";
            }
            else {
                long low = readWord(pointer, "cinit 32-bit destination low word");
                long high = readWord(pointer + 1, "cinit 32-bit destination high word");
                pointer += 2;
                destination = (high << 16) | low;
                destinationEncoding = "32-bit destination";
            }
            long source = pointer;
            pointer = addExact(pointer, words, "cinit source progression");

            if (rangesOverlap(source, words, destination, words)) {
                fail("cinit record " + recordIndex +
                    " has overlapping source/destination; ascending copy direction is unsafe: src=0x" +
                    Long.toHexString(source) + " dst=0x" + Long.toHexString(destination));
            }
            if (!rangeAllowed(destination, words, allowed)) {
                fail("cinit record " + recordIndex + " destination outside allowed RAM: 0x" +
                    Long.toHexString(destination) + "+0x" + Long.toHexString(words));
            }
            for (long[] old : destinations) {
                if (rangesOverlap(destination, words, old[0], old[1])) {
                    fail("cinit record " + recordIndex + " overlaps a prior destination record at 0x" +
                        Long.toHexString(destination));
                }
            }
            destinations.add(new long[] { destination, words });
            String name = String.format(Locale.ROOT, "CINIT_%04d_%08X", recordIndex, destination);
            records.add(new CopyRecord(name, source, destination, words, false,
                evidence + "; " + destinationEncoding));
        }
        if (terminator < 0) {
            fail("cinit table did not terminate within maxRecords=" + maxRecords);
        }

        // Build final initialized RAM as maximal contiguous destination ranges.
        // This preserves every proved byte while avoiding hundreds of one-word
        // memory blocks that would otherwise make normal analysis pathological.
        records.sort(Comparator.comparingLong(r -> r.destinationWord));
        int groupIndex = 0;
        int i = 0;
        while (i < records.size()) {
            int j = i + 1;
            long groupStart = records.get(i).destinationWord;
            long groupEnd = addExact(groupStart, records.get(i).words, "cinit group");
            while (j < records.size() && records.get(j).destinationWord == groupEnd) {
                groupEnd = addExact(groupEnd, records.get(j).words, "cinit group");
                j++;
            }
            long groupWords = groupEnd - groupStart;
            long groupBytesLong = Math.multiplyExact(groupWords, (long) addressUnitBytes);
            if (groupBytesLong > Integer.MAX_VALUE) {
                fail("cinit group is too large: " + groupBytesLong + " bytes");
            }
            byte[] material = new byte[(int) groupBytesLong];
            int byteCursor = 0;
            for (int k = i; k < j; k++) {
                CopyRecord record = records.get(k);
                byte[] recordBytes = readCopySource(record);
                System.arraycopy(recordBytes, 0, material, byteCursor, recordBytes.length);
                byteCursor += recordBytes.length;
            }
            String groupName = String.format(Locale.ROOT, "CINIT_RANGE_%03d_%08X", groupIndex, groupStart);
            String groupEvidence = evidence + "; merged " + (j - i) +
                " adjacent non-overlapping records into one exact initialized range";
            materializeDestination(groupName, groupStart, groupWords, material, false,
                "CINIT", groupEvidence);

            for (int k = i; k < j; k++) {
                CopyRecord record = records.get(k);
                Address destination = wordAddress(record.destinationWord);
                createStableLabel(destination, sanitizeSymbol(record.name), recovered);
                appendComment(destination, COMMENT_PREFIX + " CINIT copy " + record.name +
                    ": source 0x" + Long.toHexString(record.sourceWord) +
                    ", destination 0x" + Long.toHexString(record.destinationWord) +
                    ", words 0x" + Long.toHexString(record.words) +
                    ", ascending direction; " + record.evidence);
                cinitRecords++;
                recoveredWords += record.words;
                if (verboseCopies) {
                    println("FIRMWARE_WORKSPACE_COPY=CINIT:" + k + ":" + record.name +
                        ":src=0x" + Long.toHexString(record.sourceWord) +
                        ":dst=0x" + Long.toHexString(record.destinationWord) +
                        ":words=0x" + Long.toHexString(record.words) + ":x=false");
                }
            }
            groupIndex++;
            i = j;
        }

        createStableLabel(wordAddress(terminator), "CINIT_TERMINATOR", recovered);
        appendComment(wordAddress(terminator), COMMENT_PREFIX + " cinit terminator; " + evidence);
        println("FIRMWARE_WORKSPACE_CINIT_TERMINATOR=0x" + Long.toHexString(terminator));
        println("FIRMWARE_WORKSPACE_CINIT_RANGES=" + groupIndex);
    }

    private List<long[]> parseAllowedRanges(JsonArray array) {
        List<long[]> ranges = new ArrayList<>();
        for (JsonElement e : array) {
            JsonObject r = e.getAsJsonObject();
            long start = requiredLong(r, "start");
            long words = requiredLong(r, "words");
            if (words <= 0) {
                fail("empty cinit allowed range");
            }
            ranges.add(new long[] { start, words });
        }
        return ranges;
    }

    private byte[] readCopySource(CopyRecord record) throws Exception {
        long sourceEnd = addExact(record.sourceWord, record.words, record.name + " source");
        Address source = wordAddress(record.sourceWord);
        Address sourceEndAddress = wordAddress(sourceEnd);
        requireRangeMapped(source, sourceEndAddress, true, "copy source " + record.name);
        long byteLengthLong = Math.multiplyExact(record.words, (long) addressUnitBytes);
        if (byteLengthLong > Integer.MAX_VALUE) {
            fail("copy " + record.name + " is too large for bounded reconstruction: " +
                byteLengthLong + " bytes");
        }
        byte[] bytes = new byte[(int) byteLengthLong];
        int read = memory.getBytes(source, bytes);
        if (read != bytes.length) {
            fail("short read from copy source " + record.name + ": " + read + "/" + bytes.length);
        }
        return bytes;
    }

    private void recoverCopy(CopyRecord record, String method, int ordinal) throws Exception {
        if (record.words <= 0) {
            fail("copy " + record.name + " has non-positive size");
        }
        addExact(record.sourceWord, record.words, record.name + " source");
        addExact(record.destinationWord, record.words, record.name + " destination");
        if (rangesOverlap(record.sourceWord, record.words, record.destinationWord, record.words)) {
            fail("copy " + record.name +
                " has overlapping source/destination; direction cannot be reconstructed safely");
        }
        byte[] bytes = readCopySource(record);
        materializeDestination(record.name, record.destinationWord, record.words, bytes,
            record.executable, method, record.evidence);
        recoveredWords += record.words;

        Namespace recovered = childNamespace("RECOVERED");
        Address destination = wordAddress(record.destinationWord);
        createStableLabel(destination, sanitizeSymbol(record.name), recovered);
        appendComment(destination, COMMENT_PREFIX + " " + method + " copy " + record.name +
            ": source 0x" + Long.toHexString(record.sourceWord) +
            ", destination 0x" + Long.toHexString(record.destinationWord) +
            ", words 0x" + Long.toHexString(record.words) +
            ", ascending direction; " + record.evidence);

        if (verboseCopies || !"CINIT".equals(method)) {
            println("FIRMWARE_WORKSPACE_COPY=" + method + ":" + ordinal + ":" + record.name +
                ":src=0x" + Long.toHexString(record.sourceWord) +
                ":dst=0x" + Long.toHexString(record.destinationWord) +
                ":words=0x" + Long.toHexString(record.words) +
                ":x=" + record.executable);
        }
    }

    private void materializeDestination(String name, long destinationWord, long words, byte[] bytes,
            boolean executable, String method, String evidence) throws Exception {
        long destinationEnd = addExact(destinationWord, words, name + " destination");
        Address destination = wordAddress(destinationWord);
        Address destinationEndAddress = wordAddress(destinationEnd);
        requireRangeMapped(destination, destinationEndAddress, false, "copy destination " + name);
        if (bytes.length != Math.multiplyExact(words, (long) addressUnitBytes)) {
            fail("materialized byte count does not match word count for " + name);
        }

        List<MemoryBlock> destinationBlocks = isolateRange(destination, destinationEndAddress,
            "copy destination " + name);
        boolean allDestinationInitialized = true;
        for (MemoryBlock block : destinationBlocks) {
            allDestinationInitialized &= block.isInitialized();
        }
        boolean destinationAlreadyMatches = false;
        if (allDestinationInitialized) {
            byte[] existingBytes = new byte[bytes.length];
            int existingCount = memory.getBytes(destination, existingBytes);
            destinationAlreadyMatches = existingCount == existingBytes.length &&
                java.util.Arrays.equals(existingBytes, bytes);
        }
        if (!destinationAlreadyMatches &&
                !listing.isUndefined(destination, destinationEndAddress.subtract(1))) {
            fail("copy " + name +
                " would change bytes covered by existing code/data at " + destination);
        }

        for (MemoryBlock block : destinationBlocks) {
            if (block.isMapped()) {
                fail("mapped destination block for copy " + name + ": " + describeBlock(block));
            }
            if (block.isInitialized() &&
                    (!isWorkspaceOwnedCopy(block) || !destinationAlreadyMatches)) {
                fail("copy " + name + " overlaps incompatible initialized data: " +
                    describeBlock(block));
            }
            if (!block.isInitialized()) {
                block = memory.convertToInitialized(block, (byte) 0);
            }
            block.setPermissions(true, true, executable);
            block.setVolatile(false);
            block.setSourceName(WORKSPACE_SOURCE_PREFIX + workspaceName + ":COPY:" +
                method + ":" + name);
            String old = block.getComment();
            String provenance = COMMENT_PREFIX + " recovered by " + method + " " + name +
                " at RAM word 0x" + Long.toHexString(destinationWord) +
                ", 0x" + Long.toHexString(words) + " words; " + evidence;
            if (old == null || !old.contains(provenance)) {
                block.setComment(old == null || old.isBlank() ? provenance : old + "\n" + provenance);
            }
        }
        if (!destinationAlreadyMatches) {
            memory.setBytes(destination, bytes);
        }
    }

    private void seedKnownAnalysis() throws Exception {
        if (!workspace.has("analysisSeeds")) {
            return;
        }
        JsonObject seeds = workspace.getAsJsonObject("analysisSeeds");
        if (seeds.has("disassembly")) {
            for (JsonElement e : seeds.getAsJsonArray("disassembly")) {
                Address address = wordAddress(e.getAsLong());
                MemoryBlock block = memory.getBlock(address);
                if (block == null || !block.isInitialized() || !block.isExecute()) {
                    println("FIRMWARE_WORKSPACE_SEED_SKIPPED=" + address +
                        ":not initialized executable memory");
                    continue;
                }
                if (listing.getInstructionAt(address) == null && disassemble(address)) {
                    disassemblySeeds++;
                }
            }
        }
        if (seeds.has("functions")) {
            for (JsonElement e : seeds.getAsJsonArray("functions")) {
                Address address = wordAddress(e.getAsLong());
                MemoryBlock block = memory.getBlock(address);
                if (block == null || !block.isInitialized() || !block.isExecute()) {
                    println("FIRMWARE_WORKSPACE_FUNCTION_SEED_SKIPPED=" + address +
                        ":not initialized executable memory");
                    continue;
                }
                if (listing.getInstructionAt(address) == null) {
                    disassemble(address);
                }
                Function function = listing.getFunctionAt(address);
                if (function == null && listing.getInstructionAt(address) != null) {
                    function = createFunction(address, null);
                    if (function != null) {
                        functionSeeds++;
                    }
                }
            }
        }
    }

    private int readWord(long wordAddress, String what) throws MemoryAccessException {
        Address address = wordAddress(wordAddress);
        MemoryBlock block = memory.getBlock(address);
        if (block == null || !block.isInitialized()) {
            fail(what + " is not in initialized memory at word 0x" + Long.toHexString(wordAddress));
        }
        return memory.getShort(address) & 0xffff;
    }

    private void requireRangeMapped(Address start, Address endExclusive, boolean requireInitialized,
            String purpose) {
        Address cursor = start;
        while (cursor.compareTo(endExclusive) < 0) {
            MemoryBlock block = memory.getBlock(cursor);
            if (block == null) {
                fail(purpose + " is unmapped at " + cursor);
            }
            if (requireInitialized && !block.isInitialized()) {
                fail(purpose + " is uninitialized at " + cursor + " in " + block.getName());
            }
            Address next = block.getEnd().add(1);
            if (next.compareTo(cursor) <= 0) {
                fail("non-progressing memory block while checking " + purpose);
            }
            cursor = minAddress(next, endExclusive);
        }
    }

    private List<MemoryBlock> isolateRange(Address start, Address endExclusive, String purpose)
            throws Exception {
        if (start.compareTo(endExclusive) >= 0) {
            fail("empty or reversed range for " + purpose);
        }
        requireRangeMapped(start, endExclusive, false, purpose);

        MemoryBlock atStart = memory.getBlock(start);
        if (atStart != null && atStart.getStart().compareTo(start) < 0) {
            memory.split(atStart, start);
        }
        MemoryBlock atEnd = memory.getBlock(endExclusive);
        if (atEnd != null && atEnd.getStart().compareTo(endExclusive) < 0 && atEnd.contains(endExclusive)) {
            memory.split(atEnd, endExclusive);
        }

        List<MemoryBlock> result = new ArrayList<>();
        Address cursor = start;
        while (cursor.compareTo(endExclusive) < 0) {
            MemoryBlock block = memory.getBlock(cursor);
            if (block == null || !block.getStart().equals(cursor)) {
                fail("failed to isolate " + purpose + " at " + cursor);
            }
            Address next = block.getEnd().add(1);
            if (next.compareTo(endExclusive) > 0) {
                fail("isolated block extends beyond " + purpose + ": " + describeBlock(block));
            }
            result.add(block);
            cursor = next;
        }
        return result;
    }

    private Address nextBlockStart(Address cursor, Address endExclusive) {
        Address next = endExclusive;
        for (MemoryBlock block : memory.getBlocks()) {
            Address start = block.getStart();
            if (start.compareTo(cursor) > 0 && start.compareTo(next) < 0) {
                next = start;
            }
        }
        return next;
    }

    private String sha256Memory(Address start, long byteLength) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[COPY_CHUNK_BYTES];
        Address cursor = start;
        long remaining = byteLength;
        while (remaining > 0) {
            monitor.checkCancelled();
            int length = (int) Math.min(buffer.length, remaining);
            int count = memory.getBytes(cursor, buffer, 0, length);
            if (count != length) {
                fail("short read while hashing firmware at " + cursor + ": " + count + "/" + length);
            }
            digest.update(buffer, 0, length);
            cursor = cursor.add(length);
            remaining -= length;
        }
        StringBuilder result = new StringBuilder(64);
        for (byte b : digest.digest()) {
            result.append(String.format(Locale.ROOT, "%02x", b & 0xff));
        }
        return result.toString();
    }

    private void createStableLabel(Address address, String name, Namespace namespace)
            throws InvalidInputException {
        createStableLabel(address, name, namespace, false);
    }

    private void createStableLabel(Address address, String name, Namespace namespace,
            boolean preferPrimary) throws InvalidInputException {
        List<Symbol> named = symbols.getSymbols(name, namespace);
        for (Symbol symbol : named) {
            if (!symbol.getAddress().equals(address)) {
                fail("symbol collision for " + namespace.getName(true) + "::" + name +
                    ": existing=" + symbol.getAddress() + " requested=" + address);
            }
            labelsReused++;
            promoteProfileSymbol(symbol, preferPrimary);
            return;
        }
        Symbol created = symbols.createLabel(address, name, namespace, SourceType.ANALYSIS);
        labelsCreated++;
        promoteProfileSymbol(created, preferPrimary);
    }

    private void promoteProfileSymbol(Symbol profileSymbol, boolean preferPrimary) {
        if (!preferPrimary || profileSymbol.isPrimary()) {
            return;
        }
        Symbol primary = symbols.getPrimarySymbol(profileSymbol.getAddress());
        if (primary != null && primary.getName(true).contains("F2837xS_COMPAT::PERIPHERALS")) {
            // Preserve the first deterministic profile identity as primary;
            // later exact-span aliases remain visible without oscillating it.
            return;
        }
        if (primary != null && !primary.isDynamic() && primary.getSource() != SourceType.ANALYSIS) {
            return;
        }
        if (profileSymbol.setPrimary()) {
            labelsPromoted++;
        }
    }

    private void appendComment(Address address, String addition) {
        String old = listing.getComment(CommentType.PLATE, address);
        if (old != null && old.contains(addition)) {
            return;
        }
        listing.setComment(address, CommentType.PLATE,
            old == null || old.isBlank() ? addition : old + "\n" + addition);
    }

    private void appendBlockComment(MemoryBlock block, String addition) {
        String old = block.getComment();
        if (old != null && old.contains(addition)) {
            return;
        }
        block.setComment(old == null || old.isBlank() ? addition : old + "\n" + addition);
    }

    private void safeRename(MemoryBlock block, String desired) throws Exception {
        if (block.getName().equals(desired)) {
            return;
        }
        MemoryBlock conflict = memory.getBlock(desired);
        if (conflict != null && conflict != block) {
            desired = uniqueBlockName(desired);
        }
        block.setName(desired);
    }

    private String uniqueBlockName(String base) {
        String candidate = sanitizeSymbol(base);
        int i = 1;
        while (memory.getBlock(candidate) != null) {
            candidate = sanitizeSymbol(base) + "_" + i++;
        }
        return candidate;
    }

    private boolean isProfileOwned(MemoryBlock block) {
        String source = block.getSourceName();
        return source != null && source.startsWith(SOURCE_PREFIX);
    }

    private boolean isWorkspaceOwned(MemoryBlock block) {
        String source = block.getSourceName();
        return source != null && source.startsWith(WORKSPACE_SOURCE_PREFIX);
    }

    private boolean isWorkspaceOwnedCopy(MemoryBlock block) {
        String source = block.getSourceName();
        return source != null && source.startsWith(WORKSPACE_SOURCE_PREFIX + workspaceName + ":COPY:");
    }

    private boolean isRomEvidenceOwned(MemoryBlock block) {
        String source = block.getSourceName();
        return source != null && source.startsWith(ROM_SOURCE_PREFIX);
    }

    private String describeBlock(MemoryBlock block) {
        return block.getName() + "[" + block.getStart() + ".." + block.getEnd() +
            ", initialized=" + block.isInitialized() + ", source=" + block.getSourceName() + "]";
    }

    private Address wordAddress(long wordOffset) {
        if (wordOffset < 0) {
            fail("negative word address: " + wordOffset);
        }
        long byteOffset;
        try {
            byteOffset = Math.multiplyExact(wordOffset, (long) addressUnitBytes);
        }
        catch (ArithmeticException ex) {
            fail("word address overflow: 0x" + Long.toHexString(wordOffset));
            return null;
        }
        try {
            return space.getAddress(byteOffset);
        }
        catch (Exception ex) {
            fail("word address is outside program address space: 0x" + Long.toHexString(wordOffset));
            return null;
        }
    }

    private long unsignedSpaceWordLimit() {
        long max = space.getMaxAddress().getOffset();
        return max / addressUnitBytes + 1;
    }

    private static boolean rangesOverlap(long aStart, long aWords, long bStart, long bWords) {
        long aEnd = Math.addExact(aStart, aWords);
        long bEnd = Math.addExact(bStart, bWords);
        return aStart < bEnd && bStart < aEnd;
    }

    private static boolean rangeAllowed(long start, long words, List<long[]> allowed) {
        long end = Math.addExact(start, words);
        for (long[] range : allowed) {
            long allowedEnd = Math.addExact(range[0], range[1]);
            if (start >= range[0] && end <= allowedEnd) {
                return true;
            }
        }
        return false;
    }

    private static Address minAddress(Address a, Address b) {
        return a.compareTo(b) <= 0 ? a : b;
    }

    private static long addExact(long a, long b, String context) {
        try {
            return Math.addExact(a, b);
        }
        catch (ArithmeticException ex) {
            throw new IllegalStateException("DEVICE_PROFILE_ERROR: address overflow in " + context, ex);
        }
    }

    private static String sanitizeSymbol(String value) {
        String sanitized = value.replaceAll("[^A-Za-z0-9_$]", "_");
        if (sanitized.isBlank()) {
            sanitized = "unnamed";
        }
        if (Character.isDigit(sanitized.charAt(0))) {
            sanitized = "_" + sanitized;
        }
        return sanitized;
    }

    private void recordProgramOptions(File file, File workspaceFile, boolean strictFirmware,
            boolean recoverCopies) {
        Options options = currentProgram.getOptions("TMS320C28 Device Profile");
        options.setString("Profile Name", profileName);
        options.setInt("Profile Version", requiredInt(profile, "version"));
        options.setString("Profile File", file.getAbsolutePath());
        if (workspace != null) {
            Options workspaceOptions = currentProgram.getOptions("TMS320C28 Firmware Workspace");
            workspaceOptions.setString("Workspace Name", workspaceName);
            workspaceOptions.setInt("Workspace Version", requiredInt(workspace, "version"));
            workspaceOptions.setString("Workspace File", workspaceFile.getAbsolutePath());
            workspaceOptions.setString("Device Profile", profileName);
            workspaceOptions.setBoolean("Strict Firmware Identity", strictFirmware);
            workspaceOptions.setBoolean("Copy Recovery Enabled", recoverCopies);
            workspaceOptions.setInt("Explicit Copies", explicitCopies);
            workspaceOptions.setInt("Cinit Records", cinitRecords);
            workspaceOptions.setLong("Recovered Words", recoveredWords);
        }
    }

    private void printMetrics() {
        println("DEVICE_PROFILE_BLOCKS_CREATED=" + createdBlocks);
        println("DEVICE_PROFILE_BLOCKS_REUSED=" + reusedBlocks);
        println("DEVICE_PROFILE_LABELS_CREATED=" + labelsCreated);
        println("DEVICE_PROFILE_LABELS_REUSED=" + labelsReused);
        println("DEVICE_PROFILE_LABELS_PROMOTED=" + labelsPromoted);
        println("DEVICE_PROFILE_REGISTER_DATA_CREATED=" + dataCreated);
        println("DEVICE_PROFILE_REGISTER_DATA_SKIPPED=" + dataSkipped);
        println("DEVICE_PROFILE_PASS=" + profileName);
        if (workspace != null) {
            println("FIRMWARE_WORKSPACE_EXPLICIT_COPIES=" + explicitCopies);
            println("FIRMWARE_WORKSPACE_CINIT_RECORDS=" + cinitRecords);
            println("FIRMWARE_WORKSPACE_RECOVERED_WORDS=" + recoveredWords);
            println("FIRMWARE_WORKSPACE_DISASSEMBLY_SEEDS=" + disassemblySeeds);
            println("FIRMWARE_WORKSPACE_FUNCTION_SEEDS=" + functionSeeds);
            println("FIRMWARE_WORKSPACE_PASS=" + workspaceName);
        }
    }

    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> result = new LinkedHashMap<>();
        for (String arg : args) {
            int equals = arg.indexOf('=');
            if (equals <= 0) {
                throw new IllegalArgumentException("DEVICE_PROFILE_ERROR: expected key=value script argument, got: " + arg);
            }
            result.put(arg.substring(0, equals), arg.substring(equals + 1));
        }
        return result;
    }

    private static boolean parseBoolean(Map<String, String> args, String name, boolean defaultValue) {
        String value = args.get(name);
        if (value == null) {
            return defaultValue;
        }
        if (value.equalsIgnoreCase("true") || value.equals("1") || value.equalsIgnoreCase("yes")) {
            return true;
        }
        if (value.equalsIgnoreCase("false") || value.equals("0") || value.equalsIgnoreCase("no")) {
            return false;
        }
        throw new IllegalArgumentException("DEVICE_PROFILE_ERROR: invalid boolean " + name + "=" + value);
    }

    private static JsonObject requiredObject(JsonObject object, String name) {
        JsonElement e = object.get(name);
        if (e == null || !e.isJsonObject()) {
            throw new IllegalStateException("DEVICE_PROFILE_ERROR: missing object " + name);
        }
        return e.getAsJsonObject();
    }

    private static JsonArray requiredArray(JsonObject object, String name) {
        JsonElement e = object.get(name);
        if (e == null || !e.isJsonArray()) {
            throw new IllegalStateException("DEVICE_PROFILE_ERROR: missing array " + name);
        }
        return e.getAsJsonArray();
    }

    private static String requiredString(JsonObject object, String name) {
        JsonElement e = object.get(name);
        if (e == null || e.isJsonNull()) {
            throw new IllegalStateException("DEVICE_PROFILE_ERROR: missing string " + name);
        }
        return e.getAsString();
    }

    private static long requiredLong(JsonObject object, String name) {
        JsonElement e = object.get(name);
        if (e == null || e.isJsonNull()) {
            throw new IllegalStateException("DEVICE_PROFILE_ERROR: missing integer " + name);
        }
        return e.getAsLong();
    }

    private static int requiredInt(JsonObject object, String name) {
        long value = requiredLong(object, name);
        if (value < Integer.MIN_VALUE || value > Integer.MAX_VALUE) {
            throw new IllegalStateException("DEVICE_PROFILE_ERROR: integer out of range " + name + "=" + value);
        }
        return (int) value;
    }

    private static String getString(JsonObject object, String name, String defaultValue) {
        JsonElement e = object.get(name);
        return e == null || e.isJsonNull() ? defaultValue : e.getAsString();
    }

    private static boolean getBoolean(JsonObject object, String name, boolean defaultValue) {
        JsonElement e = object.get(name);
        return e == null || e.isJsonNull() ? defaultValue : e.getAsBoolean();
    }

    private static void fail(String message) {
        throw new IllegalStateException("DEVICE_PROFILE_ERROR: " + message);
    }
}
