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
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
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
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public class TMS320C28DeviceProfile extends GhidraScript {
    private static final String SCHEMA = "tms320c28-device-profile";
    private static final String WORKSPACE_SCHEMA = "tms320c28-firmware-workspace";
    private static final String SOURCE_PREFIX = "TMS320C28_DEVICE_PROFILE:";
    private static final String WORKSPACE_SOURCE_PREFIX = "TMS320C28_FIRMWARE_WORKSPACE:";
    private static final String ROM_SOURCE_PREFIX = "TMS320C28_ROM_EVIDENCE:";
    private static final String COMMENT_PREFIX = "[TMS320C28 device profile]";
    private static final CategoryPath PROFILE_TYPES =
        new CategoryPath("/TMS320C28/DeviceProfile");
    private static final int COPY_CHUNK_BYTES = 64 * 1024;
    private static final String SOURCE_DISPOSITION_INERT_STORAGE = "inert-storage";
    private static final String INERT_SOURCE_COMPONENT = ":COPY_SOURCE:EXPLICIT:";
    private static final String INERT_SOURCE_SUFFIX = ":INERT_STORAGE";
    private static final int CAN_ACCESS_VIEW_STORAGE_BITS = 16;
    private static final int CAN_ACCESS_VIEW_LOGICAL_BITS = 8;
    private static final Set<Integer> CAN_ACCESS_VIEW_LOGICAL_OFFSETS = Set.of(16, 24);
    private static final Pattern CAN_ACCESS_VIEW_NAMESPACE = Pattern.compile("CAN[AB]");
    private static final Pattern CAN_ACCESS_VIEW_PARENT = Pattern.compile("IF[123][A-Z0-9_]+");

    private JsonObject profile;
    private JsonObject workspace;
    private Memory memory;
    private Listing listing;
    private SymbolTable symbols;
    private FunctionManager functions;
    private ReferenceManager references;
    private BookmarkManager bookmarks;
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
    private int accessViewDataCreated;
    private int accessViewDataSkipped;
    private int codeVectorDataCreated;
    private int codeVectorDataSkipped;
    private int explicitCopies;
    private int cinitRecords;
    private long recoveredWords;
    private int disassemblySeeds;
    private int functionSeeds;
    private int inertSourceCleanups;
    private int inertSourceCleanupSkips;
    private long inertSourceInstructionsCleared;
    private long inertSourceReferencesCleared;
    private boolean verboseCopies;

    private static final class CopyRecord {
        final String name;
        final long sourceWord;
        final long destinationWord;
        final long words;
        final boolean executable;
        final String evidence;
        final String sourceDisposition;
        final String sourceDispositionError;

        CopyRecord(String name, long sourceWord, long destinationWord, long words,
                boolean executable, String evidence) {
            this(name, sourceWord, destinationWord, words, executable, evidence, null, null);
        }

        CopyRecord(String name, long sourceWord, long destinationWord, long words,
                boolean executable, String evidence, String sourceDisposition,
                String sourceDispositionError) {
            this.name = name;
            this.sourceWord = sourceWord;
            this.destinationWord = destinationWord;
            this.words = words;
            this.executable = executable;
            this.evidence = evidence;
            this.sourceDisposition = sourceDisposition;
            this.sourceDispositionError = sourceDispositionError;
        }

        boolean requestsInertStorage() {
            return SOURCE_DISPOSITION_INERT_STORAGE.equals(sourceDisposition);
        }
    }

    private static final class SourceDispositionSpec {
        final String value;
        final String error;

        SourceDispositionSpec(String value, String error) {
            this.value = value;
            this.error = error;
        }
    }

    private static final class CleanupProof {
        final Address start;
        final Address endExclusive;
        final Address endInclusive;
        final AddressSet range;
        final MemoryBlock parent;
        final byte[] bytes;
        final boolean alreadyMarked;

        CleanupProof(Address start, Address endExclusive, Address endInclusive,
                AddressSet range, MemoryBlock parent, byte[] bytes, boolean alreadyMarked) {
            this.start = start;
            this.endExclusive = endExclusive;
            this.endInclusive = endInclusive;
            this.range = range;
            this.parent = parent;
            this.bytes = bytes;
            this.alreadyMarked = alreadyMarked;
        }
    }

    private static final class CleanupRejection extends Exception {
        final String reason;

        CleanupRejection(String reason, String detail) {
            super(detail);
            this.reason = reason;
        }
    }

    private static final class SymbolSnapshot {
        final Address address;
        final String name;
        final Namespace namespace;
        final SourceType source;
        final boolean primary;
        final boolean pinned;

        SymbolSnapshot(Symbol symbol) {
            address = symbol.getAddress();
            name = symbol.getName();
            namespace = symbol.getParentNamespace();
            source = symbol.getSource();
            primary = symbol.isPrimary();
            pinned = symbol.isPinned();
        }
    }

    private static final class EdgeSnapshot {
        final Address start;
        final Address end;
        final byte[] bytes;
        final boolean read;
        final boolean write;
        final boolean execute;
        final boolean volatileBlock;

        EdgeSnapshot(Address start, Address end, byte[] bytes, MemoryBlock block) {
            this.start = start;
            this.end = end;
            this.bytes = bytes;
            read = block.isRead();
            write = block.isWrite();
            execute = block.isExecute();
            volatileBlock = block.isVolatile();
        }
    }

    private static final class ProfileSpan {
        final long start;
        final long end;
        final String name;

        ProfileSpan(long start, long end, String name) {
            this.start = start;
            this.end = end;
            this.name = name;
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
        functions = currentProgram.getFunctionManager();
        references = currentProgram.getReferenceManager();
        bookmarks = currentProgram.getBookmarkManager();
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

        validateAccessViews();

        println("DEVICE_PROFILE_BEGIN=" + profileName);
        println("DEVICE_PROFILE_FILE=" + file);
        println("DEVICE_PROFILE_ADDRESS_UNIT_BYTES=" + addressUnitBytes);

        applyMemoryBlocks();
        createNamespaces();
        createMemoryLabels();
        createBaseLabels();
        createRegisterLabelsAndTypes(applyRegisterTypes);
        createAccessViewLabelsAndTypes(applyRegisterTypes);
        createCodeVectorLabelsAndTypes(applyRegisterTypes);

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
        if (profile.has("accessViews") && !profile.get("accessViews").isJsonArray()) {
            fail("accessViews must be an array");
        }
    }

    private void validateAccessViews() {
        if (!profile.has("accessViews")) {
            return;
        }

        Map<String, JsonObject> registerByName = new LinkedHashMap<>();
        List<ProfileSpan> registerSpans = new ArrayList<>();
        for (JsonElement element : requiredArray(profile, "registers")) {
            JsonObject register = element.getAsJsonObject();
            String namespace = requiredString(register, "namespace");
            String name = requiredString(register, "name");
            String key = qualifiedKey(namespace, name);
            if (registerByName.putIfAbsent(key, register) != null) {
                fail("duplicate register symbol while validating access views: " +
                    namespace + "::" + name);
            }
            int widthBits = requiredInt(register, "widthBits");
            if (widthBits != 16 && widthBits != 32) {
                fail("unsupported register width while validating access views: " +
                    namespace + "::" + name);
            }
            long start = requiredLong(register, "address");
            long end = checkedProfileEnd(start, widthBits / 16,
                "register " + namespace + "::" + name);
            registerSpans.add(new ProfileSpan(start, end, namespace + "::" + name));
        }

        Set<String> viewNames = new HashSet<>();
        Set<String> logicalLanes = new HashSet<>();
        for (JsonElement element : requiredArray(profile, "accessViews")) {
            JsonObject view = element.getAsJsonObject();
            String namespace = requiredString(view, "namespace");
            String name = requiredString(view, "name");
            String key = qualifiedKey(namespace, name);
            if (!viewNames.add(key)) {
                fail("duplicate access-view symbol: " + namespace + "::" + name);
            }

            String parentName = requiredString(view, "parentRegister");
            JsonObject parent = registerByName.get(qualifiedKey(namespace, parentName));
            if (parent == null) {
                fail("missing access-view parent: " + namespace + "::" + parentName);
            }
            if (!isCanAccessViewParent(parent)) {
                fail("unsupported access-view parent: " + namespace + "::" + parentName);
            }
            if (!requiredString(parent, "baseSymbol").equals(requiredString(view, "baseSymbol"))) {
                fail("access-view base mismatch: " + namespace + "::" + name);
            }

            int parentWidth = requiredInt(parent, "widthBits");
            int logicalOffset = requiredInt(view, "logicalBitOffset");
            int logicalWidth = requiredInt(view, "logicalWidthBits");
            if (logicalOffset < 0 || logicalWidth <= 0 ||
                    (long) logicalOffset + logicalWidth > parentWidth) {
                fail("access-view logical range outside parent: " + namespace + "::" + name);
            }
            if (logicalWidth != CAN_ACCESS_VIEW_LOGICAL_BITS) {
                fail("unsupported access-view logical width: " + namespace + "::" + name);
            }

            int storageWidth = requiredInt(view, "physicalStorageWidthBits");
            if (storageWidth != CAN_ACCESS_VIEW_STORAGE_BITS) {
                fail("unsupported access-view storage width: " + namespace + "::" + name);
            }
            int storageWords = storageWidth / 16;
            long address = requiredLong(view, "address");

            JsonObject parentBlock = containingProfileBlock(requiredLong(parent, "address"),
                parentWidth / 16);
            JsonObject viewBlock = containingProfileBlock(address, storageWords);
            if (parentBlock == null || viewBlock == null ||
                    requiredLong(parentBlock, "start") != requiredLong(viewBlock, "start") ||
                    !requiredString(parentBlock, "name").equals(
                        requiredString(viewBlock, "name")) ||
                    !"peripheral".equals(requiredString(parentBlock, "kind"))) {
                fail("access view is outside parent peripheral block: " +
                    namespace + "::" + name);
            }

            String laneKey = qualifiedKey(namespace, parentName) + ":" +
                logicalOffset + ":" + logicalWidth;
            if (!logicalLanes.add(laneKey)) {
                fail("duplicate physical access view for logical lane: " +
                    namespace + "::" + parentName + " bits " + logicalOffset + "-" +
                    (logicalOffset + logicalWidth - 1));
            }

            if (!CAN_ACCESS_VIEW_LOGICAL_OFFSETS.contains(logicalOffset)) {
                fail("unsupported CAN access-view lane: " + namespace + "::" + name);
            }
            String expectedName = parentName + "_BYTE" + (logicalOffset / 8);
            if (!name.equals(expectedName)) {
                fail("CAN access-view name mismatch: " + namespace + "::" + name +
                    " expected=" + expectedName);
            }
            long expectedAddress = addExact(requiredLong(parent, "address"),
                logicalOffset / 8L, "CAN access-view address");
            if (address != expectedAddress) {
                fail("CAN access-view address mismatch: " + namespace + "::" + name +
                    " address=0x" + Long.toHexString(address) + " expected=0x" +
                    Long.toHexString(expectedAddress));
            }

            long end = checkedProfileEnd(address, storageWords,
                "access view " + namespace + "::" + name);
            for (ProfileSpan registerSpan : registerSpans) {
                if (!profileSpansOverlap(address, end, registerSpan.start, registerSpan.end)) {
                    continue;
                }
                if (registerSpan.start != address || registerSpan.end != end) {
                    fail("access view overlaps incompatible register span: " +
                        namespace + "::" + name + " and " + registerSpan.name);
                }
            }
            JsonArray actualFields = view.has("fieldOverlaps")
                ? view.getAsJsonArray("fieldOverlaps") : new JsonArray();
            JsonArray expectedFields = expectedAccessViewFields(parent, logicalOffset);
            if (!actualFields.equals(expectedFields)) {
                fail("access-view field mapping mismatch: " + namespace + "::" + name);
            }
        }

    }

    private boolean isCanAccessViewParent(JsonObject register) {
        return requiredInt(register, "widthBits") == 32 &&
            CAN_ACCESS_VIEW_NAMESPACE.matcher(requiredString(register, "namespace")).matches() &&
            CAN_ACCESS_VIEW_PARENT.matcher(requiredString(register, "name")).matches();
    }

    private JsonArray expectedAccessViewFields(JsonObject parent, int logicalOffset) {
        int logicalEnd = logicalOffset + CAN_ACCESS_VIEW_LOGICAL_BITS;
        JsonArray result = new JsonArray();
        JsonArray fields = parent.has("fields") ? parent.getAsJsonArray("fields") : new JsonArray();
        for (JsonElement element : fields) {
            JsonObject field = element.getAsJsonObject();
            int fieldStart = requiredInt(field, "shift");
            int fieldSize = requiredInt(field, "size");
            int fieldEnd = fieldStart + fieldSize;
            int overlapStart = Math.max(fieldStart, logicalOffset);
            int overlapEnd = Math.min(fieldEnd, logicalEnd);
            if (overlapStart >= overlapEnd) {
                continue;
            }
            JsonObject overlap = new JsonObject();
            overlap.addProperty("name", requiredString(field, "name"));
            overlap.addProperty("description", getString(field, "description", ""));
            overlap.addProperty("parentShift", fieldStart);
            overlap.addProperty("parentSize", fieldSize);
            overlap.addProperty("overlapLogicalBitOffset", overlapStart);
            overlap.addProperty("overlapWidthBits", overlapEnd - overlapStart);
            overlap.addProperty("crossesByteBoundary",
                fieldStart < logicalOffset || fieldEnd > logicalEnd);
            result.add(overlap);
        }
        return result;
    }

    private JsonObject containingProfileBlock(long start, long words) {
        long end = checkedProfileEnd(start, words, "profile range");
        for (JsonElement element : requiredArray(profile, "blocks")) {
            JsonObject block = element.getAsJsonObject();
            long blockStart = requiredLong(block, "start");
            long blockEnd = checkedProfileEnd(blockStart, requiredLong(block, "words"),
                "block " + requiredString(block, "name"));
            if (start >= blockStart && end <= blockEnd) {
                return block;
            }
        }
        return null;
    }

    private long checkedProfileEnd(long start, long words, String context) {
        if (start < 0 || words <= 0) {
            fail("invalid range for " + context + ": start=0x" +
                Long.toHexString(start) + " words=" + words);
        }
        return addExact(start, words, context);
    }

    private static boolean profileSpansOverlap(long aStart, long aEnd,
            long bStart, long bEnd) {
        return aStart < bEnd && bStart < aEnd;
    }

    private static String qualifiedKey(String namespace, String name) {
        return namespace + "\u0000" + name;
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
            // Source retirement is monotonic.  Validate the bytes as part of
            // the firmware image, but do not restore execution or erase the
            // workspace-owned exact source marker on a later application.
            if (isWorkspaceOwnedInertCopySource(block)) {
                index++;
                continue;
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

    private void createAccessViewLabelsAndTypes(boolean applyTypes) throws Exception {
        if (!profile.has("accessViews")) {
            return;
        }
        Namespace peripheralRoot = childNamespace("PERIPHERALS");
        Set<Long> typedAddresses = new HashSet<>();
        for (JsonElement element : requiredArray(profile, "accessViews")) {
            monitor.checkCancelled();
            JsonObject view = element.getAsJsonObject();
            String module = sanitizeSymbol(requiredString(view, "namespace"));
            Namespace namespace = symbols.getOrCreateNameSpace(
                peripheralRoot, module, SourceType.ANALYSIS);
            Address address = wordAddress(requiredLong(view, "address"));
            if (memory.getBlock(address) == null) {
                fail("access view is outside mapped memory: " + module + "::" +
                    requiredString(view, "name") + " at " + address);
            }
            String name = sanitizeSymbol(requiredString(view, "name"));
            createStableLabel(address, name, namespace, true);
            if (applyTypes && typedAddresses.add(address.getOffset())) {
                applyAccessViewType(address);
            }
            appendComment(address, formatAccessViewComment(module, name, view));
        }
    }

    private void applyAccessViewType(Address address) {
        DataType type = UnsignedShortDataType.dataType;
        Address end = address.add(type.getLength() - 1L);
        MemoryBlock block = memory.getBlock(address);
        if (block == null || memory.getBlock(end) != block) {
            accessViewDataSkipped++;
            return;
        }
        Data existing = listing.getDefinedDataAt(address);
        if (existing != null) {
            accessViewDataSkipped++;
            return;
        }
        if (!listing.isUndefined(address, end)) {
            accessViewDataSkipped++;
            return;
        }
        try {
            Data created = listing.createData(address, type);
            if (created != null && created.getLength() == type.getLength()) {
                accessViewDataCreated++;
            }
            else {
                accessViewDataSkipped++;
            }
        }
        catch (Exception ex) {
            accessViewDataSkipped++;
        }
    }

    private String formatAccessViewComment(String module, String name, JsonObject view) {
        int logicalOffset = requiredInt(view, "logicalBitOffset");
        int logicalWidth = requiredInt(view, "logicalWidthBits");
        long wordAddress = requiredLong(view, "address");
        int storageBits = requiredInt(view, "physicalStorageWidthBits");
        String parent = requiredString(view, "parentRegister");

        StringBuilder sb = new StringBuilder();
        String qualifiedModule = "F2837xS_COMPAT::PERIPHERALS::" + module;
        sb.append(COMMENT_PREFIX).append(' ').append(qualifiedModule)
            .append("::").append(name);
        String description = getString(view, "description", "");
        if (!description.isBlank()) {
            sb.append(" — ").append(description);
        }
        sb.append("; parent logical register ").append(qualifiedModule)
            .append("::").append(parent)
            .append("; logical bits ").append(logicalOffset).append('-')
            .append(logicalOffset + logicalWidth - 1)
            .append("; physical C28x word address 0x")
            .append(Long.toHexString(wordAddress).toUpperCase(Locale.ROOT))
            .append("; physical storage ").append(storageBits)
            .append(" bits (2 Ghidra bytes, one C28x word)");

        JsonArray overlaps = view.has("fieldOverlaps")
            ? view.getAsJsonArray("fieldOverlaps") : new JsonArray();
        for (JsonElement element : overlaps) {
            JsonObject overlap = element.getAsJsonObject();
            int parentShift = requiredInt(overlap, "parentShift");
            int parentSize = requiredInt(overlap, "parentSize");
            int overlapStart = requiredInt(overlap, "overlapLogicalBitOffset");
            int overlapWidth = requiredInt(overlap, "overlapWidthBits");
            sb.append("\n  ").append(requiredString(overlap, "name"))
                .append(" parent bits ").append(parentShift);
            if (parentSize > 1) {
                sb.append('-').append(parentShift + parentSize - 1);
            }
            sb.append("; represented bits ").append(overlapStart);
            if (overlapWidth > 1) {
                sb.append('-').append(overlapStart + overlapWidth - 1);
            }
            if (getBoolean(overlap, "crossesByteBoundary", false)) {
                sb.append("; field crosses this byte boundary");
            }
            String fieldDescription = getString(overlap, "description", "");
            if (!fieldDescription.isBlank()) {
                sb.append(": ").append(fieldDescription);
            }
        }
        return sb.toString();
    }

    private void createCodeVectorLabelsAndTypes(boolean applyTypes) throws Exception {
        if (!profile.has("codeVectors")) {
            return;
        }
        Namespace vectorRoot = childNamespace("VECTORS");
        DataType functionPointer = applyTypes ? codeVectorDataType() : null;
        Set<Long> occupied = new HashSet<>();
        for (JsonElement e : profile.getAsJsonArray("codeVectors")) {
            monitor.checkCancelled();
            JsonObject vector = e.getAsJsonObject();
            int widthBits = requiredInt(vector, "widthBits");
            if (widthBits != 32) {
                fail("code-vector slot must be 32 bits: " + requiredString(vector, "name"));
            }
            long word = requiredLong(vector, "address");
            if ((word & 1) != 0 || !occupied.add(word)) {
                fail("unaligned or duplicate code-vector slot at word 0x" +
                    Long.toHexString(word));
            }
            Address address = wordAddress(word);
            Address end = address.add(3);
            MemoryBlock block = memory.getBlock(address);
            if (block == null || memory.getBlock(end) != block) {
                fail("code-vector slot is outside one mapped block: " + address);
            }

            String module = sanitizeSymbol(requiredString(vector, "namespace"));
            Namespace ns = symbols.getOrCreateNameSpace(vectorRoot, module, SourceType.ANALYSIS);
            String name = sanitizeSymbol(requiredString(vector, "name"));
            createStableLabel(address, name, ns, true);
            appendComment(address, formatCodeVectorComment(module, name, vector));
            if (applyTypes) {
                applyCodeVectorType(address, functionPointer);
            }
        }
    }

    private DataType codeVectorDataType() {
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        FunctionDefinitionDataType signature = new FunctionDefinitionDataType(
            PROFILE_TYPES, "C28xInterruptHandler", dtm);
        signature.setReturnType(new VoidDataType(dtm));
        signature.setArguments();
        DataType resolved = dtm.addDataType(signature, DataTypeConflictHandler.REPLACE_HANDLER);
        return new PointerDataType(resolved, 4, dtm);
    }

    private void applyCodeVectorType(Address address, DataType type) {
        Data existing = listing.getDefinedDataAt(address);
        if (existing != null) {
            if (existing.getLength() == type.getLength() &&
                    existing.getDataType().isEquivalent(type)) {
                codeVectorDataSkipped++;
                return;
            }
            codeVectorDataSkipped++;
            return;
        }
        Address end = address.add(type.getLength() - 1L);
        if (!listing.isUndefined(address, end)) {
            codeVectorDataSkipped++;
            return;
        }
        try {
            Data created = listing.createData(address, type);
            if (created != null && created.getLength() == type.getLength()) {
                codeVectorDataCreated++;
            }
            else {
                codeVectorDataSkipped++;
            }
        }
        catch (Exception ex) {
            codeVectorDataSkipped++;
        }
    }

    private String formatCodeVectorComment(String module, String name, JsonObject vector) {
        StringBuilder sb = new StringBuilder();
        sb.append(COMMENT_PREFIX).append(' ').append(module).append("::").append(name)
            .append("; 32-bit C28x code-vector function pointer");
        String description = getString(vector, "description", "");
        if (!description.isBlank()) {
            sb.append(" — ").append(description);
        }
        return sb.toString();
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
            JsonArray explicit = requiredArray(recovery, "explicit");
            List<CopyRecord> records = new ArrayList<>();
            int index = 0;
            for (JsonElement element : explicit) {
                if (!element.isJsonObject()) {
                    fail("explicit copy record " + index + " is not an object");
                }
                JsonObject copy = element.getAsJsonObject();
                SourceDispositionSpec disposition = parseSourceDisposition(copy);
                records.add(new CopyRecord(
                    requiredString(copy, "name"), requiredLong(copy, "source"),
                    requiredLong(copy, "destination"), requiredLong(copy, "words"),
                    getBoolean(copy, "executable", false),
                    getString(copy, "evidence", "explicit copy evidence"),
                    disposition.value, disposition.error));
                index++;
            }
            index = 0;
            for (CopyRecord record : records) {
                recoverCopy(record, "EXPLICIT", index++, records);
                explicitCopies++;
            }
        }
    }

    private SourceDispositionSpec parseSourceDisposition(JsonObject record) {
        JsonElement value = record.get("sourceDisposition");
        if (value == null) {
            return new SourceDispositionSpec(null, null);
        }
        if (value.isJsonNull() || !value.isJsonPrimitive() ||
                !value.getAsJsonPrimitive().isString()) {
            return new SourceDispositionSpec(null, "invalid-type");
        }
        String disposition = value.getAsString();
        if (SOURCE_DISPOSITION_INERT_STORAGE.equals(disposition)) {
            return new SourceDispositionSpec(disposition, null);
        }
        return new SourceDispositionSpec(null,
            "unknown-value-" + diagnosticToken(disposition));
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

    private void recoverCopy(CopyRecord record, String method, int ordinal,
            List<CopyRecord> explicitRecords) throws Exception {
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

        if ("EXPLICIT".equals(method)) {
            applyExplicitSourceDisposition(record, ordinal, explicitRecords, bytes);
        }

        if (verboseCopies || !"CINIT".equals(method)) {
            println("FIRMWARE_WORKSPACE_COPY=" + method + ":" + ordinal + ":" + record.name +
                ":src=0x" + Long.toHexString(record.sourceWord) +
                ":dst=0x" + Long.toHexString(record.destinationWord) +
                ":words=0x" + Long.toHexString(record.words) +
                ":x=" + record.executable);
        }
    }

    private void applyExplicitSourceDisposition(CopyRecord record, int ordinal,
            List<CopyRecord> explicitRecords, byte[] sourceBytes) throws Exception {
        if (record.sourceDispositionError != null) {
            sourceCleanupSkipped(record, ordinal, record.sourceDispositionError,
                "sourceDisposition must be the exact string \"" +
                SOURCE_DISPOSITION_INERT_STORAGE + "\"");
            return;
        }
        if (!record.requestsInertStorage()) {
            return;
        }

        CleanupProof proof;
        try {
            proof = proveInertCopySource(record, explicitRecords, sourceBytes);
        }
        catch (CleanupRejection rejection) {
            sourceCleanupSkipped(record, ordinal, rejection.reason, rejection.getMessage());
            return;
        }

        try {
            long[] cleared = transformInertCopySource(record, proof);
            inertSourceCleanups++;
            inertSourceInstructionsCleared += cleared[0];
            inertSourceReferencesCleared += cleared[1];
            println("FIRMWARE_WORKSPACE_SOURCE_CLEANUP=EXPLICIT:" + ordinal + ":" +
                diagnosticToken(record.name) + ":APPLIED:" + SOURCE_DISPOSITION_INERT_STORAGE +
                ":instructions=" + cleared[0] + ":references=" + cleared[1] +
                ":already=" + proof.alreadyMarked);
        }
        catch (CancelledException cancelled) {
            throw cancelled;
        }
        catch (Exception failure) {
            sourceCleanupSkipped(record, ordinal, "transaction-failure",
                failure.getClass().getSimpleName() + ": " + failure.getMessage());
        }
    }

    private CleanupProof proveInertCopySource(CopyRecord record,
            List<CopyRecord> explicitRecords, byte[] sourceBytes) throws Exception {
        long sourceEndWord = addExact(record.sourceWord, record.words,
            record.name + " inert source");
        Address start = wordAddress(record.sourceWord);
        Address endExclusive = wordAddress(sourceEndWord);
        Address endInclusive = endExclusive.subtract(1);
        AddressSet range = new AddressSet(start, endInclusive);

        requireRangeMapped(start, endExclusive, true,
            "inert copy source " + record.name);
        MemoryBlock parent = memory.getBlock(start);
        if (parent == null || !parent.contains(endInclusive)) {
            throw reject("source-spans-blocks",
                "the exact source is not contained in one isolatable memory block");
        }
        if (parent.isMapped()) {
            throw reject("mapped-source", "the source block is mapped: " + describeBlock(parent));
        }
        if (!parent.isInitialized() || !parent.isRead()) {
            throw reject("source-not-readable-initialized",
                "the source block is not readable initialized storage");
        }

        String expectedMarker = inertSourceMarker(record);
        String sourceName = parent.getSourceName();
        boolean alreadyMarked = expectedMarker.equals(sourceName);
        if (isWorkspaceOwnedInertCopySource(parent) && !alreadyMarked) {
            throw reject("contradictory-source-marker",
                "the source is owned by a different inert-copy record: " + sourceName);
        }
        if (alreadyMarked &&
                (!parent.getStart().equals(start) || !parent.getEnd().equals(endInclusive))) {
            throw reject("marker-range-mismatch",
                "the prior inert-source marker does not own the exact selected range");
        }
        if (isWorkspaceOwnedCopy(parent) && parent.isExecute()) {
            throw reject("executable-copy-destination",
                "the source block is already an independently materialized executable destination");
        }

        byte[] actualSource = readBytes(start, sourceBytes.length,
            "inert copy source " + record.name);
        if (!Arrays.equals(sourceBytes, actualSource)) {
            throw reject("source-bytes-changed",
                "the source bytes changed after destination materialization");
        }

        long destinationEndWord = addExact(record.destinationWord, record.words,
            record.name + " inert destination proof");
        Address destination = wordAddress(record.destinationWord);
        Address destinationEndExclusive = wordAddress(destinationEndWord);
        requireRangeMapped(destination, destinationEndExclusive, true,
            "materialized destination " + record.name);
        Address destinationCursor = destination;
        while (destinationCursor.compareTo(destinationEndExclusive) < 0) {
            MemoryBlock block = memory.getBlock(destinationCursor);
            if (block == null || !block.isInitialized()) {
                throw reject("destination-not-initialized",
                    "the destination is not fully initialized");
            }
            if (block.isExecute() != record.executable) {
                throw reject("destination-execute-mismatch",
                    "destination execute permission does not match the explicit record");
            }
            destinationCursor = minAddress(block.getEnd().add(1), destinationEndExclusive);
        }
        byte[] destinationBytes = readBytes(destination, sourceBytes.length,
            "materialized destination " + record.name);
        if (!Arrays.equals(sourceBytes, destinationBytes)) {
            throw reject("destination-bytes-differ",
                "source and materialized destination differ over the full exact span");
        }

        FunctionIterator entries = functions.getFunctions(range, true);
        if (entries.hasNext()) {
            Function function = entries.next();
            throw reject("function-entry",
                "source contains function entry " + function.getEntryPoint());
        }
        Iterator<Function> overlaps = functions.getFunctionsOverlapping(range);
        if (overlaps.hasNext()) {
            Function function = overlaps.next();
            throw reject("function-body",
                "source intersects function body at " + function.getEntryPoint());
        }

        AddressIterator externalEntries = symbols.getExternalEntryPointIterator();
        while (externalEntries.hasNext()) {
            Address address = externalEntries.next();
            if (range.contains(address)) {
                throw reject("external-entry-point",
                    "source contains external entry point " + address);
            }
        }

        String seedKind = workspaceSeedWithin(range);
        if (seedKind != null) {
            throw reject("analysis-seed", "source contains a workspace " + seedKind + " seed");
        }

        AddressIterator destinations = references.getReferenceDestinationIterator(range, true);
        while (destinations.hasNext()) {
            Address to = destinations.next();
            ReferenceIterator incoming = references.getReferencesTo(to);
            while (incoming.hasNext()) {
                Reference reference = incoming.next();
                if (!range.contains(reference.getFromAddress()) &&
                        reference.getReferenceType().isFlow()) {
                    throw reject("external-flow-ingress",
                        reference.getReferenceType() + " enters source from " +
                        reference.getFromAddress() + " to " + reference.getToAddress());
                }
            }
        }
        InstructionIterator sourceInstructions = listing.getInstructions(range, true);
        while (sourceInstructions.hasNext()) {
            Instruction instruction = sourceInstructions.next();
            Address fallFrom = instruction.getFallFrom();
            if (fallFrom != null && !range.contains(fallFrom)) {
                throw reject("external-fallthrough-ingress",
                    "implicit fall-through enters " + instruction.getMinAddress() +
                    " from " + fallFrom);
            }
        }

        for (CopyRecord other : explicitRecords) {
            if (other == record || !other.executable || other.words <= 0) {
                continue;
            }
            try {
                Math.addExact(other.destinationWord, other.words);
                if (rangesOverlap(record.sourceWord, record.words,
                        other.destinationWord, other.words)) {
                    throw reject("executable-copy-destination",
                        "source overlaps executable destination declared by " + other.name);
                }
            }
            catch (ArithmeticException overflow) {
                // A malformed peer will be rejected by ordinary recovery.  It
                // is not affirmative evidence for disposing of this source.
            }
        }

        CodeUnit atStart = listing.getCodeUnitContaining(start);
        if (atStart != null && atStart.getMinAddress().compareTo(start) < 0) {
            throw reject("isolation-boundary-code-unit",
                "a code/data unit begins outside and crosses the source start");
        }
        CodeUnit atEnd = listing.getCodeUnitContaining(endInclusive);
        if (atEnd != null && atEnd.getMaxAddress().compareTo(endInclusive) > 0) {
            throw reject("isolation-boundary-code-unit",
                "a code/data unit begins inside and crosses the source end");
        }

        return new CleanupProof(start, endExclusive, endInclusive, range, parent,
            actualSource, alreadyMarked);
    }

    private long[] transformInertCopySource(CopyRecord record, CleanupProof proof)
            throws Exception {
        AddressSet instructionRanges = new AddressSet();
        long instructionCount = 0;
        InstructionIterator instructions = listing.getInstructions(proof.range, true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            instructionRanges.add(instruction.getMinAddress(), instruction.getMaxAddress());
            instructionCount++;
        }
        long outgoingReferences = countReferencesFrom(instructionRanges);
        List<SymbolSnapshot> labels = snapshotInstructionLabels(instructionRanges);

        Set<String> symbolsBefore = symbolSignatures(proof.range);
        Set<String> commentsBefore = commentSignatures(proof.range);
        Set<String> bookmarksBefore = bookmarkSignatures(proof.range);
        Set<String> dataBefore = dataSignatures(proof.range);
        Set<String> incomingBefore = externalIncomingNonFlowSignatures(proof.range);
        EdgeSnapshot prefix = null;
        EdgeSnapshot suffix = null;
        if (proof.parent.getStart().compareTo(proof.start) < 0) {
            prefix = snapshotEdge(proof.parent.getStart(), proof.start.subtract(1), proof.parent);
        }
        if (proof.parent.getEnd().compareTo(proof.endInclusive) > 0) {
            suffix = snapshotEdge(proof.endExclusive, proof.parent.getEnd(), proof.parent);
        }
        boolean sourceRead = proof.parent.isRead();
        boolean sourceWrite = proof.parent.isWrite();
        boolean sourceVolatile = proof.parent.isVolatile();
        boolean sourceInitialized = proof.parent.isInitialized();

        int transaction = currentProgram.startTransaction(
            "Mark explicit copy source as proved inert storage: " + record.name);
        boolean commit = false;
        try {
            monitor.checkCancelled();
            List<MemoryBlock> isolated = isolateRange(proof.start, proof.endExclusive,
                "inert copy source " + record.name);
            if (isolated.size() != 1) {
                throw new IllegalStateException("source isolation produced " +
                    isolated.size() + " blocks");
            }
            MemoryBlock sourceBlock = isolated.get(0);
            if (!sourceBlock.getStart().equals(proof.start) ||
                    !sourceBlock.getEnd().equals(proof.endInclusive)) {
                throw new IllegalStateException("source block is not the exact selected span");
            }

            AddressRangeIterator ranges = instructionRanges.getAddressRanges(true);
            while (ranges.hasNext()) {
                monitor.checkCancelled();
                AddressRange range = ranges.next();
                listing.clearCodeUnits(range.getMinAddress(), range.getMaxAddress(), false, monitor);
            }
            restoreInstructionLabels(labels);

            sourceBlock = memory.getBlock(proof.start);
            sourceBlock.setExecute(false);
            sourceBlock.setSourceName(inertSourceMarker(record));
            safeRename(sourceBlock, sanitizeSymbol(record.name + "_SOURCE_INERT"));
            appendBlockComment(sourceBlock, inertSourceComment(record));

            requireTransformation(proof, sourceBlock, instructionRanges,
                sourceRead, sourceWrite, sourceVolatile, sourceInitialized,
                symbolsBefore, commentsBefore, bookmarksBefore, dataBefore,
                incomingBefore, prefix, suffix);
            commit = true;
        }
        finally {
            currentProgram.endTransaction(transaction, commit);
        }
        return new long[] { instructionCount, outgoingReferences };
    }

    private void requireTransformation(CleanupProof proof, MemoryBlock sourceBlock,
            AddressSet instructionRanges, boolean sourceRead, boolean sourceWrite,
            boolean sourceVolatile, boolean sourceInitialized, Set<String> symbolsBefore,
            Set<String> commentsBefore, Set<String> bookmarksBefore, Set<String> dataBefore,
            Set<String> incomingBefore, EdgeSnapshot prefix, EdgeSnapshot suffix)
            throws Exception {
        if (sourceBlock == null || !sourceBlock.getStart().equals(proof.start) ||
                !sourceBlock.getEnd().equals(proof.endInclusive)) {
            throw new IllegalStateException("exact source block was not retained");
        }
        if (sourceBlock.isInitialized() != sourceInitialized ||
                sourceBlock.isRead() != sourceRead || sourceBlock.isWrite() != sourceWrite ||
                sourceBlock.isVolatile() != sourceVolatile || sourceBlock.isExecute()) {
            throw new IllegalStateException("source permissions/state changed beyond execute");
        }
        byte[] after = readBytes(proof.start, proof.bytes.length,
            "verified inert source");
        if (!Arrays.equals(proof.bytes, after)) {
            throw new IllegalStateException("source bytes changed during cleanup");
        }
        if (listing.getInstructions(proof.range, true).hasNext()) {
            throw new IllegalStateException("instructions remain in inert source");
        }
        if (countReferencesFrom(instructionRanges) != 0) {
            throw new IllegalStateException(
                "outgoing references remain at removed instruction addresses");
        }
        if (!symbolsBefore.equals(symbolSignatures(proof.range))) {
            throw new IllegalStateException("source labels/namespaces changed during cleanup");
        }
        if (!commentsBefore.equals(commentSignatures(proof.range))) {
            throw new IllegalStateException("source listing comments changed during cleanup");
        }
        if (!bookmarksBefore.equals(bookmarkSignatures(proof.range))) {
            throw new IllegalStateException("source bookmarks changed during cleanup");
        }
        if (!dataBefore.equals(dataSignatures(proof.range))) {
            throw new IllegalStateException("source defined data changed during cleanup");
        }
        if (!incomingBefore.equals(externalIncomingNonFlowSignatures(proof.range))) {
            throw new IllegalStateException("external non-flow references changed during cleanup");
        }
        verifyEdge(prefix);
        verifyEdge(suffix);
    }

    private List<SymbolSnapshot> snapshotInstructionLabels(AddressSetView instructionRanges) {
        List<SymbolSnapshot> result = new ArrayList<>();
        if (instructionRanges.isEmpty()) {
            return result;
        }
        SymbolIterator iterator = symbols.getDefinedSymbols();
        while (iterator.hasNext()) {
            Symbol symbol = iterator.next();
            if (!instructionRanges.contains(symbol.getAddress()) || symbol.isDynamic() ||
                    symbol.getSymbolType() != SymbolType.LABEL ||
                    symbol.getSource() == SourceType.DEFAULT) {
                continue;
            }
            result.add(new SymbolSnapshot(symbol));
        }
        return result;
    }

    private void restoreInstructionLabels(List<SymbolSnapshot> snapshots) throws Exception {
        for (SymbolSnapshot snapshot : snapshots) {
            Symbol symbol = symbols.getSymbol(snapshot.name, snapshot.address, snapshot.namespace);
            if (symbol == null) {
                symbol = symbols.createLabel(snapshot.address, snapshot.name,
                    snapshot.namespace, snapshot.source);
            }
            else if (symbol.getSource() != snapshot.source) {
                symbol.setSource(snapshot.source);
            }
            symbol.setPinned(snapshot.pinned);
        }
        for (SymbolSnapshot snapshot : snapshots) {
            if (!snapshot.primary) {
                continue;
            }
            Symbol symbol = symbols.getSymbol(snapshot.name, snapshot.address, snapshot.namespace);
            if (symbol != null) {
                symbol.setPrimary();
            }
        }
    }

    private EdgeSnapshot snapshotEdge(Address start, Address end, MemoryBlock block)
            throws Exception {
        long length = end.subtract(start) + 1;
        if (length > Integer.MAX_VALUE) {
            throw new IllegalStateException("edge snapshot is too large");
        }
        return new EdgeSnapshot(start, end,
            readBytes(start, (int) length, "source isolation edge"), block);
    }

    private void verifyEdge(EdgeSnapshot edge) throws Exception {
        if (edge == null) {
            return;
        }
        byte[] after = readBytes(edge.start, edge.bytes.length, "source isolation edge");
        if (!Arrays.equals(edge.bytes, after)) {
            throw new IllegalStateException("bytes outside selected source changed");
        }
        Address cursor = edge.start;
        Address endExclusive = edge.end.add(1);
        while (cursor.compareTo(endExclusive) < 0) {
            MemoryBlock block = memory.getBlock(cursor);
            if (block == null || block.isRead() != edge.read || block.isWrite() != edge.write ||
                    block.isExecute() != edge.execute ||
                    block.isVolatile() != edge.volatileBlock) {
                throw new IllegalStateException(
                    "permissions outside selected source changed at " + cursor);
            }
            cursor = minAddress(block.getEnd().add(1), endExclusive);
        }
    }

    private long countReferencesFrom(AddressSetView range) {
        if (range.isEmpty()) {
            return 0;
        }
        long count = 0;
        AddressIterator iterator = references.getReferenceSourceIterator(range, true);
        while (iterator.hasNext()) {
            count += references.getReferencesFrom(iterator.next()).length;
        }
        return count;
    }

    private Set<String> symbolSignatures(AddressSetView range) {
        Set<String> result = new LinkedHashSet<>();
        SymbolIterator iterator = symbols.getDefinedSymbols();
        while (iterator.hasNext()) {
            Symbol symbol = iterator.next();
            if (!range.contains(symbol.getAddress()) || symbol.isDynamic()) {
                continue;
            }
            result.add(symbol.getAddress() + "|" + symbol.getName(true) + "|" +
                symbol.getSymbolType() + "|" + symbol.getSource() + "|" +
                symbol.isPrimary() + "|" + symbol.isPinned());
        }
        return result;
    }

    private Set<String> commentSignatures(AddressSetView range) {
        Set<String> result = new LinkedHashSet<>();
        AddressIterator iterator = listing.getCommentAddressIterator(range, true);
        while (iterator.hasNext()) {
            Address address = iterator.next();
            for (CommentType type : CommentType.values()) {
                String text = listing.getComment(type, address);
                if (text != null) {
                    result.add(address + "|" + type + "|" + text);
                }
            }
        }
        return result;
    }

    private Set<String> bookmarkSignatures(AddressSetView range) {
        Set<String> result = new LinkedHashSet<>();
        Iterator<Bookmark> iterator = bookmarks.getBookmarksIterator(range.getMinAddress(), true);
        while (iterator.hasNext()) {
            Bookmark bookmark = iterator.next();
            if (!range.contains(bookmark.getAddress())) {
                if (bookmark.getAddress().compareTo(range.getMaxAddress()) > 0) {
                    break;
                }
                continue;
            }
            result.add(bookmark.getAddress() + "|" + bookmark.getTypeString() + "|" +
                bookmark.getCategory() + "|" + bookmark.getComment());
        }
        return result;
    }

    private Set<String> dataSignatures(AddressSetView range) {
        Set<String> result = new LinkedHashSet<>();
        Iterator<Data> iterator = listing.getDefinedData(range, true);
        while (iterator.hasNext()) {
            Data data = iterator.next();
            result.add(data.getMinAddress() + "|" + data.getMaxAddress() + "|" +
                data.getDataType().getPathName() + "|" + data.getLength());
        }
        return result;
    }

    private Set<String> externalIncomingNonFlowSignatures(AddressSetView range) {
        Set<String> result = new LinkedHashSet<>();
        AddressIterator destinations = references.getReferenceDestinationIterator(range, true);
        while (destinations.hasNext()) {
            ReferenceIterator iterator = references.getReferencesTo(destinations.next());
            while (iterator.hasNext()) {
                Reference reference = iterator.next();
                if (range.contains(reference.getFromAddress()) ||
                        reference.getReferenceType().isFlow()) {
                    continue;
                }
                result.add(reference.getFromAddress() + "|" + reference.getToAddress() + "|" +
                    reference.getReferenceType() + "|" + reference.getSource() + "|" +
                    reference.getOperandIndex() + "|" + reference.isPrimary());
            }
        }
        return result;
    }

    private String workspaceSeedWithin(AddressSetView range) {
        if (!workspace.has("analysisSeeds") || !workspace.get("analysisSeeds").isJsonObject()) {
            return null;
        }
        JsonObject seeds = workspace.getAsJsonObject("analysisSeeds");
        for (String kind : List.of("disassembly", "functions")) {
            if (!seeds.has(kind) || !seeds.get(kind).isJsonArray()) {
                continue;
            }
            for (JsonElement element : seeds.getAsJsonArray(kind)) {
                if (range.contains(wordAddress(element.getAsLong()))) {
                    return kind;
                }
            }
        }
        return null;
    }

    private byte[] readBytes(Address start, int length, String purpose) throws Exception {
        byte[] result = new byte[length];
        int count = memory.getBytes(start, result);
        if (count != length) {
            throw new IllegalStateException("short read for " + purpose + ": " +
                count + "/" + length);
        }
        return result;
    }

    private String inertSourceMarker(CopyRecord record) {
        return WORKSPACE_SOURCE_PREFIX + workspaceName + INERT_SOURCE_COMPONENT +
            record.name + INERT_SOURCE_SUFFIX;
    }

    private String inertSourceComment(CopyRecord record) {
        return COMMENT_PREFIX + " explicit copy source " + record.name +
            " retained as initialized storage/provenance and made non-executable after " +
            "full-span destination equality and finite no-ingress proof; source word 0x" +
            Long.toHexString(record.sourceWord) + ", destination word 0x" +
            Long.toHexString(record.destinationWord) + ", words 0x" +
            Long.toHexString(record.words) + "; policy " +
            SOURCE_DISPOSITION_INERT_STORAGE + "; " + record.evidence;
    }

    private void sourceCleanupSkipped(CopyRecord record, int ordinal, String reason,
            String detail) {
        inertSourceCleanupSkips++;
        println("FIRMWARE_WORKSPACE_SOURCE_CLEANUP=EXPLICIT:" + ordinal + ":" +
            diagnosticToken(record.name) + ":SKIPPED:" + diagnosticToken(reason));
        printerr("DEVICE_PROFILE_WARNING=source cleanup skipped for " + record.name +
            " [" + reason + "]: " + (detail == null ? "unspecified" : detail));
    }

    private static CleanupRejection reject(String reason, String detail) {
        return new CleanupRejection(reason, detail);
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
                if (isInertSourcePolicyAddress(address)) {
                    println("FIRMWARE_WORKSPACE_SEED_SKIPPED=" + address +
                        ":conflicts with inert-storage copy-source policy");
                    continue;
                }
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
                if (isInertSourcePolicyAddress(address)) {
                    println("FIRMWARE_WORKSPACE_FUNCTION_SEED_SKIPPED=" + address +
                        ":conflicts with inert-storage copy-source policy");
                    continue;
                }
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

    private boolean isWorkspaceOwnedInertCopySource(MemoryBlock block) {
        if (workspaceName == null) {
            return false;
        }
        String source = block.getSourceName();
        return source != null && source.startsWith(
            WORKSPACE_SOURCE_PREFIX + workspaceName + INERT_SOURCE_COMPONENT) &&
            source.endsWith(INERT_SOURCE_SUFFIX);
    }

    private boolean isInertSourcePolicyAddress(Address address) {
        if (workspace == null || !workspace.has("copyRecovery") ||
                !workspace.get("copyRecovery").isJsonObject()) {
            return false;
        }
        JsonObject recovery = workspace.getAsJsonObject("copyRecovery");
        if (!recovery.has("explicit") || !recovery.get("explicit").isJsonArray()) {
            return false;
        }
        for (JsonElement element : recovery.getAsJsonArray("explicit")) {
            if (!element.isJsonObject()) {
                continue;
            }
            JsonObject copy = element.getAsJsonObject();
            SourceDispositionSpec disposition = parseSourceDisposition(copy);
            if (!SOURCE_DISPOSITION_INERT_STORAGE.equals(disposition.value)) {
                continue;
            }
            try {
                long startWord = requiredLong(copy, "source");
                long words = requiredLong(copy, "words");
                if (words <= 0) {
                    continue;
                }
                long endWord = Math.addExact(startWord, words);
                Address start = wordAddress(startWord);
                Address endExclusive = wordAddress(endWord);
                if (address.compareTo(start) >= 0 && address.compareTo(endExclusive) < 0) {
                    return true;
                }
            }
            catch (RuntimeException malformed) {
                // Ordinary explicit-copy validation owns malformed ranges.  A
                // broken record must not create a broad seed exclusion.
            }
        }
        return false;
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

    private static String diagnosticToken(String value) {
        if (value == null || value.isBlank()) {
            return "none";
        }
        String token = value.replaceAll("[^A-Za-z0-9_.-]", "_");
        return token.isBlank() ? "none" : token;
    }

    private void recordProgramOptions(File file, File workspaceFile, boolean strictFirmware,
            boolean recoverCopies) {
        Options options = currentProgram.getOptions("TMS320C28 Device Profile");
        options.setString("Profile Name", profileName);
        options.setInt("Profile Version", requiredInt(profile, "version"));
        options.setString("Profile File", file.getAbsolutePath());
        options.setInt("Access View Data Created", accessViewDataCreated);
        options.setInt("Access View Data Skipped", accessViewDataSkipped);
        options.setInt("Code Vector Data Created", codeVectorDataCreated);
        options.setInt("Code Vector Data Skipped", codeVectorDataSkipped);
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
            workspaceOptions.setInt("Inert Source Cleanups", inertSourceCleanups);
            workspaceOptions.setInt("Inert Source Cleanup Skips", inertSourceCleanupSkips);
            workspaceOptions.setLong("Inert Source Instructions Cleared",
                inertSourceInstructionsCleared);
            workspaceOptions.setLong("Inert Source References Cleared",
                inertSourceReferencesCleared);
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
        println("DEVICE_PROFILE_ACCESS_VIEW_DATA_CREATED=" + accessViewDataCreated);
        println("DEVICE_PROFILE_ACCESS_VIEW_DATA_SKIPPED=" + accessViewDataSkipped);
        println("DEVICE_PROFILE_CODE_VECTOR_DATA_CREATED=" + codeVectorDataCreated);
        println("DEVICE_PROFILE_CODE_VECTOR_DATA_SKIPPED=" + codeVectorDataSkipped);
        println("DEVICE_PROFILE_PASS=" + profileName);
        if (workspace != null) {
            println("FIRMWARE_WORKSPACE_EXPLICIT_COPIES=" + explicitCopies);
            println("FIRMWARE_WORKSPACE_CINIT_RECORDS=" + cinitRecords);
            println("FIRMWARE_WORKSPACE_RECOVERED_WORDS=" + recoveredWords);
            println("FIRMWARE_WORKSPACE_DISASSEMBLY_SEEDS=" + disassemblySeeds);
            println("FIRMWARE_WORKSPACE_FUNCTION_SEEDS=" + functionSeeds);
            println("FIRMWARE_WORKSPACE_INERT_SOURCE_CLEANUPS=" + inertSourceCleanups);
            println("FIRMWARE_WORKSPACE_INERT_SOURCE_CLEANUP_SKIPS=" +
                inertSourceCleanupSkips);
            println("FIRMWARE_WORKSPACE_INERT_SOURCE_INSTRUCTIONS_CLEARED=" +
                inertSourceInstructionsCleared);
            println("FIRMWARE_WORKSPACE_INERT_SOURCE_REFERENCES_CLEARED=" +
                inertSourceReferencesCleared);
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
