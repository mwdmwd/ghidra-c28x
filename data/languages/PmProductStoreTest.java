// Focused regression for analyzer-proved no-shift MOV loc16,P canonicalization.
//@category TMS320C28

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class PmProductStoreTest extends GhidraScript {
    private static final String[] MANUAL_POSITIVES = {
        "pm_boundary_store",
        "pm_explicit_zero",
        "pm_explicit_zero_rejoin",
        "pm_explicit_zero_after_dynamic",
        "pm_after_completed_call",
        "pm_after_unequal_calls",
    };
    private static final String[] MANUAL_NEGATIVES = {
        "pm_near_positive_shift",
        "pm_near_negative_shift",
        "pm_near_dynamic_pm",
        "pm_near_dynamic_st0",
        "pm_near_conflicting_paths",
        "pm_near_alternate_ingress",
        "pm_near_undominated_zero_loop",
        "pm_near_raw101_c28",
        "pm_near_raw101_c2x",
    };
    private static final String[] COMPILER_FUNCTIONS = {
        "pm_plain_quotient_store",
        "pm_store_after_call",
        "pm_store_after_unequal_calls",
    };

    private Listing listing;
    private FunctionManager functions;
    private Register canonicalContext;
    private Register pm;
    private final Map<String, Address> fixtureAddresses = new HashMap<>();

    @Override
    public void run() throws Exception {
        listing = currentProgram.getListing();
        functions = currentProgram.getFunctionManager();
        canonicalContext = currentProgram.getProgramContext()
            .getRegister("pm_store_noshift");
        pm = currentProgram.getLanguage().getRegister("PM");
        require(canonicalContext != null, "missing pm_store_noshift context");
        require(pm != null, "missing PM register");

        String kind = parseFixtureArguments();
        if (kind.equals("validation")) {
            auditManual();
            println("PM_PROGRAM_PASS=validation");
        }
        else if (kind.equals("compiler")) {
            auditCompiler();
            println("PM_PROGRAM_PASS=" + currentProgram.getName());
        }
        else {
            throw new AssertionError("unrecognized PM product-store fixture kind " + kind);
        }
    }

    private void auditManual() throws Exception {
        Set<Address> expectedCanonical = new HashSet<>();
        for (String name : MANUAL_POSITIVES) {
            Function function = function(name);
            List<Instruction> stores = productStores(function);
            require(stores.size() == 1, name + " must contain one MOV loc16,P");
            Instruction store = stores.get(0);
            require(tagged(store), name + " was not canonicalized");
            requireDirectPcode(store, name);
            expectedCanonical.add(store.getMinAddress());
        }
        for (String name : MANUAL_NEGATIVES) {
            Function function = function(name);
            Instruction store;
            if (name.equals("pm_near_alternate_ingress")) {
                store = listing.getInstructionAt(address("pm_alternate_target"));
                require(store != null && isProductStore(store),
                    "alternate-ingress target no longer names MOV loc16,P");
            }
            else {
                List<Instruction> stores = productStores(function);
                require(stores.size() == 1,
                    name + " must contain one MOV loc16,P");
                store = stores.get(0);
            }
            require(!tagged(store), name + " was unsafely canonicalized");
            requireGenericPcode(store, name);
        }

        requireContextOnlyOn(expectedCanonical);
        requireStaleContextRevoked();
        requireRaw101Modes();
        requireCompletedCallShape(function("pm_after_completed_call"), 1);
        requireCompletedCallShape(function("pm_after_unequal_calls"), 4);

        println("PM_MANUAL_CANONICAL_SITES=" + expectedCanonical.size());
        println("PM_MANUAL_NEAR_MISSES=" + MANUAL_NEGATIVES.length);
        println("PM_STALE_CONTEXT_REVOKED=2");
        println("PM_RAW101_MODES_REJECTED=2");
    }

    private void auditCompiler() throws Exception {
        Set<Address> expectedCanonical = new HashSet<>();
        for (String name : COMPILER_FUNCTIONS) {
            Function function = function(name);
            List<Instruction> stores = productStores(function);
            require(stores.size() == 1, name + " must contain one MOV loc16,P");
            Instruction store = stores.get(0);
            require(tagged(store), name + " was not canonicalized");
            requireDirectPcode(store, name);
            expectedCanonical.add(store.getMinAddress());
        }
        requireContextOnlyOn(expectedCanonical);

        Function plain = function("pm_plain_quotient_store");
        require(callInstructions(plain).isEmpty(),
            "plain quotient fixture unexpectedly contains a call");
        Function after = function("pm_store_after_call");
        requireStoreAfterCalls(after, 1, false);
        Function rejoin = function("pm_store_after_unequal_calls");
        requireStoreAfterCalls(rejoin, 3, true);

        DecompInterface decompiler = new DecompInterface();
        require(decompiler.openProgram(currentProgram), "failed to open decompiler");
        try {
            for (String name : COMPILER_FUNCTIONS) {
                Function function = function(name);
                DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                require(result.decompileCompleted() && result.getDecompiledFunction() != null,
                    name + " failed to decompile: " + result.getErrorMessage());
                String c = result.getDecompiledFunction().getC();
                require(!c.contains("in_PM"), name + " still exposes incoming PM");
                require(!c.contains("& -(ulong)") && !c.contains("& ~-(ulong)"),
                    name + " still contains the mask-selected PM store form");
                if (name.equals("pm_plain_quotient_store")) {
                    require(c.contains(" / 10"),
                        "plain quotient store did not decompile as division by ten");
                }
            }
        }
        finally {
            decompiler.dispose();
        }

        println("PM_COMPILER_CANONICAL_SITES=" + expectedCanonical.size());
        println("PM_COMPILER_COMPLETED_CALL_STORE=true");
        println("PM_COMPILER_UNEQUAL_CALL_REJOIN=true");
    }

    private void requireCompletedCallShape(Function function, int minimumCalls)
            throws Exception {
        List<Instruction> calls = callInstructions(function);
        require(calls.size() >= minimumCalls,
            function.getName() + " lost completed calls");
        Instruction store = productStores(function).get(0);
        for (Instruction call : calls) {
            require(call.getFallThrough() != null,
                function.getName() + " has a non-completed call");
            require(call.getMinAddress().compareTo(store.getMinAddress()) < 0,
                function.getName() + " store no longer follows every call");
        }
    }

    private void requireStoreAfterCalls(Function function, int minimumCalls,
            boolean requireConditional) throws Exception {
        List<Instruction> calls = callInstructions(function);
        require(calls.size() >= minimumCalls,
            function.getName() + " lost its call schedule");
        Instruction store = productStores(function).get(0);
        boolean conditional = false;
        InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            if (instruction.getFlowType().isConditional()) {
                conditional = true;
            }
        }
        for (Instruction call : calls) {
            require(call.getFallThrough() != null,
                function.getName() + " contains a non-completed call");
            require(call.getMinAddress().compareTo(store.getMinAddress()) < 0,
                function.getName() + " store is not after its calls");
        }
        if (requireConditional) {
            require(conditional, function.getName() + " lost its branch rejoin");
        }
    }

    private List<Instruction> callInstructions(Function function) throws Exception {
        List<Instruction> result = new ArrayList<>();
        InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            if (instruction.getFlowType().isCall()) {
                result.add(instruction);
            }
        }
        return result;
    }

    private void requireStaleContextRevoked() throws Exception {
        Instruction store = listing.getInstructionAt(address("pm_stale_store"));
        Instruction nonmov = listing.getInstructionAt(address("pm_stale_nonmov"));
        require(store != null && isProductStore(store),
            "stale-store label no longer names MOV AR0,P");
        require(nonmov != null && nonmov.getMnemonicString().equalsIgnoreCase("NOP"),
            "stale-nonmov label no longer names NOP");
        require(!tagged(store) && !tagged(nonmov),
            "stale context was not revoked");

        Memory memory = currentProgram.getMemory();
        require(readWord(memory, store.getMinAddress()) == 0x3fa0,
            "MOV AR0,P bytes changed during context revocation");
        require(readWord(memory, nonmov.getMinAddress()) == 0x7700,
            "NOP bytes changed during context revocation");
        require(normalize(store.toString()).equals("MOVAR0,P"),
            "MOV AR0,P display changed: " + store);
        require(normalize(nonmov.toString()).equals("NOP"),
            "NOP display changed: " + nonmov);
    }

    private void requireRaw101Modes() throws Exception {
        Instruction c28 = findMnemonic(function("pm_near_raw101_c28"), "SPM");
        Instruction c2x = findMnemonic(function("pm_near_raw101_c2x"), "SPM");
        require(readWord(currentProgram.getMemory(), c28.getMinAddress()) == 0xff6d,
            "C28x raw 101 encoding changed");
        require(readWord(currentProgram.getMemory(), c2x.getMinAddress()) == 0xff6d,
            "AMODE=1 raw 101 encoding changed");
        require(normalize(c28.toString()).equals("SPM#-4"),
            "C28x raw 101 did not display as right four: " + c28);
        require(normalize(c2x.toString()).equals("SPM#4"),
            "AMODE=1 raw 101 did not display as left four: " + c2x);
    }

    private Instruction findMnemonic(Function function, String mnemonic) {
        InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            if (instruction.getMnemonicString().equalsIgnoreCase(mnemonic)) {
                return instruction;
            }
        }
        throw new AssertionError(function.getName() + " lacks " + mnemonic);
    }

    private int readWord(Memory memory, Address address) throws Exception {
        int low = memory.getByte(address) & 0xff;
        int high = memory.getByte(address.add(1)) & 0xff;
        return low | (high << 8);
    }

    private void requireContextOnlyOn(Set<Address> expected) throws Exception {
        Set<Address> actual = new HashSet<>();
        int nonMov = 0;
        InstructionIterator iterator = listing.getInstructions(true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            if (!tagged(instruction)) {
                continue;
            }
            actual.add(instruction.getMinAddress());
            if (!isProductStore(instruction)) {
                nonMov++;
            }
            requireDirectPcode(instruction, "context-tagged site " + instruction.getMinAddress());
        }
        require(actual.equals(expected),
            "unexpected canonical context sites: expected=" + expected + " actual=" + actual);
        require(nonMov == 0, "context leaked onto non-MOV-loc16-P instructions");
        println("PM_CONTEXT_ON_NON_MOV_LOC16_P=" + nonMov);
    }

    private void requireDirectPcode(Instruction instruction, String where) {
        boolean pmReference = false;
        boolean forbiddenShift = false;
        for (PcodeOp op : instruction.getPcode()) {
            // Direct-address loc16 forms may legitimately left-shift DP while
            // forming the destination address.  The forbidden PM signature is
            // the signed-direction test/arithmetic-right path, together with
            // any reference to PM itself.
            if (op.getOpcode() == PcodeOp.INT_SRIGHT ||
                op.getOpcode() == PcodeOp.INT_SLESS) {
                forbiddenShift = true;
            }
            if (registerReference(op.getOutput(), pm)) {
                pmReference = true;
            }
            for (Varnode input : op.getInputs()) {
                if (registerReference(input, pm)) {
                    pmReference = true;
                }
            }
        }
        require(!pmReference, where + " direct form still references PM");
        require(!forbiddenShift, where + " direct form retained shift/sign P-Code");
    }

    private void requireGenericPcode(Instruction instruction, String where) {
        boolean pmReference = false;
        boolean left = false;
        boolean right = false;
        for (PcodeOp op : instruction.getPcode()) {
            if (op.getOpcode() == PcodeOp.INT_LEFT) left = true;
            if (op.getOpcode() == PcodeOp.INT_SRIGHT) right = true;
            if (registerReference(op.getOutput(), pm)) pmReference = true;
            for (Varnode input : op.getInputs()) {
                if (registerReference(input, pm)) pmReference = true;
            }
        }
        require(pmReference && left && right,
            where + " no longer retains ordinary generic pmshift P-Code");
    }

    private boolean registerReference(Varnode node, Register target) {
        if (node == null || !node.isRegister()) {
            return false;
        }
        Register register = currentProgram.getLanguage()
            .getRegister(node.getAddress(), node.getSize());
        return register != null && register.equals(target);
    }

    private boolean tagged(Instruction instruction) {
        return BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(
            canonicalContext, instruction.getMinAddress(), false));
    }

    private List<Instruction> productStores(Function function) throws Exception {
        List<Instruction> result = new ArrayList<>();
        InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            if (isProductStore(instruction)) {
                result.add(instruction);
            }
        }
        return result;
    }

    private boolean isProductStore(Instruction instruction) {
        if (!instruction.getMnemonicString().equalsIgnoreCase("MOV") ||
            instruction.getNumOperands() != 2) {
            return false;
        }
        Object[] source = instruction.getOpObjects(1);
        return source.length == 1 && source[0] instanceof Register register &&
            register.getName().equals("P");
    }

    private Function function(String name) {
        Address address = address(name);
        Function function = functions.getFunctionAt(address);
        require(function != null, "missing function " + name + " at " + address);
        return function;
    }

    private String parseFixtureArguments() {
        String[] arguments = getScriptArgs();
        require(arguments.length >= 2, "missing fixture kind/address arguments");
        for (int index = 1; index < arguments.length; index++) {
            String argument = arguments[index];
            int equals = argument.indexOf('=');
            require(equals > 0 && equals < argument.length() - 1,
                "malformed fixture address " + argument);
            String name = argument.substring(0, equals);
            Address address = toAddr(argument.substring(equals + 1));
            require(address != null, "invalid fixture address " + argument);
            fixtureAddresses.put(name, address);
        }
        return arguments[0];
    }

    private Address address(String name) {
        Address address = fixtureAddresses.get(name);
        require(address != null, "missing fixture address " + name);
        return address;
    }

    private String normalize(String text) {
        return text.replaceAll("\\s+", "").toUpperCase(Locale.ROOT);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
