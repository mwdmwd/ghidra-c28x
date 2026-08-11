import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class DivisionIdiomTest extends GhidraScript {
    private static final String[] COMPILER_FUNCTIONS = {
        "div32_const10", "mod32_const10", "div32_variable_nonzero",
        "divmod32_variable_nonzero"
    };
    private static final String[] POSITIVE_FUNCTIONS = {
        "division_positive_const", "division_positive_variable"
    };
    private static final String[] REJECTED_FUNCTIONS = {
        "division_near_repeat_count",
        "division_near_initial_acc",
        "division_near_zero_divisor",
        "division_near_unknown_divisor",
        "division_near_mutated_divisor",
        "division_near_memory_alias",
        "division_near_intervening_flow",
        "division_near_alternate_ingress",
        "division_near_missing_dividend"
    };

    private Register canonicalContext;

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    @Override
    public void run() throws Exception {
        canonicalContext = currentProgram.getProgramContext().getRegister("subcul_div32");
        require(canonicalContext != null, "missing subcul_div32 context register");
        String name = currentProgram.getName().toLowerCase(Locale.ROOT);
        if (name.contains("validation")) {
            testValidationFixture();
        }
        else {
            testCompilerFixture(name.contains("o0") ? "O0" : "O2");
        }
        println("DIVISION_PROGRAM_PASS=" + currentProgram.getName());
    }

    private Function function(String name) {
        List<Function> found = getGlobalFunctions(name);
        require(found.size() == 1,
            "expected one function " + name + ", got " + found.size());
        return found.get(0);
    }

    private List<Instruction> instructions(Function function) {
        List<Instruction> result = new ArrayList<>();
        Instruction current = currentProgram.getListing()
            .getInstructionAt(function.getEntryPoint());
        for (int count = 0; current != null && count < 64; count++) {
            result.add(current);
            String mnemonic = current.getMnemonicString();
            if (mnemonic.equalsIgnoreCase("LRETR") ||
                mnemonic.equalsIgnoreCase("LRET") ||
                mnemonic.equalsIgnoreCase("LRETE")) {
                break;
            }
            Instruction next = current.getNext();
            if (next == null || !current.getMaxAddress().next()
                    .equals(next.getMinAddress())) {
                break;
            }
            current = next;
        }
        return result;
    }

    private List<Instruction> subculs(Function function) {
        List<Instruction> result = new ArrayList<>();
        for (Instruction instruction : instructions(function)) {
            if (instruction.getMnemonicString().equalsIgnoreCase("SUBCUL")) {
                result.add(instruction);
            }
        }
        return result;
    }

    private boolean canonical(Instruction instruction) {
        return BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(
            canonicalContext, instruction.getMinAddress(), false));
    }

    private boolean hasPcode(Instruction instruction, int opcode) {
        for (PcodeOp op : instruction.getPcode()) {
            if (op.getOpcode() == opcode) {
                return true;
            }
        }
        return false;
    }

    private String outputRegister(PcodeOp op) {
        Varnode output = op.getOutput();
        if (output == null || !output.isRegister()) {
            return null;
        }
        Register register = currentProgram.getLanguage().getRegister(
            output.getAddress(), output.getSize());
        return register == null ? null : register.getName();
    }

    private void requireCanonicalPcode(Instruction instruction) {
        require(instruction.getMnemonicString().equalsIgnoreCase("SUBCUL"),
            "canonical site changed mnemonic at " + instruction.getMinAddress());
        require(instruction.getDefaultOperandRepresentation(0).equalsIgnoreCase("ACC"),
            "canonical site changed ACC display at " + instruction.getMinAddress());
        require(OperandType.isRegister(instruction.getOperandType(1)),
            "canonical divisor is no longer a register at " + instruction.getMinAddress());
        require(hasPcode(instruction, PcodeOp.INT_DIV) &&
                hasPcode(instruction, PcodeOp.INT_REM),
            "canonical site lacks quotient/remainder P-Code at " +
                instruction.getMinAddress());
        require(!hasPcode(instruction, PcodeOp.BRANCH) &&
                !hasPcode(instruction, PcodeOp.CBRANCH),
            "canonical site retained restoring-loop CFG at " +
                instruction.getMinAddress());

        boolean p = false, acc = false, c = false, n = false, z = false, rptc = false;
        for (PcodeOp op : instruction.getPcode()) {
            String output = outputRegister(op);
            if ("P".equals(output)) p = true;
            if ("ACC".equals(output)) acc = true;
            if ("C".equals(output)) c = true;
            if ("N".equals(output)) n = true;
            if ("Z".equals(output)) z = true;
            if ("RPTC".equals(output)) rptc = true;
            require(!"V".equals(output) && !"OVC".equals(output),
                "canonical site unexpectedly changes V/OVC at " +
                    instruction.getMinAddress());
        }
        require(p && acc && c && n && z && rptc,
            "canonical final state is incomplete at " + instruction.getMinAddress());

        Instruction rpt = instruction.getPrevious();
        require(rpt != null && rpt.getMnemonicString().equalsIgnoreCase("RPT") &&
                scalar(rpt, 0) == 31,
            "canonical site lost exact RPT #31 at " + instruction.getMinAddress());
    }

    private void requireOrdinaryPcode(Instruction instruction) {
        require(!canonical(instruction),
            "near miss was canonicalized at " + instruction.getMinAddress());
        require(!hasPcode(instruction, PcodeOp.INT_DIV) &&
                !hasPcode(instruction, PcodeOp.INT_REM),
            "near miss gained unsound division P-Code at " +
                instruction.getMinAddress());
        require(hasPcode(instruction, PcodeOp.INT_CARRY) &&
                hasPcode(instruction, PcodeOp.INT_LESSEQUAL),
            "near miss lost ordinary restoring SUBCUL data flow at " +
                instruction.getMinAddress());
        require(hasPcode(instruction, PcodeOp.CBRANCH) &&
                hasPcode(instruction, PcodeOp.BRANCH),
            "near miss lost ordinary RPT repeat flow at " +
                instruction.getMinAddress());
    }

    private long scalar(Instruction instruction, int operand) {
        for (Object object : instruction.getOpObjects(operand)) {
            if (object instanceof Scalar scalar) {
                return scalar.getUnsignedValue();
            }
        }
        return -1;
    }

    private String decompile(Function function) {
        DecompInterface decompiler = new DecompInterface();
        require(decompiler.openProgram(currentProgram), "failed to open decompiler");
        DecompileResults results = decompiler.decompileFunction(function, 45, monitor);
        decompiler.dispose();
        require(results.decompileCompleted() && results.getDecompiledFunction() != null,
            "decompile failed for " + function.getName() + ": " +
                results.getErrorMessage());
        String c = results.getDecompiledFunction().getC();
        require(!c.contains("CARRY4") && !c.contains("while( true )") &&
                !c.contains("while (true)"),
            "restoring division leaked into C for " + function.getName() + "\n" + c);
        return c;
    }

    private void testCompilerFixture(String optimization) {
        int sites = 0;
        for (String name : COMPILER_FUNCTIONS) {
            Function function = function(name);
            List<Instruction> divisionSites = subculs(function);
            require(!divisionSites.isEmpty(), "compiler function lost SUBCUL: " + name);
            for (Instruction site : divisionSites) {
                require(canonical(site), "compiler division was not canonicalized: " +
                    name + " at " + site.getMinAddress());
                requireCanonicalPcode(site);
                sites++;
            }
            String c = decompile(function);
            if (name.equals("div32_const10")) {
                require(c.contains(" / 10"), "constant quotient not recovered\n" + c);
            }
            else if (name.equals("mod32_const10")) {
                require(c.contains(" % 10"), "constant remainder not recovered\n" + c);
            }
            else if (name.equals("div32_variable_nonzero")) {
                require(c.contains(" / ") && c.contains("| 1"),
                    "variable nonzero quotient not recovered\n" + c);
            }
            else {
                require(c.contains(" / ") && c.contains(" % ") && c.contains("| 1"),
                    "variable quotient/remainder not recovered\n" + c);
            }
        }
        require(sites == 5, "expected five compiler SUBCUL divisions, got " + sites);
        require(totalCanonicalSites() == 5,
            "only the five compiler divisions may be canonical");
        println("DIVISION_COMPILER_OPTIMIZATION=" + optimization);
        println("DIVISION_COMPILER_CANONICAL_SITES=" + sites);
        println("DIVISION_COMPILER_CONSTANT_NONZERO=PASS");
        println("DIVISION_COMPILER_VARIABLE_NONZERO=PASS");
        println("DIVISION_COMPILER_DECOMPILATION=PASS");
    }

    private void testValidationFixture() {
        int positive = 0;
        for (String name : POSITIVE_FUNCTIONS) {
            List<Instruction> sites = subculs(function(name));
            require(sites.size() == 1, "positive fixture lost one SUBCUL: " + name);
            Instruction site = sites.get(0);
            require(canonical(site), "positive fixture was not canonicalized: " + name);
            requireCanonicalPcode(site);
            String c = decompile(function(name));
            require(c.contains(" / "), "positive fixture did not expose division\n" + c);
            positive++;
        }

        for (String name : REJECTED_FUNCTIONS) {
            List<Instruction> sites = subculs(function(name));
            require(sites.size() == 1, "near miss lost one SUBCUL: " + name);
            requireOrdinaryPcode(sites.get(0));
        }
        require(totalCanonicalSites() == positive,
            "a validation near miss was canonicalized");

        Instruction count = subculs(function("division_near_repeat_count")).get(0);
        require(scalar(count.getPrevious(), 0) == 30,
            "repeat-count near miss no longer uses RPT #30");
        require(hasMnemonic(function("division_near_mutated_divisor"), "MOVB", "AR6"),
            "mutated-divisor near miss no longer writes AR6");
        Instruction alias = subculs(function("division_near_memory_alias")).get(0);
        require(!OperandType.isRegister(alias.getOperandType(1)),
            "alias near miss no longer uses a memory divisor");
        require(hasMnemonic(function("division_near_intervening_flow"), "SB", null),
            "intervening-flow near miss no longer branches");
        Instruction alternate =
            subculs(function("division_near_alternate_ingress")).get(0).getPrevious();
        require(hasExternalFlowReference(alternate.getMinAddress(),
                function("division_near_alternate_ingress").getEntryPoint()),
            "alternate-ingress near miss lost its external branch");
        require(!hasMnemonic(function("division_near_missing_dividend"), "MOVL", "P"),
            "missing-dividend near miss regained a P snapshot");

        println("DIVISION_MANUAL_POSITIVE_SITES=" + positive);
        println("DIVISION_NEAR_MISS_REPEAT_COUNT=REJECTED");
        println("DIVISION_NEAR_MISS_INITIAL_ACC=REJECTED");
        println("DIVISION_NEAR_MISS_ZERO_DIVISOR=REJECTED");
        println("DIVISION_NEAR_MISS_UNKNOWN_DIVISOR=REJECTED");
        println("DIVISION_NEAR_MISS_MUTATED_DIVISOR=REJECTED");
        println("DIVISION_NEAR_MISS_MEMORY_ALIAS=REJECTED");
        println("DIVISION_NEAR_MISS_INTERVENING_FLOW=REJECTED");
        println("DIVISION_NEAR_MISS_ALTERNATE_INGRESS=REJECTED");
        println("DIVISION_NEAR_MISS_MISSING_DIVIDEND=REJECTED");
        println("DIVISION_NEAR_MISS_REJECTED=" + REJECTED_FUNCTIONS.length);
        println("DIVISION_ORDINARY_RPT_SUBCUL=PASS");
    }

    private boolean hasMnemonic(Function function, String mnemonic, String destination) {
        for (Instruction instruction : instructions(function)) {
            if (!instruction.getMnemonicString().equalsIgnoreCase(mnemonic)) {
                continue;
            }
            if (destination == null) {
                return true;
            }
            Register register = instruction.getRegister(0);
            if (register != null && register.getName().equalsIgnoreCase(destination)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasExternalFlowReference(Address target, Address allowedEntry) {
        ReferenceIterator references =
            currentProgram.getReferenceManager().getReferencesTo(target);
        while (references.hasNext()) {
            Reference reference = references.next();
            if (!reference.getReferenceType().isFlow()) {
                continue;
            }
            Function source = currentProgram.getFunctionManager()
                .getFunctionContaining(reference.getFromAddress());
            if (source == null || !source.getEntryPoint().equals(allowedEntry)) {
                return true;
            }
        }
        return false;
    }

    private int totalCanonicalSites() {
        int result = 0;
        InstructionIterator iterator = currentProgram.getListing().getInstructions(true);
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            if (instruction.getMnemonicString().equalsIgnoreCase("SUBCUL") &&
                canonical(instruction)) {
                result++;
            }
        }
        return result;
    }
}
