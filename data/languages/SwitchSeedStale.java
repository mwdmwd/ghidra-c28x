//@category TMS320C28

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import java.math.BigInteger;
import java.util.ArrayList;

/** Seeds a stale analyzer-owned saved-selector switch conclusion before analysis. */
public class SwitchSeedStale extends GhidraScript {
    private static final String OWNER = "tms320c28_switch_analyzer_owned";
    private static final long FUNCTION = 0x1709f;
    private static final long ADD = 0x170aa;
    private static final long BRANCH = 0x170ae;
    private static final long[] TARGETS = { 0x170b1, 0x170b3, 0x170b5 };

    @Override
    public void run() throws Exception {
        Register context = currentProgram.getProgramContext()
            .getRegister("switch_canonical");
        require(context != null, "missing switch_canonical context register");

        // Seed the two conclusions an earlier, over-broad matcher would have
        // selected for this save/reload-mismatch schedule.
        ProgramContext programContext = currentProgram.getProgramContext();
        programContext.setValue(context, wordAddress(ADD), wordAddress(ADD).add(3),
            BigInteger.ONE);
        programContext.setValue(context, wordAddress(BRANCH), wordAddress(BRANCH).add(1),
            BigInteger.ONE);

        require(disassemble(wordAddress(FUNCTION)), "could not disassemble stale function");
        for (long target : TARGETS) {
            require(disassemble(wordAddress(target)),
                "could not disassemble stale target " + wordAddress(target));
        }
        Function function = getFunctionAt(wordAddress(FUNCTION));
        if (function == null) {
            function = createFunction(wordAddress(FUNCTION), null);
        }
        require(function != null, "could not create stale switch function");

        ArrayList<Address> targets = new ArrayList<>();
        for (long targetWord : TARGETS) {
            Address target = wordAddress(targetWord);
            targets.add(target);
            currentProgram.getReferenceManager().addMemoryReference(wordAddress(BRANCH), target,
                RefType.COMPUTED_JUMP, SourceType.ANALYSIS, Reference.MNEMONIC);
        }
        JumpTable table = new JumpTable(wordAddress(BRANCH), targets, true, 0);
        table.writeOverride(function);
        Namespace override = HighFunction.findOverrideSpace(function);
        require(override != null, "missing stale override namespace");
        Namespace namespace = HighFunction.findNamespace(currentProgram.getSymbolTable(), override,
            "jmp_" + wordAddress(BRANCH));
        require(namespace != null, "missing stale jump namespace");
        HighFunction.createLabelSymbol(currentProgram.getSymbolTable(), wordAddress(BRANCH), OWNER,
            namespace, SourceType.ANALYSIS, false);
        CreateFunctionCmd.fixupFunctionBody(currentProgram, function, monitor);
        for (long target : TARGETS) {
            require(function.getBody().contains(wordAddress(target)),
                "stale target did not enter seeded body " + wordAddress(target));
        }
        println("SWITCH_STALE_OWNERSHIP_SEEDED=" + wordAddress(BRANCH));
        println("SWITCH_STALE_DESCRIPTOR_SEEDED=" + wordAddress(BRANCH));
    }

    private Address wordAddress(long wordOffset) {
        int wordSize = currentProgram.getAddressFactory().getDefaultAddressSpace()
            .getAddressableUnitSize();
        return currentProgram.getAddressFactory().getDefaultAddressSpace()
            .getAddress(wordOffset * wordSize);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
