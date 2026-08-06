import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class SwitchTest extends GhidraScript {
    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    @Override
    public void run() throws Exception {
        AddressIterator entryPoints =
            currentProgram.getSymbolTable().getExternalEntryPointIterator();
        require(entryPoints.hasNext(), "expected an ELF entry point");
        Address entryPoint = entryPoints.next();
        Function function = getFunctionAt(entryPoint);
        require(function != null, "expected a function at ELF entry point " + entryPoint);

        ReferenceManager references = currentProgram.getReferenceManager();
        List<Integer> destinationCounts = new ArrayList<>();
        // Before recovery, the indirect dispatches and case blocks need not yet
        // belong to the conservatively discovered function body.
        InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            if (!instruction.getMnemonicString().equalsIgnoreCase("LB") ||
                    !instruction.getFlowType().isJump() ||
                    !instruction.getFlowType().isComputed()) {
                continue;
            }

            int count = 0;
            for (Reference reference : references.getReferencesFrom(instruction.getAddress(),
                    Reference.MNEMONIC)) {
                if (reference.getReferenceType() == RefType.COMPUTED_JUMP) {
                    count++;
                }
            }
            destinationCounts.add(count);
        }

        Collections.sort(destinationCounts);
        require(destinationCounts.equals(List.of(14, 22)),
                "expected 14- and 22-entry computed jumps, got " + destinationCounts);

        DecompInterface decompiler = new DecompInterface();
        require(decompiler.openProgram(currentProgram), "failed to open decompiler");
        DecompileResults results = decompiler.decompileFunction(function, 30, monitor);
        decompiler.dispose();
        require(results.decompileCompleted(),
                "decompile failed: " + results.getErrorMessage());

        String c = results.getDecompiledFunction().getC();
        require(!c.contains("Could not recover jumptable"),
                "decompiler still reports an unrecovered jump table");
        require(c.contains("case 0x1ae:") && c.contains("case 0x1c3:") &&
                c.contains("case 0x1e0:") && c.contains("case 0x1ed:"),
                "decompiler did not preserve both original selector ranges\n" + c);
    }
}
