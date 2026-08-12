//@category TMS320C28

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

/** Seeds only the two ordinary caller-proved function entries for the layout fixture. */
public class SwitchLayoutSeed extends GhidraScript {
    private static final long[] ENTRIES = { 0x18005, 0x18021 };

    @Override
    public void run() throws Exception {
        for (long word : ENTRIES) {
            Address entry = wordAddress(word);
            require(disassemble(entry), "could not disassemble layout entry " + entry);
            Function function = getFunctionAt(entry);
            if (function == null) {
                function = createFunction(entry, null);
            }
            require(function != null,
                "could not create caller-proved layout function " + entry);
        }
        println("SWITCH_LAYOUT_FUNCTION_SEEDS=2");
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
