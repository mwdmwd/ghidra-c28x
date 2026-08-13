//@category TMS320C28

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.ProgramContext;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

/** Seeds stale OVM context and otherwise unreachable validation functions. */
public class StatusModeSeedStale extends GhidraScript {
    @Override
    public void run() throws Exception {
        Register context = currentProgram.getProgramContext().getRegister("ovm_zero");
        require(context != null, "missing ovm_zero context register");
        Map<String, Address> addresses = parseAddresses();

        seed(context, addresses, "status_stale_addu");
        seed(context, addresses, "status_stale_nonaddu");
        seedUncalledFunction(addresses, "status_unproved_entry");
        seedUncalledFunction(addresses, "status_stale_function");
        println("STATUS_MODE_STALE_CONTEXT_SEEDED=2");
    }

    private Map<String, Address> parseAddresses() {
        Map<String, Address> result = new HashMap<>();
        for (String argument : getScriptArgs()) {
            int equals = argument.indexOf('=');
            require(equals > 0 && equals < argument.length() - 1,
                "malformed fixture address " + argument);
            Address address = toAddr(argument.substring(equals + 1));
            require(address != null, "invalid fixture address " + argument);
            result.put(argument.substring(0, equals), address);
        }
        return result;
    }

    private void seed(Register context, Map<String, Address> addresses, String name)
            throws Exception {
        Address address = addresses.get(name);
        require(address != null, "missing stale context address " + name);
        ProgramContext programContext = currentProgram.getProgramContext();
        // Cover the maximum two-byte instruction extent before disassembly.
        programContext.setValue(context, address, address.add(1), BigInteger.ONE);
        println("STATUS_MODE_STALE_CONTEXT_SEEDED_" + name.toUpperCase() + "=" + address);
    }

    private void seedUncalledFunction(Map<String, Address> addresses, String name)
            throws Exception {
        Address address = addresses.get(name);
        require(address != null, "missing uncalled function address " + name);
        Listing listing = currentProgram.getListing();
        if (listing.getInstructionAt(address) == null) {
            require(disassemble(address), "could not disassemble uncalled function " + name);
        }
        if (listing.getFunctionAt(address) == null) {
            require(createFunction(address, null) != null,
                "could not create uncalled function " + name);
        }
        println("STATUS_MODE_UNCALLED_FUNCTION_SEEDED_" + name.toUpperCase() + "=" + address);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
