import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.util.List;

public class Decompile extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            throw new RuntimeException("failed to open program in decompiler");
        }

        String[] names = {
            "abi_scale_sum",
            "abi_make_pair",
            "abi_dot4",
        };

        int count = 0;
        for (String name : names) {
            List<Function> functions = getGlobalFunctions(name);
            if (functions.isEmpty()) {
                throw new RuntimeException("missing function " + name);
            }
            Function function = functions.get(0);
            println("### " + function.getName() + " " + function.getEntryPoint());
            DecompileResults results = decompiler.decompileFunction(function, 30, monitor);
            if (!results.decompileCompleted()) {
                throw new RuntimeException("decompile failed for " + function.getName() + ": "
                    + results.getErrorMessage());
            }
            println(results.getDecompiledFunction().getC());
            count++;
        }

        decompiler.dispose();

        if (count == 0) {
            throw new RuntimeException("no functions found to decompile");
        }
        println("DECOMPILED_FUNCTIONS=" + count);
    }
}
