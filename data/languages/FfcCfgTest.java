// Bounded, image-independent FFC control-flow and lifecycle regression.
// The instruction words are checked against TI dis2000 in ffc_cfg_encodings.asm.
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.TMS320C28FfcReturnAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.*;
import java.math.BigInteger;
import java.util.*;

public class FfcCfgTest extends GhidraScript {
    private long nextBase = 0x30000;
    private int cases;
    private Register tag;
    private static void check(boolean b, String message) {
        if (!b) throw new AssertionError(message);
    }
    private Address a(long word) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(word * 2);
    }
    private void words(long word, int... values) throws Exception {
        byte[] bytes = new byte[values.length * 2];
        for (int i=0; i<values.length; ++i) {
            bytes[2*i]=(byte)values[i]; bytes[2*i+1]=(byte)(values[i] >>> 8);
        }
        currentProgram.getMemory().setBytes(a(word), bytes);
    }
    private long fixture(String name, int... body) throws Exception {
        long base=nextBase; nextBase+=0x200;
        var block=currentProgram.getMemory().createInitializedBlock(name, a(base), 0x200,
            (byte)0, monitor, false);
        block.setExecute(true);
        long entry=base+0x10;
        words(base, 0x00c0 | (int)(entry >>> 16), (int)entry & 0xffff, 0x0006);
        words(entry, body);
        return base;
    }
    private void decode(long word) throws Exception {
        check(disassemble(a(word)), "decode failed at " + a(word));
        Instruction i=getInstructionAt(a(word));
        if (i.getMnemonicString().equalsIgnoreCase("ffc") ||
            i.getMnemonicString().equalsIgnoreCase("lcr")) {
            // The normal reference analyzer resolves the register-backed CALL
            // P-Code. Seed that prerequisite from the actual instruction words,
            // not a guessed function entry, with other analyzers disabled here.
            int first=currentProgram.getMemory().getShort(a(word)) & 0xffff;
            int second=currentProgram.getMemory().getShort(a(word+1)) & 0xffff;
            long target=((long)(first & 0x3f)<<16)|second;
            int operand=i.getMnemonicString().equalsIgnoreCase("ffc") ? 1 : 0;
            currentProgram.getReferenceManager().addMemoryReference(a(word),a(target),
                RefType.COMPUTED_CALL,SourceType.DEFAULT,operand);
            check(disassemble(a(target)),"callee decode failed");
        }
    }
    private void analyze() throws Exception {
        MessageLog log=new MessageLog();
        check(new TMS320C28FfcReturnAnalyzer().added(currentProgram,
            new AddressSet(currentProgram.getMemory()), monitor, log), "analyzer failed: "+log);
        AutoAnalysisManager.getAnalysisManager(currentProgram).startAnalysis(monitor);
    }
    private boolean tagged(long word) {
        return BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(tag,a(word),false));
    }
    private void expect(String name, boolean expected, long base, int... offsets) throws Exception {
        decode(base);
        analyze();
        for (int off:offsets) {
            long word=base+off;
            check(tagged(word)==expected,name+" context at "+a(word)+" expected="+expected);
            Instruction ins=getInstructionAt(a(word));
            check(ins!=null,name+" missing terminal");
            boolean ret=false, branch=false;
            for (PcodeOp op:ins.getPcode()) { ret|=op.getOpcode()==PcodeOp.RETURN;
                branch|=op.getOpcode()==PcodeOp.BRANCHIND; }
            check(expected ? ret&&!branch : branch&&!ret, name+" wrong raw P-Code at "+a(word));
        }
        cases++; println("FFC_CFG_CASE_PASS="+name);
    }
    private void replace(long word, int value) throws Exception {
        Instruction i=getInstructionAt(a(word));
        currentProgram.getListing().clearCodeUnits(a(word),i.getMaxAddress(),false);
        words(word,value); decode(word);
    }
    @Override public void run() throws Exception {
        // Only the analyzer under test is invoked. Its queued redisassembly still
        // runs, but unrelated auto-analyzers cannot repair away seeded negatives.
        Options opts=currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        for (String name:opts.getOptionNames()) {
            Object value=opts.getObject(name,null);
            if (value instanceof Boolean) opts.setBoolean(name,false);
        }
        tag=currentProgram.getProgramContext().getRegister("ffc_return");
        check(tag!=null,"missing context");
        long b=fixture("two_exits",0x6003,0x9a01,0x7620,0x9a02,0x7620);
        expect("two-exits",true,b,0x12,0x14);
        long lifecycle=b;
        b=fixture("rejoin",0x6003,0x9a01,0x6f02,0x9a02,0x7620);
        expect("rejoin",true,b,0x14);
        b=fixture("loop",0x7700,0x6003,0x7700,0x6ffe,0x7620);
        expect("closed-internal-loop",true,b,0x14);
        b=fixture("discontiguous",0x6f10); words(b+0x20,0x9a01,0x7620);
        expect("discontiguous-body",true,b,0x21);
        int[] limit=new int[128]; Arrays.fill(limit,0x7700); limit[127]=0x7620;
        b=fixture("limit128",limit); expect("128-distinct-instructions",true,b,0x8f);
        limit=new int[129]; Arrays.fill(limit,0x7700); limit[128]=0x7620;
        b=fixture("limit129",limit); expect("129-distinct-instructions",false,b,0x90);
        b=fixture("clobber",0x6003,0x9a01,0x7620,0xb600,0x7620);
        expect("clobber-one-arm",false,b,0x12,0x14);
        b=fixture("partial",0x6003,0x9a01,0x7620,0x28a7,0x0001,0x7620);
        expect("partial-AR7-write",false,b,0x12,0x15);
        b=fixture("postincrement",0x6003,0x9a01,0x7620,0xc487,0x7620);
        expect("implicit-XAR7-postincrement",false,b,0x12,0x14);
        b=fixture("nestedcall",0x6003,0x9a01,0x7620,0x7643,(int)((nextBase-0x200+0x30)&0xffff),0x7620);
        words(b+0x30,0x0006); expect("call-one-arm",false,b,0x12,0x15);
        b=fixture("otherterminal",0x6003,0x9a01,0x7620,0x0006);
        expect("non-FFC-terminal",false,b,0x12);
        b=fixture("computed",0x6003,0x9a01,0x7620,0x5614);
        expect("computed-successor",false,b,0x12);
        b=fixture("mixed",0x7700,0x7620);
        words(b+0x30,0x7643,(int)((b+0x10)&0xffff),0x0006); decode(b+0x30);
        expect("mixed-FFC-LCR-entry",false,b,0x11);
        b=fixture("entryfall",0x7700,0x7620); words(b+0xf,0x7700); decode(b+0xf);
        expect("entry-fallthrough",false,b,0x11);
        b=fixture("interiorbranch",0x7700,0x7620);
        words(b+0x30,0x6fe1); decode(b+0x30);
        expect("external-interior-branch",false,b,0x11);
        b=fixture("interiorfall",0x6f10); words(b+0x1f,0x7700,0x9a01,0x7620); decode(b+0x1f);
        expect("external-interior-fallthrough",false,b,0x21);
        b=fixture("noffc",0x7700,0x7620); words(b,0x7643,(int)((b+0x10)&0xffff),0x0006);
        expect("no-FFC-provenance",false,b,0x11);
        b=fixture("missingtarget",0x6003,0x7620,0x7700,0x7620); decode(b);
        currentProgram.getListing().clearCodeUnits(a(b+0x13),a(b+0x13),false);
        analyze(); check(!tagged(b+0x11),"missing successor accepted"); cases++;
        println("FFC_CFG_CASE_PASS=missing-successor");
        b=fixture("noexit",0x7700,0x6f00); decode(b); analyze();
        check(!tagged(b+0x11),"no-return cycle accepted"); cases++;
        println("FFC_CFG_CASE_PASS=no-return-cycle");
        b=fixture("switchowned",0x7700,0x7620); decode(b);
        currentProgram.getListing().clearCodeUnits(a(b+0x11),a(b+0x11),false);
        currentProgram.getProgramContext().setValue(currentProgram.getRegister("switch_canonical"),
            a(b+0x11),a(b+0x11),BigInteger.ONE);
        decode(b+0x11); analyze(); check(!tagged(b+0x11),"switch ownership ignored"); cases++;
        println("FFC_CFG_CASE_PASS=switch-owned-exit");
        b=fixture("overridden",0x6003,0x9a01,0x7620,0x9a02,0x7620); decode(b);
        getInstructionAt(a(b+0x10)).setFallThrough(null);
        analyze(); check(!tagged(b+0x12)&&!tagged(b+0x14),"overridden fallthrough accepted"); cases++;
        println("FFC_CFG_CASE_PASS=fallthrough-override");

        // Both exits are revoked when *any* reachable arm loses XAR7 provenance.
        replace(lifecycle+0x13,0xb600); analyze();
        check(!tagged(lifecycle+0x12)&&!tagged(lifecycle+0x14),"partial revocation");
        replace(lifecycle+0x13,0x9a02); analyze();
        check(tagged(lifecycle+0x12)&&tagged(lifecycle+0x14),"failed republication");
        cases++; println("FFC_CFG_CASE_PASS=clobber-revoke-republish");
        var rm=currentProgram.getReferenceManager();
        Reference r=rm.getReference(a(lifecycle),a(lifecycle+0x10),1);
        check(r!=null,"missing FFC caller reference"); rm.delete(r); analyze();
        check(!tagged(lifecycle+0x12)&&!tagged(lifecycle+0x14),"missing caller not revoked");
        rm.addMemoryReference(a(lifecycle),a(lifecycle+0x10),RefType.UNCONDITIONAL_CALL,SourceType.DEFAULT,1);
        analyze(); check(tagged(lifecycle+0x12)&&tagged(lifecycle+0x14),"caller repair not republished");
        cases++; println("FFC_CFG_CASE_PASS=caller-revoke-republish");
        analyze(); check(tagged(lifecycle+0x12)&&tagged(lifecycle+0x14),"repeat pass changed proof");
        cases++; println("FFC_CFG_CASE_PASS=idempotent");
        // References belong to the user, not to this proof's lifetime.
        Address manualTarget=a(lifecycle+0x40);
        rm.addMemoryReference(a(lifecycle+0x12),manualTarget,RefType.COMPUTED_JUMP,
            SourceType.USER_DEFINED,0);
        rm.setPrimary(rm.getReference(a(lifecycle+0x12),manualTarget,0),true);
        replace(lifecycle+0x13,0xb600); analyze();
        Reference manual=rm.getReference(a(lifecycle+0x12),manualTarget,0);
        check(manual!=null && manual.getSource()==SourceType.USER_DEFINED && manual.isPrimary(),
            "manual reference lost on revocation");
        replace(lifecycle+0x13,0x9a02); analyze();
        manual=rm.getReference(a(lifecycle+0x12),manualTarget,0);
        check(tagged(lifecycle+0x12) && manual!=null && manual.isPrimary(),
            "manual reference lost on republication");
        cases++; println("FFC_CFG_CASE_PASS=user-reference-preservation");
        getInstructionAt(a(lifecycle+0x12)).setFlowOverride(FlowOverride.BRANCH);
        analyze();
        check(!tagged(lifecycle+0x12)&&!tagged(lifecycle+0x14),"flow override not revoked");
        check(getInstructionAt(a(lifecycle+0x12)).getFlowOverride()==FlowOverride.BRANCH,
            "flow override discarded on revocation");
        getInstructionAt(a(lifecycle+0x12)).setFlowOverride(FlowOverride.NONE); analyze();
        check(tagged(lifecycle+0x12)&&tagged(lifecycle+0x14),"flow-override repair not republished");
        cases++; println("FFC_CFG_CASE_PASS=flow-override-preservation");
        getInstructionAt(a(lifecycle+0x12)).setFallThrough(a(lifecycle+0x13)); analyze();
        check(!tagged(lifecycle+0x12)&&!tagged(lifecycle+0x14),"exit fallthrough override not revoked");
        check(getInstructionAt(a(lifecycle+0x12)).isFallThroughOverridden() &&
            a(lifecycle+0x13).equals(getInstructionAt(a(lifecycle+0x12)).getFallThrough()),
            "exit fallthrough override discarded");
        getInstructionAt(a(lifecycle+0x12)).clearFallThroughOverride(); analyze();
        check(tagged(lifecycle+0x12)&&tagged(lifecycle+0x14),"fallthrough repair not republished");
        cases++; println("FFC_CFG_CASE_PASS=exit-fallthrough-preservation");
        println("FFC_CFG_CASES="+cases);
        println("FFC_CFG_PASS=all");
    }
}
