#!/usr/bin/env python3
"""Build and audit focused TI EABI RPC call/return fixtures."""
from __future__ import annotations
import argparse, os, shutil, subprocess, sys
import xml.etree.ElementTree as ET
from pathlib import Path
COMMON=("--float_support=fpu32","--abi=eabi")

def run(cmd:list[str],cwd:Path,out:Path|None=None)->None:
    if out is None: p=subprocess.run(cmd,cwd=cwd,check=False)
    else:
        with out.open("w",encoding="utf-8") as f:
            p=subprocess.run(cmd,cwd=cwd,stdout=f,stderr=subprocess.STDOUT,check=False)
    if p.returncode:
        if out and out.exists(): sys.stderr.write(out.read_text(errors="replace"))
        raise RuntimeError(f"command failed ({p.returncode}): {' '.join(cmd)}")

def check_cspec(root: Path) -> None:
    tree = ET.parse(root / "tms320c28.cspec")
    protos = list(tree.findall("./default_proto/prototype")) + list(tree.findall("./prototype"))
    by_name = {proto.get("name"): proto for proto in protos}
    for name in ("__stdcall", "__lc", "__ffc"):
        proto = by_name.get(name)
        if proto is None:
            raise RuntimeError(f"missing compiler prototype {name}")
        registers = [node.get("name") for node in proto.findall("./input/pentry/register")]
        for register in ("XAR4", "XAR5"):
            if registers.count(register) != 2:
                raise RuntimeError(
                    f"{name} must expose {register} once as a pointer pool and once "
                    f"as a general fallback, got {registers.count(register)}"
                )
    print("RPC_ABI_GENERAL_REGISTER_FALLBACKS=PASS")


def build(root:Path,out:Path,cc:Path,dis:Path)->list[Path]:
    shutil.rmtree(out,ignore_errors=True); out.mkdir(parents=True)
    subjects=[]
    for opt in ("o0","o2"):
        obj=out/f"rpc_abi_{opt}.obj"; linked=out/f"rpc_abi_{opt}.linked.out"
        run([str(cc),*COMMON,"--c11",f"-{opt.upper()}","--symdebug:none","--compile_only",f"--output_file={obj}",str(root/'rpc_abi_test.c')],root)
        run([str(cc),*COMMON,"--run_linker","--entry_point=rpc_fixture_entry",f"--output_file={linked}",str(obj),str(root/'rpc_abi_test.cmd')],root)
        listing=out/f"rpc_abi_{opt}.dis.txt"; run([str(dis),str(linked)],root,listing)
        text=listing.read_text(errors="replace")
        for marker in ("LCR","LRETR","rpc_stack_args","rpc_stack_caller",
                       "rpc_branch_rejoin","rpc_void_a","rpc_void_b","rpc_void_c"):
            if marker not in text: raise RuntimeError(f"{opt} disassembly lost {marker}")
        if "LCR          *XAR" not in text: raise RuntimeError(f"{opt} lost indirect LCR")
        subjects.append(linked)
    obj=out/'rpc_flow_validation.obj'; linked=out/'rpc_flow_validation.linked.out'
    run([str(cc),*COMMON,"--compile_only",f"--output_file={obj}",str(root/'rpc_flow_validation.asm')],root)
    run([str(cc),*COMMON,"--run_linker","--entry_point=rpc_flow_entry",f"--output_file={linked}",str(obj),str(root/'rpc_flow_validation.cmd')],root)
    listing=out/'rpc_flow_validation.dis.txt'; run([str(dis),str(linked)],root,listing)
    text=listing.read_text(errors="replace")
    for marker in ("LC           *XAR7","LCR          *XAR0","LRET","LRETE","LRETR","IRET"):
        if marker not in text: raise RuntimeError(f"flow disassembly lost {marker}")
    subjects.append(linked)
    return subjects

def headless(root:Path,work:Path,ghidra:Path,subject:Path,index:int)->str:
    run_dir=work/f"{index}-{subject.stem}"; shutil.rmtree(run_dir,ignore_errors=True)
    for n in ("home","config","project","tmp","cache","scripts"): (run_dir/n).mkdir(parents=True,exist_ok=True)
    shutil.copy2(root/'RpcAbiTest.java',run_dir/'scripts'/'RpcAbiTest.java')
    cmd=["timeout","--signal=TERM","--kill-after=5s","150s",str(ghidra),str(run_dir/'project'),"rpc-abi-test","-import",str(subject),"-processor","tms320c28:LE:32:default","-cspec","default","-scriptPath",str(run_dir/'scripts'),"-postScript",str(run_dir/'scripts'/'RpcAbiTest.java'),"-log",str(run_dir/'ghidra.log'),"-scriptlog",str(run_dir/'script.log'),"-analysisTimeoutPerFile","90","-overwrite","-deleteProject"]
    env=os.environ.copy(); env.update({"HOME":str(run_dir/'home'),"XDG_CONFIG_HOME":str(run_dir/'config'),"GHIDRA_HEADLESS_JAVA_OPTIONS":f"-Dapplication.tempdir={run_dir/'tmp'} -Dapplication.cachedir={run_dir/'cache'} -Djava.io.tmpdir={run_dir/'tmp'}"})
    with (run_dir/'console.log').open('w',encoding='utf-8') as f: p=subprocess.run(cmd,cwd=root,env=env,stdout=f,stderr=subprocess.STDOUT,check=False)
    script=(run_dir/'script.log').read_text(errors='replace') if (run_dir/'script.log').exists() else ''
    if p.returncode or script.count('RPC_ABI_PROGRAM_PASS=')!=1:
        sys.stderr.write((run_dir/'console.log').read_text(errors='replace')); sys.stderr.write(script)
        raise RuntimeError(f"headless failed for {subject.name}")
    return '\n'.join(line.split('> ',1)[-1].strip() for line in script.splitlines() if 'RPC_ABI_' in line)

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument('--root',type=Path,required=True); ap.add_argument('--cl2000',type=Path,required=True); ap.add_argument('--dis2000',type=Path,required=True); ap.add_argument('--ghidra-headless',type=Path,required=True); ap.add_argument('--build',type=Path,required=True); ap.add_argument('--work',type=Path,required=True); a=ap.parse_args()
    root=a.root.resolve(); check_cspec(root); subjects=build(root,a.build.resolve(),a.cl2000.resolve(),a.dis2000.resolve()); shutil.rmtree(a.work.resolve(),ignore_errors=True); a.work.resolve().mkdir(parents=True)
    for i,s in enumerate(subjects,1): print(headless(root,a.work.resolve(),a.ghidra_headless.resolve(),s,i))
    print(f"RPC_ABI_GHIDRA_PROGRAMS={len(subjects)}"); print("RPC_ABI_TEST_PASS=all"); return 0
if __name__=='__main__': raise SystemExit(main())
