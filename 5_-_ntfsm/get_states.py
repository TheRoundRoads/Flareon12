import time
import json
jump_table = 0x140C687B8

def get_branch_start(idx):
    offset = int.from_bytes(ida_bytes.get_bytes(jump_table + 4*idx, 4), "little")
    
    return 0x140000000 + offset

def get_new_state(start_ea):
    # go to jump
    instr = idc.generate_disasm_line(start_ea, idc.GENDSM_FORCE_CODE)
    
    jmp_addr = int(instr.split("loc_")[1], 16)
    instr = idc.generate_disasm_line(jmp_addr, idc.GENDSM_FORCE_CODE)
    assert "mov" in instr and "rsp" in instr
    
    new_state = int(instr.split("], ")[1].split("h")[0], 16)
    
    inc = False
    for _ in range(3):
        if "inc" in instr:
            inc = True
            break
        jmp_addr = idc.next_head(jmp_addr)
        instr = idc.generate_disasm_line(jmp_addr, idc.GENDSM_FORCE_CODE)
    
    assert inc
    
    return new_state

def get_instructions(start_ea):
    possible = {}
    cur_addr = start_ea
    while cur_addr < start_ea + 0x100:
        instr = idc.generate_disasm_line(cur_addr, idc.GENDSM_FORCE_CODE)
        
        # end
        if "jmp" in instr:
            break
            
        # comparison
        if "cmp" in instr and "rsp" in instr:
            target = int(instr.split("],")[1].split("h")[0], 16)
            
            cur_addr = idc.next_head(cur_addr)
            # get new state
            possible[target] = get_new_state(cur_addr)
        
        cur_addr = idc.next_head(cur_addr)

    return possible
    
    
def main():
    branches = {}
    for i in range(90781):
        print(f"Processing branch {i}")
        branch = get_branch_start(i)
        branches[i] = get_instructions(branch)
    
    with open(f"out.json", "w") as outfile:
        outfile.write(json.dumps(branches))
    print("Done!")
    
    return
main()