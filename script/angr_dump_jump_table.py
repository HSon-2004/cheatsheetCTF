import angr
import logging

logging.getLogger('angr').setLevel(logging.ERROR)

proj = angr.Project('ch38.bin', load_options={'auto_load_libs': False})

state = proj.factory.entry_state(args=['./ch38'], add_options={
    angr.options.LAZY_SOLVES,
    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
})
# Tạo CFG nhanh
cfg = proj.analyses.CFGFast(normalize=True)

# Liệt kê tất cả các hàm
for func_addr, func in cfg.kb.functions.items():
    print(f"Function at {hex(func_addr)}: {func.name}")


main_func = cfg.kb.functions.get(0x4013D2)  

for block in main_func.blocks:
    with open('ch38_disasm.txt', 'a') as f:
        f.write(f"< Block at {hex(block.addr)} >\n")
        for ins in block.capstone.insns:
            f.write(f"0x{ins.address:x}: {ins.mnemonic} {ins.op_str}\n")

        f.write("=====================================\n")

relative_block = []
relative_block_addr = []

sub_dispatcher = []
sub_dispatcher_addr = []

dispatcher_addr = [0x4013EB]
predispatcher_addr = [0x40201C]

for block in main_func.blocks:
    if block.addr == 0x4013EB:
        print(f"Dispatcher")
    elif block.addr in predispatcher_addr:
        print(f"Pre dispatcher at {hex(block.addr)}")
    elif 'cmp' in block.capstone.insns[0].mnemonic and '[rbp - 0x38]' in block.capstone.insns[0].op_str:
        print(f'sub dispatcher at {hex(block.addr)}')
        if block.addr not in sub_dispatcher_addr:
            sub_dispatcher.append(block)
            sub_dispatcher_addr.append(block.addr)
    else:
        if block.addr not in relative_block_addr:
            relative_block.append(block)
            relative_block_addr.append(block.addr)
        

for block in relative_block:
    with open('relative_func.txt', 'a') as f:
    #print(f"< Block at {hex(block.addr)} >")
        f.write(f"< Block at {hex(block.addr)} >\n")
        for ins in block.capstone.insns:
            f.write(f"0x{ins.address:x}: {ins.mnemonic} {ins.op_str}\n")
        f.write("=====================================\n")


# cfg = proj.analyses.CFGEmulated()
# cfg.kb.functions.get(0x4013D2).normalize()

print(relative_block_addr)

# hook vao simgr_run

# #print("Relative block address: ", hex(relative_block_addr))
# buf_addr = state.regs.rbp - 0x40
# def hook_simgr_run(simgr):
#     if simgr.addr == 0x401F31:
#         print("Check v20 <= 7")
#         state.memory.store(buf_addr, 0, size=8)
#         state.regs.eflags &= ~0x40
#     print(hex(simgr.addr))

# for addr in relative_block_addr:
#     proj.hook(addr, hook_simgr_run)
# simgr = proj.factory.simulation_manager(state)
# simgr.run()



