from unicorn import *
from unicorn.x86_const import *


def read_data(file_path):
    with open(file_path, "rb") as infile:
        return infile.read()

pe_data = read_data('ch38.bin')

uc = Uc(UC_ARCH_X86, UC_MODE_64)


BASE = 0x400000
stack_addr = 0x4000000
stack_size = 1024*1024

hook_addr = 0x401F21


uc.mem_map(BASE, 1024*1024)
uc.mem_map(stack_addr, stack_size)
uc.mem_write(stack_addr, b'\x00' * stack_size)
uc.mem_write(BASE, pe_data)

uc.reg_write(UC_X86_REG_RSP, stack_addr + int(stack_size / 2))


entry_point = 0x4013D2
FN_end = 0x40202A


def bytes_into_arr(arr):
    return [int(x) for x in arr]

def arr_into_bytes(arr):
    return bytes(arr)


def hook_code(uc, address, size, user_data):
    #print(f"Tracing instruction at 0x{address:x}")
    if address == hook_addr:
        print("Hooking at 0x401F21")
        rbp = uc.reg_read(UC_X86_REG_RBP)
        data_arr1 = uc.mem_read(rbp - 0x250, 512)
        print(f"RBP: {hex(rbp)}")
        #data_arr.decode('utf-8')
        print(bytes_into_arr(data_arr1))
        data_arr0 = uc.mem_read(rbp - 0x48, 8)
        print(bytes_into_arr(data_arr0))
    if address == 0x4019EB:
        rbp = uc.reg_read(UC_X86_REG_RBP)
        flag = uc.mem_read(rbp - 0x1, 4)
        buf = uc.mem_read(rbp - 0x40, 8)
        print(f"Buf_bytes: {buf}")
        print(f"Buf: {bytes_into_arr(buf)}")
        print(f"Flag: {int.from_bytes(flag, 'little')}")

def hook_syscall(uc, user_data):
    rax = uc.reg_read(UC_X86_REG_RAX)
    rbp = uc.reg_read(UC_X86_REG_RBP)
    if rax == 0:
        print("Hooking syscall read")
        uc.mem_write(rbp - 0x40, arr_into_bytes([195, 219, 60, 126, 126, 60, 219, 195]))
    if rax == 1:
        print("Hooking syscall write")
        print((uc.mem_read(rbp - 0x20, 32)))

uc.hook_add(UC_HOOK_CODE, hook_code)
uc.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)

try:
    uc.emu_start(entry_point | 1, FN_end) 
except Exception as e:
    print(e)