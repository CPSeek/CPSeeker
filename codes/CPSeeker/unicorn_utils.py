#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0
# @Date:   2021-08-11 08:45:53
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2021-08-11 09:45:48


from print_registers import print_x86_regs
from unicorn import *
from unicorn.mips_const import *
from unicorn.arm_const import *
from unicorn.x86_const import *

from collections import OrderedDict

from libc_functions import *
import networkx as nx

#unicorefuzz

INSN_WRMSR = b"\x0f\x30"

MSR_FSBASE = 0xC0000100
MSR_GSBASE = 0xC0000101

MIPS_SYSCALL_INSN = 'syscall'       #syscall num $v0, li      $v0, 0x108E
X86_SYSCALL_INSN = 'int     80h'    #syscall num eax, mov     eax, 4
ARM_SYSCALL_INSN = 'SVC     0'      #syscall num r7, MOV     R7, #5
PPC_SYSCALL_INSN = 'sc'             #syscall num r0, li        r0, 0xAE

SHORT_PATH_THRESHOLD = 2
ALL_SIMPLE_PATH_THRESHOLD = 1
MAX_BLOCK_SIZE = 50
#参数的传递
#addiu   $a0, $sp, 0x218+var_200
#opcode dst, src

# ida_get_sys_int_dict = OrderedDict([
#     ('x86', (x86_get_sys_int_value)),
#     ('x64', (x86_get_sys_int_value)),
#     ('mipsbe', (mips_get_sys_int_value)),
#     ('mipsle', (mips_get_sys_int_value)),
#     ('mips64be', (mips_get_sys_int_value)),
#     ('mips64le', (mips_get_sys_int_value)),
#     ('armbe', (arm_get_sys_int_value)),
#     ('armle', (arm_get_sys_int_value)),
#     ('arm64be', (arm_get_sys_int_value)),
#     ('arm64le', (arm_get_sys_int_value)),
#     ('ppcbe', (ppc_get_sys_int_value)),
#     ('ppcle', (ppc_get_sys_int_value)),
#     ('ppc64be', (ppc_get_sys_int_value)),
#     ('ppc64le', (ppc_get_sys_int_value))
# ])
ida_get_sys_int_dict = OrderedDict([
])

ida_sys_int_dict = OrderedDict([
    ('x86', (X86_SYSCALL_INSN)),
    ('x64', (X86_SYSCALL_INSN)),
    ('mipsbe', (MIPS_SYSCALL_INSN)),
    ('mipsle', (MIPS_SYSCALL_INSN)),
    ('mips64be', (MIPS_SYSCALL_INSN)),
    ('mips64le', (MIPS_SYSCALL_INSN)),
    ('armbe', (ARM_SYSCALL_INSN)),
    ('armle', (ARM_SYSCALL_INSN)),
    ('arm64be', (ARM_SYSCALL_INSN)),
    ('arm64le', (ARM_SYSCALL_INSN)),
    ('ppcbe', (PPC_SYSCALL_INSN)),
    ('ppcle', (PPC_SYSCALL_INSN)),
    ('ppc64be', (PPC_SYSCALL_INSN)),
    ('ppc64le', (PPC_SYSCALL_INSN))
    ])


def get_arch(proj):
    arch_name = proj.arch.name.lower()
    endness = proj.arch.memory_endness
    if arch_name == 'x64':
        return "x64"
    elif arch_name == 'x86':
        return "x86"
    elif arch_name == 'arm64':
        if 'BE' in endness:
            return "arm64be"
        else:
            return "arm64le"
    elif arch_name == 'arm':
        if 'BE' in endness:
            return "armbe"
        else:
            return "armle"
    elif arch_name == 'mips32':
        if 'BE' in endness:
            return "mipsbe"
        else:
            return "mipsle"
    elif arch_name == 'ppc32':
        if 'BE' in endness:
            return "ppcbe"
        else:
            return "ppcle"
    elif arch_name == 'arm64':
        if 'BE' in endness:
            return "arm64be"
        else:
            return "arm64le"
    elif arch_name == 'mips64':
        if 'BE' in endness:
            return "mips64be"
        else:
            return "mips64le"
    elif arch_name == 'ppc64':
        if 'BE' in endness:
            return "ppc64be"
        else:
            return "ppc64le"
    else:
        return ""

def Heads(proj, start, end):
    func = proj.kb.functions.floor_func(start)
    func_addr_list = list(func_addr_set(func))
    start_index = func_addr_list.index(start)
    end_index = func_addr_list.index(end)
    
    return func_addr_list[start_index: end_index +1]

def func_addr_set(self, func):
    func_addr_set = set()
    for block in func.blocks:
        addr_set = set(block.instruction_addrs)
        func_addr_set = func_addr_set.union(addr_set)
    return sorted(func_addr_set)

def generate_disasm_line(proj, addr):
    block = proj.factory.block(addr)
    addr_list = block.instruction_addrs
    index = addr_list.index(addr)
    return str(block.capstone.insns[index])

def get_func_loop(cfg, addr):
    func = cfg.functions.floor_func(addr)
    func_cfg = func.graph
    loop_paths = list(nx.simple_cycles(func_cfg))

    return loop_paths


def coverage_block(func_blocks, exec_blocks):

    nums = 0
    for addr in exec_blocks:
        if addr in func_blocks:
            nums += 1 
    tot = len(func_blocks)

    cover = nums / tot

    return cover

def coverage_inst(func_insts, exec_insts):
    nums = 0

    for addr in exec_insts:
        if addr in func_insts:
            nums += 1 
    tot = len(func_insts)

    cover = nums / tot

    return cover

def set_x86_msr(uc: Uc, base_addr: int, msr: int, val: int) -> None:
    """
    set the given model-specific register (MSR) to the given value.
    this will clobber some memory at the given base_addr address, as it emits some code.
    """
    # save clobbered registers
    orax = uc.reg_read(UC_X86_REG_EAX)
    ordx = uc.reg_read(UC_X86_REG_EDX)
    orcx = uc.reg_read(UC_X86_REG_ECX)
    orip = uc.reg_read(UC_X86_REG_EIP)

    # x86: wrmsr
    uc.mem_write(base_addr, INSN_WRMSR)
    uc.reg_write(UC_X86_REG_EAX, val & 0xFFFFFFFF)
    uc.reg_write(UC_X86_REG_EDX, (val >> 32) & 0xFFFFFFFF)
    uc.reg_write(UC_X86_REG_ECX, msr & 0xFFFFFFFF)
    uc.emu_start(base_addr, base_addr + len(INSN_WRMSR), count=1)

    # restore clobbered registers
    uc.reg_write(UC_X86_REG_EAX, orax)
    uc.reg_write(UC_X86_REG_EDX, ordx)
    uc.reg_write(UC_X86_REG_ECX, orcx)
    uc.reg_write(UC_X86_REG_EIP, orip)


def get_x86_msr(uc: Uc, base_addr: int, msr: int) -> int:
    """
    fetch the contents of the given model-specific register (MSR).
    this will clobber some memory at the given base_addr address, as it emits some code.
    """
    # save clobbered registers
    orax = uc.reg_read(UC_X86_REG_EAX)
    ordx = uc.reg_read(UC_X86_REG_EDX)
    orcx = uc.reg_read(UC_X86_REG_ECX)
    orip = uc.reg_read(UC_X86_REG_EIP)

    # x86: rdmsr
    buf = b"\x0f\x32"
    uc.mem_write(base_addr, buf)
    uc.reg_write(UC_X86_REG_ECX, msr & 0xFFFFFFFF)
    uc.emu_start(base_addr, base_addr + len(buf), count=1)
    eax = uc.reg_read(UC_X86_REG_EAX)
    edx = uc.reg_read(UC_X86_REG_EDX)

    res = (edx << 32) | (eax & 0xFFFFFFFF)

    # restore clobbered registers
    uc.reg_write(UC_X86_REG_EAX, orax)
    uc.reg_write(UC_X86_REG_EDX, ordx)
    uc.reg_write(UC_X86_REG_ECX, orcx)
    uc.reg_write(UC_X86_REG_EIP, orip)

    return res

def set_x64_msr(uc: Uc, base_addr: int, msr: int, val: int) -> None:
    """
    set the given model-specific register (MSR) to the given value.
    this will clobber some memory at the given base_addr address, as it emits some code.
    """
    # save clobbered registers
    orax = uc.reg_read(UC_X86_REG_RAX)
    ordx = uc.reg_read(UC_X86_REG_RDX)
    orcx = uc.reg_read(UC_X86_REG_RCX)
    orip = uc.reg_read(UC_X86_REG_RIP)

    # x86: wrmsr
    uc.mem_write(base_addr, INSN_WRMSR)
    uc.reg_write(UC_X86_REG_RAX, val & 0xFFFFFFFF)
    uc.reg_write(UC_X86_REG_RDX, (val >> 32) & 0xFFFFFFFF)
    uc.reg_write(UC_X86_REG_RCX, msr & 0xFFFFFFFF)
    uc.emu_start(base_addr, base_addr + len(INSN_WRMSR), count=1)
    # restore clobbered registers
    uc.reg_write(UC_X86_REG_RAX, orax)
    uc.reg_write(UC_X86_REG_RDX, ordx)
    uc.reg_write(UC_X86_REG_RCX, orcx)
    uc.reg_write(UC_X86_REG_RIP, orip)


def get_x64_msr(uc: Uc, base_addr: int, msr: int) -> int:
    """
    fetch the contents of the given model-specific register (MSR).
    this will clobber some memory at the given base_addr address, as it emits some code.
    """
    # save clobbered registers
    orax = uc.reg_read(UC_X86_REG_RAX)
    ordx = uc.reg_read(UC_X86_REG_RDX)
    orcx = uc.reg_read(UC_X86_REG_RCX)
    orip = uc.reg_read(UC_X86_REG_RIP)

    # x86: rdmsr
    buf = b"\x0f\x32"
    uc.mem_write(base_addr, buf)
    uc.reg_write(UC_X86_REG_RCX, msr & 0xFFFFFFFF)
    uc.emu_start(base_addr, base_addr + len(buf), count=1)
    eax = uc.reg_read(UC_X86_REG_EAX)
    edx = uc.reg_read(UC_X86_REG_EDX)

    # restore clobbered registers
    uc.reg_write(UC_X86_REG_RAX, orax)
    uc.reg_write(UC_X86_REG_RDX, ordx)
    uc.reg_write(UC_X86_REG_RCX, orcx)
    uc.reg_write(UC_X86_REG_RIP, orip)

    return (edx << 32) | (eax & 0xFFFFFFFF)



def set_gs_base(uc: Uc, base_addr: int, val: int, mode: int) -> None:
    """
    Set the GS.base hidden descriptor-register field to the given address.
    this enables referencing the gs segment on x86-64.
    """
    if mode == UC_MODE_32:
        return set_x86_msr(uc, base_addr, MSR_GSBASE, val)
    return set_x64_msr(uc, base_addr, MSR_GSBASE, val)


def get_gs_base(uc: Uc, base_addr: int, mode: int) -> int:
    """
    fetch the GS.base hidden descriptor-register field.
    """
    if mode == UC_MODE_32:
        return get_x86_msr(uc, base_addr, MSR_GSBASE)
    return get_x64_msr(uc, base_addr, MSR_GSBASE)


def set_fs_base(uc: Uc, base_addr: int, val: int, mode: int) -> None:
    """
    set the FS.base hidden descriptor-register field to the given address.
    this enables referencing the fs segment on x86-64.
    """
    if mode == UC_MODE_32:
        return set_x86_msr(uc, base_addr, MSR_FSBASE, val)
    return set_x64_msr(uc, base_addr, MSR_FSBASE, val)


def get_fs_base(uc: Uc, base_addr: int, mode: int) -> int:
    """
    fetch the FS.base hidden descriptor-register field.
    """
    if mode == UC_MODE_32:
        return get_x86_msr(uc, base_addr, MSR_FSBASE)
    return get_x64_msr(uc, base_addr, MSR_FSBASE)



# Page size required by Unicorn
UNICORN_PAGE_SIZE = 0x1000

# Max allowable segment size (1G)
MAX_ALLOWABLE_SEG_SIZE = 1024 * 1024 * 1024

# Alignment functions to align all memory segments to Unicorn page boundaries (4KB pages only)
ALIGN_PAGE_DOWN = lambda x: x & ~(UNICORN_PAGE_SIZE - 1)
ALIGN_PAGE_UP   = lambda x: (x + UNICORN_PAGE_SIZE - 1) & ~(UNICORN_PAGE_SIZE-1)


class UnicornSimpleHeap(object):
    """ Use this class to provide a simple heap implementation. This should
        be used if malloc/free calls break things during emulation. This heap also
        implements basic guard-page capabilities which enable immediate notice of
        heap overflow and underflows.
    """

    # Helper data-container used to track chunks
    class HeapChunk(object):
        def __init__(self, actual_addr, total_size, data_size):
            self.total_size = total_size                        # Total size of the chunk (including padding and guard page)
            self.actual_addr = actual_addr                      # Actual start address of the chunk
            self.data_size = data_size                          # Size requested by the caller of actual malloc call
            self.data_addr = actual_addr + UNICORN_PAGE_SIZE    # Address where data actually starts

        # Returns true if the specified buffer is completely within the chunk, else false
        def is_buffer_in_chunk(self, addr, size):
            if addr >= self.data_addr and ((addr + size) <= (self.data_addr + self.data_size)):
                return True
            else:
                return False

    # Skip the zero-page to avoid weird potential issues with segment registers
    HEAP_MIN_ADDR = 0x00002000
    HEAP_MAX_ADDR = 0xFFFFFFFF

    _uc = None              # Unicorn engine instance to interact with
    _chunks = []            # List of all known chunks
    _debug_print = False    # True to print debug information

    def __init__(self, uc, debug_print=False):
        self._uc = uc
        self._debug_print = debug_print

        # Add the watchpoint hook that will be used to implement psuedo-guard page support
        self._uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, self.__check_mem_access)

    def malloc(self, size):
        # Figure out the overall size to be allocated/mapped
        #    - Allocate at least 1 4k page of memory to make Unicorn happy
        #    - Add guard pages at the start and end of the region
        total_chunk_size = UNICORN_PAGE_SIZE + ALIGN_PAGE_UP(size) + UNICORN_PAGE_SIZE
        # Gross but efficient way to find space for the chunk:
        chunk = None
        for addr in range(self.HEAP_MIN_ADDR, self.HEAP_MAX_ADDR, UNICORN_PAGE_SIZE):
            try:
                self._uc.mem_map(addr, total_chunk_size, UC_PROT_READ | UC_PROT_WRITE)
                chunk = self.HeapChunk(addr, total_chunk_size, size)
                if self._debug_print:
                    print("Allocating 0x{0:x}-byte chunk @ 0x{1:016x}".format(chunk.data_size, chunk.data_addr))
                break
            except UcError as e:
                continue
        # Something went very wrong
        if chunk == None:
            return 0
        self._chunks.append(chunk)
        return chunk.data_addr

    def calloc(self, size, count):
        # Simple wrapper around malloc with calloc() args
        return self.malloc(size*count)

    def realloc(self, ptr, new_size):
        # Wrapper around malloc(new_size) / memcpy(new, old, old_size) / free(old)
        if self._debug_print:
            print("Reallocating chunk @ 0x{0:016x} to be 0x{1:x} bytes".format(ptr, new_size))
        old_chunk = None
        for chunk in self._chunks:
            if chunk.data_addr == ptr:
                old_chunk = chunk
        new_chunk_addr = self.malloc(new_size)
        if old_chunk != None:
            self._uc.mem_write(new_chunk_addr, str(self._uc.mem_read(old_chunk.data_addr, old_chunk.data_size)))
            self.free(old_chunk.data_addr)
        return new_chunk_addr

    def free(self, addr):
        for chunk in self._chunks:
            if chunk.is_buffer_in_chunk(addr, 1):
                if self._debug_print:
                    print("Freeing 0x{0:x}-byte chunk @ 0x{0:016x}".format(chunk.req_size, chunk.data_addr))
                self._uc.mem_unmap(chunk.actual_addr, chunk.total_size)
                self._chunks.remove(chunk)
                return True
        return False

    # Implements basic guard-page functionality
    def __check_mem_access(self, uc, access, address, size, value, user_data):
        for chunk in self._chunks:
            if address >= chunk.actual_addr and ((address + size) <= (chunk.actual_addr + chunk.total_size)):
                if chunk.is_buffer_in_chunk(address, size) == False:
                    if self._debug_print:
                        print("Heap over/underflow attempting to {0} 0x{1:x} bytes @ {2:016x}".format( \
                            "write" if access == UC_MEM_WRITE else "read", size, address))
                    # Force a memory-based crash
                    raise UcError(UC_ERR_READ_PROT)
def malloc_hook():
    addr = None

    return addr

def strcpy_hook(emu, addr, args, user_data):
    dst_addr = args[0]
    src_addr = args[1]
    if emu.debug:
        print("[+] Hooking 'strcpy' @0x%x..." % addr)
    emu.emu_copy_mem(dst_addr, src_addr)
    emu.write_reg_val(emu.ret_reg, args[0])
    if emu.debug:
        print("[+] Hooking 'strcpy' is done...")

    return None

def strncpy_hook(emu, addr, args, user_data):
    dst_addr = args[0]
    src_addr = args[1]
    copy_len = args[2]
    if emu.debug:
        print("[+] Hooking 'strncpy' @0x%x..." % addr)
    emu.emu_copy_mem_len(dst_addr, src_addr, copy_len)
    emu.write_reg_val(emu.ret_reg, args[0])
    if emu.debug:
        print("[+] Hooking 'strncpy' is done...")

def memcpy_hook(emu, addr, args, user_data):
    dst_addr = args[0]
    src_addr = args[1]
    copy_len = args[2]
    if emu.debug:
        print("[+] Hooking 'memcpy' @0x%x..." % addr)
    emu.emu_copy_mem_len(dst_addr, src_addr, copy_len)
    emu.write_reg_val(emu.ret_reg, args[0])
    if emu.debug:
        print("[+] Hooking 'memcpy' is done...")

def printf_hook(emu, addr, args, user_data):
    if emu.debug:
        print("[+] Hooking 'printf' @0x%x..." % addr)
    
    if emu.debug:
        print("[+] Hooking 'printf' is done...")


def strlen_hook(emu, addr, args, user_data):
    arg_str_ea = args[0]
    if emu.debug:
        print("[+] Hooking 'strlen' @0x%x..." % addr)
    strlen = emu.emu_strlen(arg_str_ea)
    if strlen == None:
        print("[+] Hooking 'strlen' error @0x%x..." % addr)
        strlen = 0
    else:
        emu.write_reg_val(emu.ret_reg, strlen)
    if emu.debug:
        print("[+] Hooking 'strlen (%d)' is done..." % strlen)

def toupper_hook(emu, addr, args, user_data):
    byte = args[0]
    if emu.debug:
        print("[+] Hooking 'toupper' @0x%x..." % addr)
    byte = emu.emu_toupper(byte)
    if byte == None:
        print("[+] Hooking 'toupper' error @0x%x..." % addr)
        byte = 0
    else:
        emu.write_reg_val(emu.ret_reg, byte)
    if emu.debug:
        print("[+] Hooking 'toupper (%d)' is done..." % byte)

def memset_hook(emu, addr, args, user_data):
    addr = args[0]
    int_c = args[1]
    size_n = args[2]
    if emu.debug:
        print("[+] Hooking 'memset' @0x%x..." % addr)
    byte = emu.emu_memset(addr, int_c, size_n)
    if byte == None:
        print("[+] Hooking 'memset' error @0x%x..." % addr)
        byte = 0
        emu.write_reg_val(emu.ret_reg, byte)
    else:
        emu.write_reg_val(emu.ret_reg, byte)
    if emu.debug:
        print("[+] Hooking 'memset (%d)' is done..." % byte)

def strstr_hook(emu, addr, args, user_data):
    haystack = args[0]
    needle = args[1]
    if emu.debug:
        print("[+] Hooking 'strstr' @0x%x, @0x%x..." % (haystack, needle))
    pos = emu.emu_strstr(haystack, needle)
    if pos == None:
        print("[+] Hooking 'strstr' error @0x%x, @0x%x..." % (haystack, needle))
        pos = 0
    elif pos == -1:
        print("[+] Hooking 'strstr' at @0x%x, @0x%x... find nothing" % (haystack, needle))
        pos = 0
        emu.write_reg_val(emu.ret_reg, pos)
    else:
        emu.write_reg_val(emu.ret_reg, pos)
    if emu.debug:
        print("[+] Hooking 'strstr (%d)' is done..." % pos)
def strsep_hook(emu, addr, args, user_data):
    haystack = args[0]
    needle = args[1]
    if emu.debug:
        print("[+] Hooking 'strsep' @0x%x, @0x%x..." % (haystack, needle))
    pos = emu.emu_strsep(haystack, needle)
    print("[+] Hooking strsep pos:", pos)
    if pos == None:
        print("[+] Hooking 'strsep' error @0x%x, @0x%x..." % (haystack, needle))
        pos = 0
    elif pos == -1:
        print("[+] Hooking 'strsep' at @0x%x, @0x%x... nothing" % (haystack, needle))
        pos = 0
        emu.write_reg_val(emu.ret_reg, pos)
    else:
        emu.write_reg_val(emu.ret_reg, pos)
    if emu.debug:
        print("[+] Hooking 'strsep (0x%x)' is done..." % pos)
        
def strcmp_hook(emu, addr, args, user_data):
    s1 = args[0]
    s2 = args[1]

    if emu.debug:
        print("[+] Hooking 'strcmp' @0x%x, @0x%x..." % (s1, s2))
    ret = emu.emu_strcmp(s1, s2)
    
    emu.write_reg_val(emu.ret_reg, ret)
    if emu.debug:
        print("[+] Hooking 'strcmp' is done...")
    
    
def strncmp_hook(emu, addr, args, user_data):
    s1 = args[0]
    s2 = args[1]
    n = args[2]
    if emu.debug:
        print("[+] Hooking 'strncmp' @0x%x, @0x%x..." % (s1, s2))
    ret = emu.emu_strncmp(s1, s2, n)
    emu.write_reg_val(emu.ret_reg, ret)
    if emu.debug:
        print("[+] Hooking 'strncmp' is done...")
def strspn_hook(emu, addr, args, user_data):
    s1 = args[0]
    s2 = args[1]
    if emu.debug:
        print("[+] Hooking 'strspn' @0x%x, @0x%x..." % (s1, s2))
    ret = emu.emu_strspn(s1, s2)
    emu.write_reg_val(emu.ret_reg, ret)
    if emu.debug:
        print("[+] Hooking 'strspn' is done...")

def strpbrk_hook(emu, addr, args, user_data):
    s1 = args[0]
    s2 = args[1]
    if emu.debug:
        print("[+] Hooking 'strpbrk' @0x%x, @0x%x..." % (s1, s2))
    ret = emu.emu_strpbrk(s1, s2)
    emu.write_reg_val(emu.ret_reg, ret)
    if emu.debug:
        print("[+] Hooking 'strpbrk' is done...")
        
def init_support_lib_hooks():
    support_lib_hook = {}
    support_lib_hook[MALLOC_NAME] = malloc_hook
    support_lib_hook[STRCPY_NAME] = strcpy_hook
    support_lib_hook[STRNCPY_NAME] = strncpy_hook
    support_lib_hook[MEMCPY_NAME] = memcpy_hook

    support_lib_hook[PRINTF_NAME] = printf_hook
    support_lib_hook[STRLEN_NAME] = strlen_hook
    support_lib_hook[MEMSET_NAME] = memset_hook
    support_lib_hook[TOUPPER_NAME] = toupper_hook
    support_lib_hook[STRSTR_NAME] = strstr_hook
    support_lib_hook[STRSEP_NAME] = strsep_hook
    support_lib_hook[STRCMP_NAME] = strcmp_hook
    support_lib_hook[STRNCMP_NAME] = strncmp_hook
    support_lib_hook[STRSPN_NAME] = strspn_hook
    support_lib_hook[STRPBRK_NAME] = strpbrk_hook
    
    return support_lib_hook

def init_support_sys_int_hooks():
    support_int_hook = {}

    return support_int_hook




