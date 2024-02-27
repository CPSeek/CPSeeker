#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0
# @Date:   2021-08-16 10:45:53
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2021-08-16 10:48:48

import os
import sys
import random
import struct
from unicorn_utils import UNICORN_PAGE_SIZE
from capstone import *
from capstone.mips import *
from capstone.arm import *
from capstone.ppc import *
from capstone.x86 import *
import angr

sys.setrecursionlimit(3000)


from unicorn import *
from unicorn.mips_const import *
from unicorn.arm_const import *
from unicorn.x86_const import *

from unicorn_regs import *
from unicorn_utils import *
# from print_registers import *

UNICORN_PAGE_SIZE     = 0x1000
MAX_ARGS = 8

STACK_BASE =  0x7ffff000
DATA_BASE = 0x6ffff000
MIPS_NOP = b'\x00\x00\x00\x00'

def ALIGN_PAGE_DOWN(x):
    return x & ~(UNICORN_PAGE_SIZE - 1)

def ALIGN_PAGE_UP(x):
    return (x + UNICORN_PAGE_SIZE - 1) & ~(UNICORN_PAGE_SIZE - 1)

#ALIGN_PAGE_DOWN = lambda x: x & ~(UNICORN_PAGE_SIZE - 1)
#ALIGN_PAGE_UP   = lambda x: (x + UNICORN_PAGE_SIZE - 1) & ~(UNICORN_PAGE_SIZE-1)


class autoEmu():
    def __init__(self, proj, arch, segm_start, segm_end, debug, timeout = None):
        self.proj = proj
        self.debug = debug
        self.regs = uc_reg_dict[arch]
        self.ret_reg = uc_ret_reg_dict[arch]
        self.arg_regs = uc_arg_reg_dict[arch]
        self.print_reg = uc_print_reg_dict[arch]
        self.args_val = []
        self.call_args_val = []
        self.args_dict = {}
        self.ip_reg = uc_ip_reg_dict[arch]
        self.ip = None
        self.sp_reg = uc_sp_reg_dict[arch]
        self.sp = None
        self.lr_reg = uc_lr_reg_dict[arch]
        self.lr = None
        self.arch = arch
        self.sys_int_inst = ida_sys_int_dict[arch]
        self.sys_int_insts_addr = {}
        self.mu = None
        if timeout == None:
            self.timeout = 5 * UC_SECOND_SCALE
        else:
            self.timeout = timeout * UC_SECOND_SCALE

        self.addr_tuples = None
        self.uc_arch = uc_arch_mode_dict[arch][0]
        self.uc_mode = uc_arch_mode_dict[arch][1]
        try:
            self.mu = Uc(self.uc_arch, self.uc_mode)
        except:
            print("[-] Cannot initialize unicorn.Uc...")
            sys.exit(-1)

        self.is_func = False
        self.func = None
        self.exec_start = None
        self.exec_end = None
        self.all_calls = None
        self.current_calls = None

        self.exec_insts = []
        self.exec_blocks = []

        self.skip_call = None

        self.code_hook = []
        self.block_hook = []
        self.mem_hook = []
        
        self.mem_read_addr = []     # address, size, val
        self.mem_write_addr = []    # address, size, val
        self.memory_access_addr = []

        self.memory_invalid_addr = []

        self.lib_calls_dict = {}
        self.sys_int_dict = {}

        self.sys_int_hooks = {}
        self.lib_hooks = {}
        self.all_calls_dict = {}

        self.support_lib_hook = None
        self.support_sys_int_hook = None

        self.lib_func = None

        self.copy_len = 0
        self.src_mem = None
        self.dst_mem_addr = None
        self.src_mem_addr = None

        self.instn_eas = set()
        self.block_eas = set()

        self.map_start_addr = 0
        self.map_end_addr = 0
        
        self.segm_start = segm_start
        self.segm_end = segm_end
        
        
        
    def get_mu(self):
        return self.mu
    
    def get_dst_mem_addr(self):
        return self.dst_mem_addr
    
    def get_src_mem_addr(self):
        return self.src_mem_addr
    
    def get_lib_call_dict(self):
        return self.lib_calls_dict

    def get_exec_blocks_trace(self):

        return self.exec_blocks
    
    def get_exec_insts_trace(self):

        return self.exec_insts
    def get_memory_read(self):

        return self.mem_read_addr

    def get_memory_write(self):

        return self.mem_write_addr
    def get_calls_dict(self):
        return  self.all_calls_dict

    def get_total_blocks(self):

        return self.block_eas

    def get_total_insts(self):

        return self.instn_eas

    def get_block_coverage(self):
        exec_blocks_set = set(self.exec_blocks)
        cover = coverage_block(self.block_eas, exec_blocks_set)

        return cover

    def get_insn_coverage(self):
        exec_insts_set = set(self.exec_insts)
        cover = coverage_inst(self.instn_eas, exec_insts_set)

        return cover

    def read_mem(self, addr, lens = 10):
        try:
            if self.debug:
                print("[+] Reading memory @0x%x(len: %d)" % (addr, lens))
            mem = self.mu.mem_read(addr, lens)
        except:
            print("[-] Failed to read at address 0x%x ..." % addr)
            return None
        if self.debug:
            print("[+] Memory read @0x%x(len: %d) is ok..." % (addr, lens), mem)
        return mem

    def read_mem_until_zero(self, addr):
        mem = bytearray()
        try:
            buf = self.mu.mem_read(addr, 1)
            while buf != b'\x00':
                mem = mem + buf
                addr = addr + 1
                buf = self.mu.mem_read(addr, 1)
            return mem
        except:
            print("[-] Failed to read memory at address 0x%x" % addr)
            return None
    

    def write_mem(self, addr, Bbytes = None):
        if self.debug:
            print("[+] Trying to write memory at address 0x%x with value: %s" % (addr, Bbytes))
            #print(Bbytes)
        if isinstance(Bbytes, bytearray):
            Bbytes = bytes(Bbytes)
        try:
            self.mu.mem_write(addr, Bbytes)
            return True
        except:
            print("[-] Failed to write memory at address 0x%x ..." % addr)
            return False
        
    def emu_toupper(self, byte):
        try:
            if byte >= 0x61:
                byte = byte - 0x20
            return byte
        
        except:
            print("[-] Failed to toupper %s" % byte)
            return None
    def emu_memset(self, addr, int_c, size_n):
        try:
            self.mu.mem_write(addr, int_c * size_n)
            
            return None
        except:
            print("[-] Failed to memset at address 0x%x with %c * %d" % (addr, int_c, size_n))
            return None
    def emu_strstr(self, haystack, needle):
        try:
            orig = self.read_mem_until_zero(haystack)
            need = self.read_mem_until_zero(needle)
            if self.debug:
                print("[+] hooking strstr...")
                print("[+] s1", orig)
                print("[+] s2", need)
            index = orig.find(need)
            if index == -1:
                return -1
            else:
                return haystack + index
        except:
            print("[-] Failed to find 0x%x at address 0x%x" % (need, haystack))
            return None
        
    def emu_strsep(self, haystack, needle):
        try:
            addr = haystack
            print("[+] hooking strsep: **hatstack: 0x%x" % haystack)
            if 'be' in self.arch:
                if '64' in self.arch:
                    haystack = self.mu.mem_read(haystack, 8)
                    haystack = struct.unpack(">Q", haystack)[0]
                else:
                    
                    haystack = self.mu.mem_read(haystack, 4)
                    haystack = struct.unpack(">L", haystack)[0]
            else:

                if '64' in self.arch:
                    haystack = self.mu.mem_read(haystack, 8)
                    haystack = struct.unpack("<Q", haystack)[0]
                else:
                    
                    haystack = self.mu.mem_read(haystack, 4)
                    haystack = struct.unpack("<L", haystack)[0]
                    
            print("[+] hooking strsep: *hatstack: 0x%x" % haystack)
            orig = self.read_mem_until_zero(haystack)
            need = self.read_mem_until_zero(needle)
            if self.debug:
                print("[+] hooking strsep...")
                print("[+] s1", orig)
                print("[+] s2", need)
            index = orig.find(need)
            print("[+] strsep @0x%x, index: %d" % (haystack, index))
            if index == -1:
                return haystack
            else:
                
                print("[+] strsep, try to write_mem")
                print("@0x%x: %s" % (haystack + index, b'\x00'*len(need)))
                self.write_mem(haystack+index, b'\x00'*len(need))
                new_addr = haystack + index + len(need)
                if 'be' in self.arch:
                    self.mu.mem_write(addr, new_addr.to_bytes(4, byteorder="big", signed = False))
                else:
                    self.mu.mem_write(addr, new_addr.to_bytes(4, byteorder="little", signed = False))
                    
                print("[+] strsep, write_mem")
                return haystack
        except:
            print("[-] Failed to find 0x%x at address 0x%x" % (need, haystack))
            return None
    def emu_strcmp(self, s1, s2):
        try:
            orig = self.read_mem_until_zero(s1)
            need = self.read_mem_until_zero(s2)
            if self.debug:
                print("[+] hooking strcmp...")
                print("[+] s1: ", orig)
                print("[+] s2: ", need)
            len_s1 = len(orig)
            len_s2 = len(need)
            i = 0
            j = 0
            while i < len_s1 and j < len_s2:
                if orig[i] == need[j]:
                    i += 1
                    j += 1
                else:
                    ret = orig[i] - need[j]
                    return ret
            if len_s1 > len_s2:
                ret = orig[i]
                return ret
            if len_s1 < len_s2:
                ret = need[j]
                return ret
            if i == j:
                return 0
        except:
            print("[-] Failed to strcmp 0x%x and 0x%x" % (s1, s2))
            return -1
        
    def emu_strncmp(self, s1, s2, n):
        try:
            orig = self.read_mem_until_zero(s1)
            need = self.read_mem_until_zero(s2)
            if self.debug:
                print("[+] hooking strncmp...")
                print("[+] s1: ", orig)
                print("[+] s2: ", need)
                print("[+] n: ", n)
            len_s1 = len(orig)
            len_s2 = len(need)
            i = 0
            j = 0
            while i < len_s1 and j < len_s2 and i < n and j < n:
                if orig[i] == need[j]:
                    i += 1
                    j += 1
                else:
                    ret = orig[i] - need[j]
                    return ret
            if i == n:
                return 0
            if len_s1 > len_s2:
                ret = orig[i]
                return ret
            if len_s1 < len_s2:
                ret = need[j]
                return ret
            if i == j:
                return 0
        except:
            print("[-] Failed to strncmp 0x%x and 0x%x" % (s1, s2))
            return -1
    def emu_strspn(self, s1, s2):
        try:
            orig = self.read_mem_until_zero(s1)
            need = self.read_mem_until_zero(s2)
            if self.debug:
                print("[+] hooking strspn...")
                print("[+] s1: ", orig)
                print("[+] s2: ", need)
            
            len_s1 = len(orig)
            len_s2 = len(need)
            i = 0
            j = 0
            while i < len_s1 and j < len_s2:
                if orig[i] == need[j]:
                    i += 1
                    j += 1
                else:
                    return i
        except:
            print("[-] Failed to strspn 0x%x and 0x%x" % (s1, s2))
            return -1
    def emu_strpbrk(self, s1, s2):
        try:
            orig = self.read_mem_until_zero(s1)
            need = self.read_mem_until_zero(s2)
            if self.debug:
                print("[+] hooking strpbrk...")
                print("[+] s1: ", orig)
                print("[+] s2: ", need)
            
            len_s1 = len(orig)
            len_s2 = len(need)
            i = 0
            j = 0
            for i in range(len_s1):
                for j in range(len_s2):
                    if orig[i] == need[j]:
                        return s1 + i
            return 0
                
        except:
            print("[-] Failed to strpbrk 0x%x and 0x%x" % (s1, s2))
            return -1
        
    def emu_strlen(self, addr):
        strlen = 0
        try:
            if self.debug:
                print("[+] Reading str to count the length @0x%x" % addr)
            buf = self.mu.mem_read(addr, 1)
            while buf != b'\x20' and buf != b'\x00': # ' '
                strlen += 1
                addr = addr + 1
                buf = self.mu.mem_read(addr, 1)
            if self.debug:
                print("[+] str len: %d" % strlen)
            return strlen
        except:
            print("[-] Failed to count the 'str' at address 0x%x" % addr)
            return None

    def emu_copy_mem_len(self, dst_addr, src_addr, lens):
        try:
            if self.debug:
                print("[+] Trying to copy (len: %d) memory from @0x%x to @0x%x ..." % (lens, src_addr, dst_addr))
            mem = self.read_mem(src_addr, lens)
            self.write_mem(dst_addr, mem)
            return True
        except:
            print("[-] Failed to copy (len: %d) memory from @0x%x to @0x%x ..." % (lens, src_addr, dst_addr))
            return False

    def emu_copy_mem(self, dst_addr, src_addr):
        try:
            if self.debug:
                print("[+] Trying to copy memory from @0x%x to @0x%x ..." % (src_addr, dst_addr))
            mem = self.read_mem_until_zero(src_addr)
            self.write_mem(dst_addr, mem)
            return True
        except:
            print("[-] Failed to copy memory from @0x%x to @0x%x ..." % (src_addr, dst_addr))
            return False


    def get_reg_val(self, reg_id):

        try:
            val = self.mu.reg_read(reg_id)
            return val
        except:
            print("[-] Failed to read register (uc id: %d) ..." % reg_id)
            return None

    def get_args_val(self, length = MAX_ARGS):
        '''
        get MAX_ARGS args
        '''
        self.call_args_val = []
        if self.debug:
            print("[+] Getting all arguments...")
        for reg_id in self.arg_regs:
            self.call_args_val.append(self.get_reg_val(reg_id))
        
        sp = self.get_reg_val(self.sp_reg)
        if self.debug:
            print("[+] Got stack pointer: 0x%x..." % sp)
            print("[+] Getting stack arguments...")
        if 'be' in self.arch:
            
            if '64' in self.arch:
                for i in range(MAX_ARGS - len(self.arg_regs)):
                    if self.debug:
                        print("[+] Getting stack arguments @0x%x..." % (sp + i * 8))
                    self.call_args_val.append(struct.unpack(">Q", self.read_mem(sp + i * 8, 8))[0])
            else:
                
                for i in range(MAX_ARGS - len(self.arg_regs)):
                    if self.debug:
                        print("[+] Getting stack arguments @0x%x..." % (sp + i * 4))
                    self.call_args_val.append(struct.unpack(">L", self.read_mem(sp + i * 4, 4))[0])
        else:

            if '64' in self.arch:
                for i in range(MAX_ARGS - len(self.arg_regs)):
                    if self.debug:
                        print("[+] Getting stack arguments @0x%x..." % (sp + i * 8))
                    self.call_args_val.append(struct.unpack("<Q", self.read_mem(sp + i * 8, 8))[0])
            else:
                for i in range(MAX_ARGS - len(self.arg_regs)):
                    if self.debug:
                        print("[+] Getting stack arguments @0x%x..." % (sp + i * 4))
                    self.call_args_val.append(struct.unpack("<L", self.read_mem(sp + i * 4, 4))[0])
        if self.debug:
            print("[+] Getting all arguments is done...")


        
    def write_reg_val(self, reg_id, val):
        try:
            self.mu.reg_write(reg_id, val)
            return True
        except:
            print("[-] Failed to write register (uc id: %d, val: 0x%x) ..." % (reg_id, val))
            return False
        
    def read_dst_mem(self, args_val):
        try:
            if self.debug:
                print("[+] Reading dst memory @0x%x (len: %d)..." % (args_val, self.copy_len))
            dst_mem = self.mu.mem_read(args_val, self.copy_len)
            return dst_mem
        except:
            print("[-] Failed to read memory at address 0x%x ..." % args_val)
            return None


    def normalize_name(self, name):
        if name.startswith('_'):
            if self.debug:
                print("[+] stripping function name with '_'")
            name = name.strip('_')
        elif name.startswith('.'):
            if self.debug:
                print("[+] stripping function name with '.'")
            name = name.strip('.')
        return name

    def in_text_segm(self, func_ea):

        if func_ea >= self.segm_start and func_ea <= self.segm_end:
            return True
        else:
            return False
            
    def emu_get_calls(self, func):
        '''
        $ return calls_dict: {addr: (func_ea, func_name)}
        '''
        func_start = func.addr
        func_end = func_start + func.size
        call_insts_addr = []
        sys_int_insts_addr = {}
        calls_dict = {}

        lib_calls_dict = dict() # addr: call_ea

        for block in func.blocks:
            if 'mips' in self.arch:   # delay slot
                if block.vex.jumpkind == 'Ijk_Call':    # function call
                    call_site = block.vex.insinstruction_addresses[-2]
                    target = block.vex.default_exit_target
                    func_name = self.get_func_name(target)
                    if self.in_text_segm(target):
                        calls_dict[call_site] = (target, func_name)
                    else:           #dynamic call
                        func_name = self.normalize_name(func_name)
                        addr = call_site
                        delay_slot = self.read_mem(self.next_head(addr),4)
                        self.write_mem(addr, delay_slot)
                        self.write_mem(addr+4, MIPS_NOP)
                        #addr = next_head(addr)
                        addr = self.next_head(addr)
                        call_site = addr
                        lib_calls_dict[call_site] = (target, func_name)

                elif block.vex.jumpkind == 'Ijk_Sys_syscall':
                    call_site = block.vex.insinstruction_addresses[-2]
                    target = block.vex.default_exit_target
                    eax_ea = self.prev_head(call_site)
                    val = ida_get_sys_int_dict[self.arch](eax_ea)
                    while val == None and eax_ea <= func_start:
                        eax_ea = self.prev_head(eax_ea)
                        val = ida_get_sys_int_dict[self.arch](eax_ea)
                    if val != None:
                        sys_int_insts_addr[call_site] = val
                        if self.debug:
                            print("[+] Syscall number is: %xh" % val)

                elif block.vex.jumpkind == 'Ijk_Boring':
                    target = block.vex.default_exit_target
                    if target < func_start or target >= func_end: # b/j call
                        call_site = block.vex.insinstruction_addresses[-2]
                        if self.in_text_segm(target):
                            calls_dict[call_site] = (target, func_name)
                        else:
                            func_name = self.normalize_name(func_name)
                            addr = call_site
                            delay_slot = self.read_mem(self.next_head(addr),4)
                            self.write_mem(addr, delay_slot)
                            self.write_mem(addr+4, MIPS_NOP)
                            #addr = next_head(addr)
                            addr = self.next_head(addr)
                            call_site = addr
                            lib_calls_dict[call_site] = (target, func_name)
            else:
                if block.vex.jumpkind == 'Ijk_Call':    # function call
                    call_site = block.vex.insinstruction_addresses[-2]
                    target = block.vex.default_exit_target
                    func_name = self.get_func_name(target)
                    if self.in_text_segm(target):
                        calls_dict[call_site] = (target, func_name)
                    else:
                        func_name = self.normalize_name(func_name)
                        lib_calls_dict[call_site] = (target, func_name)

                elif block.vex.jumpkind == 'Ijk_Sys_syscall':
                    call_site = block.vex.insinstruction_addresses[-2]
                    target = block.vex.default_exit_target
                    eax_ea = self.prev_head(call_site)
                    val = ida_get_sys_int_dict[self.arch](eax_ea)
                    while val == None and eax_ea <= func_start:
                        eax_ea = self.prev_head(eax_ea)
                        val = ida_get_sys_int_dict[self.arch](eax_ea)
                    if val != None:
                        sys_int_insts_addr[call_site] = val
                        if self.debug:
                            print("[+] Syscall number is: %xh" % val)

                elif block.vex.jumpkind == 'Ijk_Boring':
                    target = block.vex.default_exit_target
                    if target < func_start or target >= func_end: # b/j call
                        call_site = block.vex.insinstruction_addresses[-2]
                        if self.in_text_segm(target):
                            calls_dict[call_site] = (target, func_name)
                        else:
                            func_name = self.normalize_name(func_name)
                            lib_calls_dict[call_site] = (target, func_name)
        
        self.sys_int_insts_addr = sys_int_insts_addr
        self.lib_calls_dict = lib_calls_dict
        self.all_calls_dict = calls_dict
        return call_insts_addr

    # def get_sys_int_addr(self, addr_tuples):
    #     sys_int_insts_addr = {}
    #     #inst_info = idaapi.insn_t()
    #     if self.debug:
    #         print("[+] Analyzing syscall @0x%x" % (addr_tuples[0][0]))
    #     for start, end in addr_tuples:
    #         addr = start
    #         for addr in self.Heads(start, end):
    #             inst_str = self.generate_disasm_line(addr, 0)

    #             if self.sys_int_inst in inst_str:
    #                 #sys_int_insts_addr.append(addr)
    #                 eax_ea = self.prev_head(addr)
    #                 val = ida_get_sys_int_dict[self.arch](eax_ea)
    #                 while val == None and eax_ea <= start:
    #                     eax_ea = self.prev_head(eax_ea)
    #                     val = ida_get_sys_int_dict[self.arch](eax_ea)
    #                 if val != None:
    #                     sys_int_insts_addr[addr] = val
    #                     if self.debug:
    #                         print("[+] Syscall number is: %xh" % val)


    #     self.sys_int_insts_addr = sys_int_insts_addr
    #     return sys_int_insts_addr


    # def get_lib_func(self, addr_tuples, iter = 0):
    #     '''
    #     $ addr_tuples: [(start, end)...]
    #     $return lib_calls_dict: {addr: (func_ea, func_name)}
    #     '''
    #     lib_calls_dict = dict() # addr: call_ea
    #     if iter > 1:
    #         return lib_calls_dict
    #     call_insts_addr = self.get_call_site(addr_tuples)
    #     #print("[+] get all call sites...")
    #     for addr in call_insts_addr:
    #         for ref in XrefsFrom(addr, idaapi.XREF_FAR):
    #             if not ref.iscode:
    #                 continue
    #             func = idaapi.get_func(ref.to)
    #             if not func:
    #                 continue
    #             # ignore calls to imports / library calls / thunks
    #             segm_name = get_segm_name(func.start_ea)

    #             if (func.flags & (idaapi.FUNC_THUNK | idaapi.FUNC_LIB)) != 0 or segm_name == 'extern':
    #                 func_name = self.get_func_name(ref.to)
    #                 func_name = self.normalize_name(func_name)
    #                 if 'mips' in self.arch:
    #                     # this should be consistent with lib_call_hook()
    #                     '''
    #                     # (mode 1) hook at the function address
    #                     #addr = ref.to
    #                     '''
    #                     # (mode 2) hook at address of branch delay slot
    #                     delay_slot = self.read_mem(self.next_head(addr),4)
                        
    #                     self.write_mem(addr, delay_slot)
    #                     self.write_mem(addr+4, MIPS_NOP)
    #                     #addr = next_head(addr)
    #                     addr = self.next_head(addr)
    #                 lib_calls_dict[addr] = (ref.to, func_name)
    #             else:
    #                 iter += 1
    #                 result = self.get_lib_func([(func.start_ea, func.end_ea)], iter)
    #                 lib_calls_dict.update(result)
    #     if self.debug:
    #         print("[+] lib call dict:", lib_calls_dict)
    #     return lib_calls_dict

    def get_sys_int(self, addr_tuples):
        sys_int_dict = dict()

        return sys_int_dict

    def emu_analyze_calls(self):

        self.emu_get_calls(self.func)

    def emu_analyze_sys_int(self):

        self.get_sys_int_addr(self.addr_tuples)
    
    def next_head(self, addr):
        block = self.proj.factory.block(addr)
        addr_list = block.instruction_addrs

        index = addr_list.index(addr)
        if index + 1 < len(addr_list):
            return addr_list[index+1]
        else:
            return addr + 4
    def func_addr_set(self, func):
        func_addr_set = set()
        for block in func.blocks:
            addr_set = set(block.instruction_addrs)
            func_addr_set = func_addr_set.union(addr_set)
        return sorted(func_addr_set)

    def prev_head(self, addr):
        block = self.proj.factory.block(addr)
        addr_list = block.instruction_addrs

        index = addr_list.index(addr)
        if index - 1 > 0 :
            return addr_list[index-1]
        else:
            return addr - 4

    def Heads(self, start, end):
        func = self.proj.kb.functions.floor_func(start)
        func_addr_list = list(self.func_addr_set(func))
        start_index = func_addr_list.index(start)
        end_index = func_addr_list.index(end)
        
        return func_addr_list[start_index: end_index +1]

    def get_func_name(self, addr):
        func = self.proj.kb.functions.floor_func(addr)
        return func.name

    def generate_disasm_line(self, addr):
        block = self.proj.factory.block(addr)
        addr_list = block.instruction_addrs
        index = addr_list.index(addr)
        return str(block.capstone.insns[index])

    # def get_all_func_calls(self, func_ea, calls_dict = dict(), call_ea = None):
    #     '''
    #     $ addr_tuples: [(start, end)...]
    #     $return calls_dict: {addr: (func_ea, func_name)}
    #     '''
    #     #calls_dict = dict() # addr: call_ea
    #     func = self.proj.kb.functions.floor_func(func_ea)
    #     func_calls = func.functions_called()
    #     call_site_addrs = self.get_call_site(func)

    #     return calls_dict

    def emu_init_support_lib_hooks(self):

        self.support_lib_hook = init_support_lib_hooks()
    
    def emu_init_support_int_hooks(self):
        self.support_sys_int_hook = init_support_sys_int_hooks()

    def insn_cover_hook(self, mu, address, size, user_data):
        if address > self.segm_end or address < self.segm_start:
            self.auto_emu_stop()
        self.exec_insts.append(address)
        if self.debug:
            #pass
            print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
            self.print_reg(mu)
            
    def block_cover_hook(self, mu, address, size, user_data):
        self.exec_blocks.append(address)
        if self.debug:
            #pass
            print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))

    def memory_access_hook(self, mu, access, address, size, val, user_data):
        '''
        record all the memory access
        UC_HOOK_MEM_READ: it seems that the hook happens before the read and write. The read val is zero.
        UC_HOOK_MEM_READ_AFTER: hook after the successful read 
        '''
        if access == UC_MEM_WRITE:
            try:
                self.mem_write_addr.append((address, size, val))
                if self.debug:
                    print("[+] Memory write: addr @0x%x, size: 0x%x, val: 0x%x..." %(address, size, val))
            except:
                self.auto_emu_stop()  
        else:
            try:
                self.mem_read_addr.append((address, size, val))
                if self.debug:
                    print("[+] Memory read: addr @0x%x, size: 0x%x, val: 0x%x..." %(address, size, val))
            except:
                self.auto_emu_stop()
        return None

    def memory_invalid_hook(self, mu, access, address, size, val, user_data):
        '''
        deal with the invalid memory access
        '''
        if access == UC_MEM_WRITE:
            print("[+] Invalid memory write: addr @0x%x, size: 0x%x, val: 0x%x" % (address, size, val))
        else:
            print("[+] Invalid memory read: addr @0x%x, size: 0x%x, val: 0x%x" % (address, size, val))
        return self.auto_emu_stop()

    def lib_call_hook(self, mu, addr, size, user_data):
        #user_data = None
        # self.debug = True
        if addr in self.lib_hooks:
            try:
                # if 'mips' in self.arch:
                #     self.mu.
                print(self.call_args_val)
                self.get_args_val()
                if self.debug:
                    print("[+] Lib hooking at 0x%x" % addr)
                    #print(self.lib_hooks[addr])
                    self.print_reg(mu)
                if 'mipsle' in self.arch:
                    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
                elif 'mipsbe' in self.arch:
                    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
                byte = self.mu.mem_read(addr - 16, 0x30)
                for j in md.disasm(byte, addr - 16):
                    #opcode = j.mnemonic
                    print ('%x: %s %s' % (j.address, j.mnemonic, j.op_str))
                self.lib_hooks[addr](self, addr, self.call_args_val, user_data)
                if 'mips' in self.arch:
                    print("[+] MIPS hooking")
                    # # this should be consistent with get_libc_hook()
                    '''
                    # (mode 1) hook at the function address
                    #pc = self.get_reg_val(self.lr_reg)
                    #self.write_reg_val(self.ip_reg, pc)
                    '''
                    # (mode 2) hook at address of branch delay slot, do nothing
                    pass
                else:
                    pc = self.next_head(addr)
                    self.write_reg_val(self.ip_reg, pc)

            except:
                pc = self.next_head(addr)
                self.write_reg_val(self.ip_reg, pc)
                print("[-] Failed to hook @0x%x call '%s'..." % (addr, self.lib_calls_dict[addr][1]))
        else:
            pc = self.next_head(addr)
            
    def sys_int_hook_with_code(self, mu, addr, size, user_data):

        if addr in self.sys_int_insts_addr:
            try:
                if self.debug:
                    print("[+] Syscall hooking at 0x%x: %s" % (addr, self.generate_disasm_line(addr)))
                pc = self.next_head(addr)
                self.write_reg_val(self.ip_reg, pc)
                self.write_reg_val(self.ret_reg, 0x0)
            except:
                print("[-] Failed to hook syscall @0x%x call '%s'..." % (addr, self.generate_disasm_line(addr)))

    def sys_int_hook(self, mu, int_no, user_data):
        addr = self.get_reg_val(self.ip_reg)
        if self.debug:
            print("[+] Hooking @0x%x (hook number: %d)" % (addr, int_no))
        if addr in self.sys_int_insts_addr:
            try:
                if self.debug:
                    print("[+] Syscall hooking at 0x%x: %s" % (addr, self.generate_disasm_line(addr)))
                pc = self.next_head(addr)
                self.write_reg_val(self.ip_reg, pc)
                self.write_reg_val(self.ret_reg, 0x0)
            except:
                print("[-] Failed to hook syscall @0x%x call '%s'..." % (addr, self.generate_disasm_line(addr)))

    def auto_emu_segm_init(self):
        proj = self.proj
        MAP_START_ADDR = proj.loader.main_object.min_addr
        self.map_start_addr = MAP_START_ADDR
        MAX_SEGM_ADDR = proj.loader.main_object.max_addr
        MAP_END_ADDR = ALIGN_PAGE_UP(MAX_SEGM_ADDR)
        self.map_end_addr = MAP_END_ADDR
        if self.debug:
            print("[+] trying to mem_map 0x%x~0x%x" % (MAP_START_ADDR, MAP_END_ADDR))
        self.mu.mem_map(MAP_START_ADDR, MAP_END_ADDR - MAP_START_ADDR)
        segm_start = MAP_START_ADDR
        segm_end = MAX_SEGM_ADDR
        segm_bytes = proj.loader.memory.load(segm_start, segm_end - segm_start)
        self.mu.mem_write(segm_start, segm_bytes)

    def auto_emu_segm_uninit(self):
        try:
            if self.debug:
                print("[+] trying to mem_unmap 0x%x~0x%x" % (self.map_start_addr,self.map_end_addr))
            self.mu.mem_unmap(self.map_start_addr, self.map_start_addr - self.map_end_addr)
        except:
            print("[+] error in mem_unmap 0x%x~0x%x" % (self.map_start_addr, self.map_end_addr))

    def is_copy_init_reg_mem(self, byte = None, copy_len = None, args0 = None, args1 = None, args2 = None, args3 = None, reverse = 0):
        self.auto_emu_reg_init()
        if byte == None:
            byte = b'A'
        if copy_len == None:
            copy_len = 0x8
        self.copy_len = copy_len * len(byte)
        src_mem = byte * copy_len
        self.src_mem = src_mem
        
        
        sp = 0x7fffff00
        self.sp = sp
        bp = 0x7fffffff
        self.bp = bp
        if args0 == None:
            args0 = DATA_BASE + 0x4000
        if args1 == None:
            args1 = DATA_BASE + 0x6000
        if args2 == None:
            args2 = copy_len * len(byte)
        if args3 == None:
            args3 = copy_len * len(byte)
        self.args_val = []
        self.args_val.append(args0)
        self.args_val.append(args1)
        self.args_val.append(args2)
        self.args_val.append(args3)
        if reverse == 0:
            self.mu.mem_write(self.args_val[1], src_mem)
            self.dst_mem_addr = self.args_val[0]
            self.src_mem_addr = self.args_val[1]
        elif reverse == 1:
            self.mu.mem_write(self.args_val[0], src_mem)
            self.dst_mem_addr = self.args_val[1]
            self.src_mem_addr = self.args_val[0]
        elif reverse == 2:
            self.mu.mem_write(self.args_val[2], src_mem)
            self.dst_mem_addr = self.args_val[0]
            self.src_mem_addr = self.args_val[2]
        elif reverse == 3:
            self.mu.mem_write(self.args_val[0], src_mem)
            self.dst_mem_addr = self.args_val[2]
            self.src_mem_addr = self.args_val[0]
        # for i in range(1, len(self.args_val)):
        #     if self.args_val[i] > DATA_BASE:
        #         self.mu.mem_write(self.args_val[i], src_mem)
        self.mu.reg_write(self.sp_reg, sp)
        if self.arch != 'x86':
            
            self.mu.reg_write(self.arg_regs[0], args0)
            self.mu.reg_write(self.arg_regs[1], args1)
            self.mu.reg_write(self.arg_regs[2], args2)
            self.mu.reg_write(self.arg_regs[3], args3)
            
        else:
            self.mu.mem_write(sp + 4, args0.to_bytes(4, byteorder="little", signed = False))
            self.mu.mem_write(sp + 8, args1.to_bytes(4, byteorder="little", signed = False))
            self.mu.mem_write(sp + 0xc, args2.to_bytes(4, byteorder="little", signed = False))
            self.mu.mem_write(sp + 0x10, args3.to_bytes(4, byteorder="little", signed = False))
        
        if self.arch != 'x86' and self.arch != 'x64':
            self.mu.reg_write(self.lr_reg, self.exec_end)
        else:
            # segm = idaapi.get_segm_by_name(".rodata")
            # rodata_start = segm.start_ea
            '''
            if self.debug:
                print("[+] setting up gs...")
            set_gs_base(self.mu, self.sp, rodata_start, self.uc_mode)
            if self.debug:
                print("[+] setting up fs...")
            set_fs_base(self.mu, self.sp, rodata_start, self.uc_mode)
            '''
            print("[+] Arch: %s" % self.arch)
            if self.arch == 'x86':
                self.mu.reg_write(UC_X86_REG_EBP, bp)
            else:
                self.mu.reg_write(UC_X86_REG_RBP, bp)   # x64
            self.mu.mem_write(sp, self.exec_end.to_bytes(4, byteorder="little", signed = False))

    def auto_analyze_args(self):


        return self.args


    def auto_emu_reg_init(self):
        for reg_name, uc_reg in self.regs.items():
            if reg_name in ['CS', 'DS', 'ES', 'FS', 'GS']: # fix write bug in x86
                #self.write_reg_val(uc_reg[0], 0xff)
                continue
            self.write_reg_val(uc_reg[0], 0x0)
        if self.debug:
            self.print_reg(self.mu)
        return 0
    
    def auto_emu_stack_init(self):
        self.mu.mem_map(STACK_BASE, 2 * 1024 * 1024)     #stack
        self.mu.mem_map(DATA_BASE, 2 * 1024 * 1024)

        return 0

    def auto_emu_stack_uninit(self):
        self.mu.mem_unmap(STACK_BASE, 2 * 1024 * 1024)     #stack
        self.mu.mem_unmap(DATA_BASE, 2 * 1024 * 1024)
        
    def auto_emu_args_init(self):

        return 0

    def emu_add_lib_hook(self, addr, name):
        if name in self.support_lib_hook:
            self.lib_hooks[addr] = self.support_lib_hook[name]
        else:
            print("[+] Not support %s lib hook..." % name)

    def emu_add_sys_int_hook(self, addr, name):
        if name in self.support_sys_int_hook:
            self.sys_int_hooks[addr] = self.support_sys_int_hook[name]
        else:
            print("[+] Not support %s system int hook..." % name)

    def auto_emu_lib_hook_init(self):
        self.emu_get_calls(self.func)
        for addr, (func_ea, func_name) in self.lib_calls_dict.items():
            if self.debug:
                print("[+] Adding hook @0x%x: %s" % (addr, func_name))
            self.emu_add_lib_hook(addr, func_name)
        
    
    def auto_emu_sys_int_hook_init(self):
        self.emu_analyze_sys_int()
        #for addr, (int_ea, int_name) in self.sys_int_dict.items():
        #    self.emu_add_sys_int_hook(addr, int_name)
    
    '''     
    def support_lib_hook_init(self):
        
        self.support_lib_hook

    def support_sys_int_hook_init(self):

        self.support_sys_int_hook
    '''
   

    def check_zeros(self, mem_bytes):

        continue_zeros = b'\x00' * 4
        #print(continue_zeros)
        if mem_bytes.find(continue_zeros) == -1:
            return 1
        else:
            return 0
    def copy_mem_check(self, befor, after):

        if befor == after:
            return 1
        elif befor[:-1] == after[:-1]:      # secur copy, for example, 'sstrncpy', b'AAAAAA' -> bytearray(b'AAAAA\x00')
            return 1
        elif self.check_zeros(after) != 0:
            return 1
        else:
            return 0

    def auto_emu_func_init(self, func):
        self.func = func
        self.block_eas = func.block_addrs_set
        self.exec_start = func.addr
        self.exec_end = func.addr + func.size
        self.is_func = True
        proj = self.proj
        for addr in self.block_eas:
            block = proj.factory.block(addr)
            addr_set = set(block.instruction_addrs)
            self.instn_eas = self.instn_eas.union(addr_set)


    # def auto_emu_loop_init(self, start_bb, path, blocks):
    #     start_id = path.index(start_bb)
    #     self.exec_start = blocks[start_id].start_ea
    #     func = idaapi.get_func(self.exec_start)
    #     self.exec_end = func.end_ea
    #     for bb_id in path:
    #         bb_start_ea = blocks[bb_id].start_ea
    #         bb_end_ea = blocks[bb_id].end_ea
    #         for ea in Heads(bb_start_ea, bb_end_ea):
    #             self.instn_eas.add(ea)
    #         self.block_eas.add(bb_start_ea)


    
    def auto_emu_hook_init(self):
        self.mu.hook_add(UC_HOOK_CODE, self.insn_cover_hook)
        self.mu.hook_add(UC_HOOK_CODE, self.lib_call_hook)
        self.mu.hook_add(UC_HOOK_BLOCK, self.block_cover_hook)
        self.mu.hook_add(UC_HOOK_INTR, self.sys_int_hook)
        self.mu.hook_add(UC_HOOK_MEM_INVALID, self.memory_invalid_hook)
        self.mu.hook_add(UC_HOOK_MEM_READ_AFTER | UC_HOOK_MEM_WRITE, self.memory_access_hook)

    def auto_emu_start(self):
        self.mu.emu_start(self.exec_start, self.exec_end, self.timeout)
        '''
        try:
            self.mu.emu_start(self.exec_start, self.exec_end, self.timeout)
            return True
        except:
            print("[-] Failed to emulate")
            return False
        '''

        
    def auto_emu_stop(self):
        try:
            self.mu.emu_stop()
            return True
        except:
            print("[-] Failed to stop...")
            return False

    def auto_detect_copy_mem(self):

        try:
            dst_mem = self.read_dst_mem(self.get_dst_mem_addr())
        except:
            print("[-] Error in reading memory...")
        if self.debug:
            print("[+] source memory @0x%x:" % self.get_src_mem_addr())
            print(self.src_mem)
            print("[+] destination memory $0x%x:" % self.get_dst_mem_addr())
            print(dst_mem)
        if self.copy_mem_check(self.src_mem, dst_mem):
            return True

        else:
            return False
    
    def count_exec_insts(self):
        exec_insts_dict = {}

        for inst in self.exec_insts:
            if inst not in exec_insts_dict:
                exec_insts_dict[inst] = 1
            else:
                exec_insts_dict[inst] += 1
        
        return exec_insts_dict
    def judge_sequence(self, mode = "r", threshold = 5):
        mem_addrs = set()
        mem_access = None
        if mode == "r":
            mem_access = self.mem_read_addr
        else:
            mem_access = self.mem_write_addr
        if self.debug:
            print(mem_access)
        temp_access = sorted(mem_access)
        sequence_list = []
        sequence = []
        for i in range(len(temp_access) - 1):
            curr = temp_access[i]
            next = temp_access[i+1]
            curr_addr, curr_size, curr_val = curr
            next_addr, next_size, next_val = next
            if curr_addr == next_addr:
                continue
            if curr_addr + curr_size == next_addr and curr_val !=0:
                sequence.append(curr)
            else:
                if sequence != []:
                    #sequence.append(next)
                    sequence_list.append(sequence)
                sequence = []
        if sequence != []:
            sequence_list.append(sequence)
        if self.debug:
            print("sequence list:", sequence_list)
        large = 0
        large_sequence = None
        for i in range(len(sequence_list)):
            size = len(sequence_list[i])
            if size >= large:
                large_sequence = sequence_list[i]
                large = size
        if large_sequence == None:
            return 0, 0, 0
        first_addr = large_sequence[0][0]
        last_addr = large_sequence[-1][0]
        inter = large_sequence[0][1]
        return first_addr, last_addr, inter
        # mem_addrs = list(mem_addrs)
        # interval_dict = {}
        
        
    def mem_access_check(self, mode = "r", threshold = 5):
        mem_addrs = set()
        mem_access = None
        if mode == "r":
            mem_access = self.mem_read_addr
        else:
            mem_access = self.mem_write_addr
        if self.debug:
            print(mem_access)

        for (addr, size, val) in mem_access:
            mem_addrs.add(addr)
        mem_addrs = list(mem_addrs)
        interval_dict = {}
        key = 0
        if self.debug:
            print(mem_addrs)
        mem_addrs = sorted(mem_addrs)
        for i in range(0, len(mem_addrs) - 1):
            inter = abs(mem_addrs[i+1] - mem_addrs[i])
            if inter not in interval_dict:
                interval_dict[inter] = 1
            else:
                interval_dict[inter] += 1
        
        for key, val in interval_dict.items():
            if val > threshold:
                break
            else:
                continue
        first_addr = 0
        index = 0
        for i in range(0, len(mem_addrs) - 1):
            inter = abs(mem_addrs[i+1] - mem_addrs[i])
            if inter == key:
                first_addr = mem_addrs[i]
                index = i
                break
        last_addr = 0
        for i in range(index, len(mem_addrs) - 1):
            inter = abs(mem_addrs[i+1] - mem_addrs[i])
            if inter != key:
                last_addr = mem_addrs[i]
                break
            else:
                last_addr = mem_addrs[i+1]
        inter = key
        return first_addr, last_addr, inter

    def mem_read_check(self):

        return True


def init_autoEmu_for_func(proj, func_ea, debug = False):
    func = proj.kb.functions.floor_func(func_ea)
    # addr_tuples = [(func.start_ea, func.end_ea)]
    # print(hex(func.start_ea), hex(func.end_ea))
    # addr_tuples = [(func.start_ea, func.start_ea + 0x8c)]
    arch = get_arch(proj)
    segm_start = proj.loader.find_segment_containing(func.addr).min_addr
    segm_end = proj.loader.find_segment_containing(func.addr).max_addr
    aemu = autoEmu(proj, arch, segm_start, segm_end, debug = True)
    aemu.auto_emu_segm_init()
    aemu.auto_emu_stack_init()
    #aemu.auto_emu_reg_init()

    aemu.auto_emu_func_init(func)
    aemu.emu_init_support_lib_hooks()
    aemu.auto_emu_lib_hook_init()
    #aemu.auto_emu_sys_int_hook_init()

    return aemu

def init_autoEmu_for_loop(proj, start_bb, path, blocks, debug = False):
    loop_input_analysis(start_bb, path, blocks)
    arch = get_arch(proj)
    func_ea = start_bb.addr
    segm_start = proj.loader.find_segment_containing(func_ea).min_addr
    segm_end = proj.loader.find_segment_containing(func_ea).max_addr
    
    aemu = autoEmu(arch, segm_start, segm_end, debug = True)
    #aemu = autoEmu(arch, debug)

    aemu.auto_emu_segm_init()
    aemu.auto_emu_stack_init()
    #aemu.auto_emu_reg_init()

    aemu.auto_emu_loop_init(start_bb, path, blocks)
    aemu.emu_init_support_lib_hooks()
    aemu.auto_emu_lib_hook_init()
    aemu.auto_emu_sys_int_hook_init()

    return aemu






if __name__ == "__main__":
    ea = 0x8000
    aemu = init_autoEmu_for_func(ea, debug=True)
    func_name = ''
    indicator = 0
    byte = b'A'
    copy_len = 0x8
    args0 = DATA_BASE + 0x4000
    arguments = [DATA_BASE + 0x6000, copy_len * len(byte), copy_len * len(byte)]
    '''
    args0 = DATA_BASE + 0x4000
    args1 = DATA_BASE + 0x6000
    args2 = copy_len * len(byte)
    args3 = copy_len * len(byte)
    '''
    args1, args2, args3 = arguments
    print("=" * 80)
    print("=" * 80)
    aemu.is_copy_init_reg_mem(byte, copy_len, args0, args1, args2, args3)
    aemu.auto_emu_hook_init()
    flag = aemu.auto_emu_start()
    #if flag == False:
    #    print("[-] Failed to emulate...")
    is_copy = aemu.auto_detect_copy_mem()
    indicator = indicator + is_copy
    print([(hex(i),j) for i,j in aemu.count_exec_insts().items()])
    read_start_addr, read_end_addr, interval = aemu.mem_access_check()
    write_start_addr, write_end_addr, interval = aemu.mem_access_check(mode='w')
    access_len = 5
    if read_end_addr - read_start_addr > access_len and write_end_addr - write_start_addr > access_len:
        print("[+] Memory copy from @0x%x to @0x%x (length: %d)" % (read_start_addr, write_start_addr, write_end_addr - write_start_addr))


    #aemu.auto_emu_stop()
    '''
    for i in range(3):
        aemu.auto_emu_reg_init()
        args1, args2, args3 = arguments[i%3], arguments[(i+1)%3], arguments[(i+2)%3]
        print("[+] Arguments: 0x%x, 0x%x,0x%x, 0x%x" % (args0, args1, args2, args3))
        aemu.is_copy_init_reg_mem(byte, copy_len, args0, args1, args2, args3)

        aemu.auto_emu_start()
        is_copy = aemu.auto_detect_copy_mem()
        aemu.auto_emu_stop()
        indicator = indicator + is_copy
    '''

    #print(aemu.get_lib_call_dict())
    #print(aemu.sys_int_insts_addr)
    print("[+] is '%s' a copy likely function?" % func_name)
    if indicator:
        print("[+] True.")
    else:
        print("[-] False.")

    print("[+] Executed instruction trace:", [hex(i) for i in aemu.get_exec_insts_trace()])
    print("[+] Executed block trace:", [hex(i) for i in aemu.get_exec_blocks_trace()])
    print("[+] Memory read:", [(hex(i),j,k) for i,j,k in aemu.get_memory_read()])
    print("[+] Memory write:", [(hex(i),j,k) for i,j,k in aemu.get_memory_write()])
    print("[+] Block coverage: %0.6f" % aemu.get_block_coverage())
    print("[+] Instruction coverage: %0.6f" % aemu.get_insn_coverage())
    '''
    print("[+] Total block address")
    print(aemu.get_total_blocks())
    print("[+] Executed block address")
    print(aemu.get_exec_blocks())
    print("[+] Total instruction address")
    print(aemu.get_total_insts())
    print("[+] Executed instruction address")
    print(aemu.get_exec_insts())
    '''
    print("=" * 80)
    print("=" * 80)



    #print(aemu.all_calls)
    #print(aemu.get_lib_func(addr_tuples))




