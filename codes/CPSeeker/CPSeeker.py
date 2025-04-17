#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0
# @Date:   2022-02-11 10:45:53
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2022-02-11 10:48:48

import autoEmu
from autoEmu import *
import time
import argparse

from unicorn_regs import *
from unicorn_utils import *

import numpy as np

from sklearn.metrics import auc, roc_curve, precision_score, recall_score, f1_score


def init_autoEmu_for_bin(proj, debug = False):
    arch = get_arch(proj)

    aemu = autoEmu(proj, arch, debug)
    aemu.auto_emu_segm_init()
    aemu.auto_emu_stack_init()

    

    return aemu

# def init_for_bin_func(aemu, func_ea):
#     try:
#         aemu.auto_emu_segm_uninit()
#         aemu.auto_emu_stack_uninit()
#     except:
#         aemu.auto_emu_segm_uninit()
#     func = idaapi.get_func(func_ea)
#     addr_tuples = [(func.start_ea, func.end_ea)]
#     aemu.auto_emu_func_init(addr_tuples)
#     aemu.emu_init_support_lib_hooks()
#     aemu.auto_emu_lib_hook_init()
#     aemu.auto_emu_sys_int_hook_init()

def init_autoEmu_for_func(proj, func_ea, debug):
    func = proj.kb.functions.floor_func(func_ea)

    arch = get_arch(proj)
    region = proj.loader.main_object.sections.find_region_containing(func_ea)
    segm_start = region.min_addr
    segm_end = region.max_addr
    aemu = autoEmu(proj, arch, segm_start, segm_end, debug)
    aemu.auto_emu_segm_init()
    aemu.auto_emu_stack_init()
    #aemu.auto_emu_reg_init()

    aemu.auto_emu_func_init(func)
    aemu.emu_init_support_lib_hooks()
    aemu.auto_emu_lib_hook_init()
    # aemu.auto_emu_sys_int_hook_init()

    return aemu

def judge_exec_loop(loop_block_start_list, exec_traces):
    
    for start_eas in loop_block_start_list:
        length = 0
        # print([hex(i) for i in start_eas])
        for ea in start_eas:
            if ea in exec_traces:
                length += 1
        if length == len(start_eas):
            return True
    return False

def is_copy_func(proj, ea, loops, reverse, debug):
    #debug = False
    aemu = init_autoEmu_for_func(proj, ea, debug)
    func = proj.kb.functions.floor_func(ea)
    func_name = func.name
    indicator = 0
    #byte = b'http://www.baidu.com/A.\t\t\t\t\r\n\<br>><?#Location:aaaaaaaaaaa'
    byte = b'HTTP/1.1200OK\r\nLocation:HTTP://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\r\nA.\#:\r\n'
    copy_len = 0x1
    # byte = b'http/A.\#:\r\n'
    # copy_len = 0x2
    
    args0 = DATA_BASE + 0x4000
    arguments = [DATA_BASE + 0x6000, copy_len * len(byte), copy_len * len(byte)]
    '''
    args0 = DATA_BASE + 0x4000
    args1 = DATA_BASE + 0x6000
    args2 = copy_len * len(byte)
    args3 = copy_len * len(byte)
    '''

    #args2, args1, args3 = arguments
    args1, args2, args3 = arguments
    print("=" * 80)
    print("=" * 80)
    if reverse == 0:
        aemu.is_copy_init_reg_mem(byte, copy_len, args0, args1, args2, args3)
    elif reverse == 1:
        aemu.is_copy_init_reg_mem(byte, copy_len, args0, args1, args2, args3, 1)
    elif reverse == 2:
        aemu.is_copy_init_reg_mem(byte, copy_len, args0, args2, args1, args3, 2)
    elif reverse == 3:
        aemu.is_copy_init_reg_mem(byte, copy_len, args0, args2, args1, args3, 3)
    #aemu.is_copy_init_reg_mem(byte, copy_len, args0, args1, args2, args3, 1)
    aemu.auto_emu_hook_init()
    #aemu.write_mem(args0, byte*copy_len)
 
    arch = get_arch(proj)
    # global, mips t9
    if 'mips' in arch:
        aemu.write_reg_val(UC_MIPS_REG_T9, func.addr)
    calls_dict = aemu.get_calls_dict()
    for key, val in calls_dict.items():
        if "abort" in val[1]:
            return 0, ea
    try:
        flag = aemu.auto_emu_start()
    except:
        return 0, ea

    
    blocks = func.blocks


    loop_block_start_list = []
    for path in loops:
        loop_block_start_eas = set()
        for bb in path:
            bb_start_ea = bb.addr
            # bb_end_ea = blocks[bb_id].end_ea
            
            loop_block_start_eas.add(bb_start_ea)
        loop_block_start_list.append(loop_block_start_eas)  # block error _memcpy

    #if flag == False:
    #    print("[-] Failed to emulate...")
    is_copy = aemu.auto_detect_copy_mem()
    # if flag == False:
    #     print("[-] Failed to emulate...")
    indicator = indicator + is_copy
    print([(hex(i),j) for i,j in aemu.count_exec_insts().items()])
    # read_start_addr, read_end_addr, interval = aemu.mem_access_check()
    # write_start_addr, write_end_addr, interval = aemu.mem_access_check(mode='w')
    read_start_addr, read_end_addr, interval = aemu.judge_sequence()
    write_start_addr, write_end_addr, interval = aemu.judge_sequence(mode='w')
    access_len = copy_len * len(byte) // 4
    print("[+] access length: ", access_len)
    print("[+] Memory read from @0x%x to @0x%x (length: %d)" % (read_start_addr, read_end_addr, read_end_addr - read_start_addr))
    print("[+] Memory write from @0x%x to @0x%x (length: %d)" % (write_start_addr, write_end_addr, write_end_addr - write_start_addr))
    if read_end_addr - read_start_addr >= access_len \
        and read_end_addr - read_start_addr <= access_len * 16 \
        and write_end_addr - write_start_addr >= access_len \
        and write_end_addr - write_start_addr <= access_len * 16 \
        and read_start_addr != write_start_addr:
        print("[+] Memory copy from @0x%x to @0x%x (length: %d)" % (read_start_addr, write_start_addr, write_end_addr - write_start_addr))
        if judge_exec_loop(loop_block_start_list, aemu.get_exec_insts_trace()):
            indicator = indicator + 1


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

    if debug:
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
    if indicator:
        return 1, ea
    else:
        return 0, ea

def find_copy_funcs(proj):
    binary_name = proj.loader.main_object.binary_basename
    path_name = proj.loader.main_object.binary
    global loops
    thresh = 50     # function is too large.( too many blocks)
    print("binary name: %s" % binary_name)
    func_items = {}
    id = 0
    #segm = idaapi.get_segm_by_name(".text")
    #aemu = init_autoEmu_for_bin()
    cfg = proj.analyses.CFG()
    for funcea in cfg.functions:
        line = []   # present the results
        loops = []
        func = proj.kb.functions.floor_func(funcea) # get function object
        funcname = func.name
        #print(funcname)
        if 'abort' in funcname:
            continue
        if funcname.startswith("_"):
           continue
        line.append(funcea)
        line.append(funcname)
        blocks = func.block
        if len(blocks) < 3 or len(blocks) > thresh:
            continue
        #flag = is_copy_func(func, blocks)  # get function features and successor and so on.
        flag = 0
        aemu = None
        start_block_ea = func.start_ea
        if 'x86' in get_arch(proj):
            addr_list = list(func_addr_set(func))
            for addr in addr_list:
                opcode = generate_disasm_line(addr, 0)
                if "rep movs" in opcode:
                    flag = 1
                    start_block_ea = addr
                    break
        if flag == 0:
            loops = get_func_loop(cfg, funcea)
            if loops == []:  # no loop, return false
                flag = 0
                start_block_ea = 0
            else:
                try:
                    
                    flag, start_block_ea = is_copy_func(proj, funcea, loops, 0, debug=False)
                    
                except:
                    
                    flag = 0
                    start_block_ea = 0
                if flag == 0:
                    flag, start_block_ea = is_copy_func(proj, funcea, loops, 1, debug=False)
                if flag == 0:
                    flag, start_block_ea = is_copy_func(proj, funcea, loops, 2, debug=False)
        line.append(start_block_ea)
        line.append(flag)
        line.append(1)
        func_items[id] = line
        id += 1
        #break
        # try:
        #     aemu.auto_emu_segm_uninit()
        #     aemu.auto_emu_stack_uninit()
        #     del aemu
        # except:
        #     continue

    return func_items



def get_single_func(proj, func_ea):
    ea = func_ea
    cfg = proj.analyses.CFG()
    func = proj.kb.functions.floor_func(ea)
    funcname = func.name
    func_start = func.addr
    func_end = func.addr + func.size
    
    if 'x86' in get_arch(proj):
        addr_list = Heads(proj, func_start, func_end)
        for addr in addr_list:
            opcode = generate_disasm_line(addr, 0)
            if "rep movs" in opcode:
                flag = 1
                start_block_ea = addr
                print("[+] is '%s' a copy function?" % funcname)
                if flag == 0:
                    print("[-] False (0).")
                else:
                    print("[+] True (1).")
                return None
    loops = get_func_loop(cfg, ea)
    if loops == []:
        flag = 0
    else:
        # aemu = init_autoEmu_for_func(ea, debug = True)
        flag, start_block_ea = is_copy_func(proj, ea, loops, 0, debug=True)
        if flag == 0:
            print("="*60)
            print("reverse:")
            flag, start_block_ea = is_copy_func(proj, ea, loops, 1, debug=True)
        if flag == 0:
            flag, start_block_ea = is_copy_func(proj, ea, loops, 2, debug=False)
        if flag == 0:
            flag, start_block_ea = is_copy_func(proj, ea, loops, 3, debug=False)
    print("[+] is '%s' a copy function?" % funcname)
    if flag == 0:
        print("[-] False (0).")
    else:
        print("[+] True (1).")


def get_all_funcs(proj, mode = False):
    binary_name = proj.loader.main_object.binary_basename

    start_stime = time.time()
    if mode == False:
        print("[+] Classifying function info is ok...................")
        print("[+] Finding all copy functions...............")
    func_items = find_copy_funcs()
    if mode == False:
        print("[+] Total: %d functions." % len(func_items) )


    

    c_lib_cpy = [
    "memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat", "strxfrm",
    "wcscat", "wcscpy", "wcsxfrm", "wcsncpy", "wmemmove", "wcsncat", "wmemcpy",
    "wcsnrtombs", "mempcpy",
    "my_copy", "yystpcpy", "yy_flex_strncpy", "zmemcpy", "stpcpy", "unistrcpy",
    "BUF_strlcpy", "tr_strlcpy", "g_strlcpy", "wxStrncpy", "wxStrcpy", "wxStrcat",
    "w_copy", "strlcpy", "util_memcpy", "resolv_domain_to_hostname", "MD5_memcpy",
    "alpha_strcpy_fn", "StrnCpy_fn", "strncpy_w", "sstrncpy", "alps_lib_toupper"
    ]
    #print(c_lib_cpy)
    y_truth = []
    y_pre = []
    for key, value in func_items.items():
        func_name = value[1].strip("_")
        flag = value[3]
        try:
            if func_name.lower() in c_lib_cpy or func_name in c_lib_cpy:
                #print(func_name.lower())
                y_truth.append(1)
            else:
                y_truth.append(0)
            y_pre.append(flag)
        except:
            continue
    y_truth = np.array(y_truth)
    y_pre = np.array(y_pre)
    precision = precision_score(y_truth, y_pre, average='binary')
    recall = recall_score(y_truth, y_pre, average='binary')
    f1 = f1_score(y_truth, y_pre, average='binary')
    end_stime = time.time()
    if mode:
        res = open(binary_name + '_CPFinder-U.txt', 'w')
        print >> res, func_items
        print("[+] Precision: %f, recall: %f, f1: %f." %(precision, recall, f1), file = res)
        print("Time: %f" % (end_stime - start_stime), file = res)
        res.close()
    else:
        print("[+] Precision: %f, recall: %f, f1: %f." %(precision, recall, f1))
        print("Time: %f" % (end_stime - start_stime))

    
    

def main():
    parser = argparse.ArgumentParser(description="Finding loop copy...")
    parser.add_argument('-b', '--binary', type=os.path.abspath, help='the binary executable', required=True)
    parser.add_argument('-m', '--mode', type=str, help='the mode', required=False, default='single')
    parser.add_argument('-a', '--addr', type=str, help='the address (hex str)', required=False)
    parser.add_argument('-o', '--outfile', type=str, help='out file, default for stdout')
    # parser.add_argument('--project-name', help='project name')
    args = parser.parse_args()
    binary_file = args.binary
    mode = args.mode
    addr = int(args.addr,16)
    proj = angr.Project(binary_file, auto_load_libs=False, use_sim_procedures=True)
    if mode == "all":
        get_all_funcs(proj)
    elif addr != None:
        get_single_func(proj, addr)



if __name__ == "__main__":
    main()
