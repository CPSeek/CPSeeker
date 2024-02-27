#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0
# @Date:   2021-04-22 15:45:53
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2021-04-22 15:45:48

import os
import networkx as nx
import random
import re
from itertools import islice
import func_timeout
from func_timeout import func_set_timeout

import archinfo
import pyvex
from archinfo import Endness

from collections import OrderedDict

from pyvex import block
from unicorn_regs import *
from ida_regs import *


# https://www.linux-mips.org/wiki/Syscall
# And of course a syscall is invoked through a SYSCALL instruction. 
# The kernel assumes the syscall instruction not to be in a branch delay slot, 
# that is, it will not check for branch delay slots and do branch emulation. 

MIPS_SYSCALL_INSN = 'syscall'       #syscall num $v0, li      $v0, 0x108E
X86_SYSCALL_INSN = 'int     80h'    #syscall num eax, mov     eax, 4
ARM_SYSCALL_INSN = 'SVC     0'      #syscall num r7, MOV     R7, #5
PPC_SYSCALL_INSN = 'sc'             #syscall num r0, li        r0, 0xAE

SHORT_PATH_THRESHOLD = 2
ALL_SIMPLE_PATH_THRESHOLD = 1
MAX_BLOCK_SIZE = 50

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

vex_arch_dict = OrderedDict([
    ('x86', (archinfo.ArchX86())),
    ('x64', (archinfo.ArchAMD64())),
    ('mipsbe', (archinfo.ArchMIPS32(Endness.BE))),
    ('mipsle', (archinfo.ArchMIPS32(Endness.LE))),
    ('mips64be', (archinfo.ArchMIPS64(Endness.BE))),
    ('mips64le', (archinfo.ArchMIPS64(Endness.LE))),
    ('armbe', (archinfo.ArchARM(Endness.BE))),
    ('armle', (archinfo.ArchARM(Endness.LE))),
    ('arm64be', (archinfo.ArchARM(Endness.BE))),    #
    ('arm64le', (archinfo.ArchARM(Endness.LE))),    #
    ('ppcbe', (archinfo.ArchPPC32(Endness.BE))),
    ('ppcle', (archinfo.ArchPPC32(Endness.LE))),
    ('ppc64be', (archinfo.ArchPPC64(Endness.BE))),  #
    ('ppc64le', (archinfo.ArchPPC64(Endness.LE)))   #
    ])

def get_arch():
    if ph.id == PLFM_386 and ph.flag & PR_USE64:
        return "x64"
    elif ph.id == PLFM_386 and ph.flag & PR_USE32:
        return "x86"
    elif ph.id == PLFM_ARM and ph.flag & PR_USE64:
        if cvar.inf.is_be():
            return "arm64be"
        else:
            return "arm64le"
    elif ph.id == PLFM_ARM and ph.flag & PR_USE32:
        if cvar.inf.is_be():
            return "armbe"
        else:
            return "armle"
    elif ph.id == PLFM_MIPS and ph.flag & PR_USE32:
        if cvar.inf.is_be():
            return "mipsbe"
        else:
            return "mipsle"
    elif ph.id == PLFM_PPC and ph.flag & PR_USE32:
        if cvar.inf.is_be():
            return "ppcbe"
        else:
            return "ppcle"
    elif ph.id == PLFM_ARM and ph.flag & PR_USE64:
        if cvar.inf.is_be():
            return "arm64be"
        else:
            return "arm64le"
    elif ph.id == PLFM_MIPS and ph.flag & PR_USE64:
        if cvar.inf.is_be():
            return "mips64be"
        else:
            return "mips64le"
    elif ph.id == PLFM_PPC and ph.flag & PR_USE64:
        if cvar.inf.is_be():
            return "ppc64be"
        else:
            return "ppc64le"
    else:
        return ""

#syscall num eax, mov     eax, 4
def x86_get_sys_int_value(ea):
    
    mnem = print_insn_mnem(ea)
    sys_int_value = None
    if mnem == 'mov' or mnem == 'movq':
        if get_operand_type(ea, 0) == o_reg and get_operand_value(ea, 0) == 0x0: # 0x0, eax, rax
            sys_int_value = get_operand_value(ea, 1)

    return sys_int_value

#syscall num $v0, li      $v0, 0x108E
def mips_get_sys_int_value(ea):

    mnem = print_insn_mnem(ea)
    sys_int_value = None
    if mnem == 'li':
        if get_operand_type(ea, 0) == o_reg and get_operand_value(ea, 0) == 0x2: # 0x2, $v0
            sys_int_value = get_operand_value(ea, 1)

    return sys_int_value

#syscall num r7, MOV     R7, #5
def arm_get_sys_int_value(ea):

    mnem = print_insn_mnem(ea)
    sys_int_value = None
    if mnem.lower() == 'mov':
        if get_operand_type(ea, 0) == o_reg and get_operand_value(ea, 0) == 0x7: # 0x7, R7
            sys_int_value = get_operand_value(ea, 1)
            
    return sys_int_value

#syscall num r0, li        r0, 0xAE
def ppc_get_sys_int_value(ea):

    mnem = print_insn_mnem(ea)
    sys_int_value = None
    if mnem.lower() == 'mov':
        if get_operand_type(ea, 0) == o_reg and get_operand_value(ea, 0) == 0x0: # 0x0, r0
            sys_int_value = get_operand_value(ea, 1)
            
    return sys_int_value


def get_exec_seg():
    segm = idaapi.get_segm_by_name(".text")
    if segm == None: # no .text segment, it's name maybe is LOAD
        #ea = get_name_ea_simple('.init_proc')
        ea = get_name_ea_simple('init_proc')
        if ea == BADADDR:
            ea = get_name_ea_simple('_start')
        seg_start_ea = get_segm_start(ea)
        seg_end_ea = get_segm_end(ea)
    else:
        seg_start_ea = segm.start_ea
        seg_end_ea = segm.end_ea
    return seg_start_ea, seg_end_ea

def get_extern_func():
    extern_func = []
    segm = idaapi.get_segm_by_name("extern")
    for ea in Functions(segm.start_ea,segm.end_ea):
        func_name = get_func_name(ea)
        if "__imp_" in func_name:
            func_name = func_name.strip("__imp_")
        extern_func.append(func_name)
    return extern_func

def fix_boundary():
    seg_start_ea, seg_end_ea = get_exec_seg()
    ea = seg_start_ea
    while (ea < seg_end_ea):
        naddress = find_not_func(ea, SEARCH_DOWN)
        flag = get_flags(naddress)
        if flag & 0x600 == 0x600:
            add_func(naddress, BADADDR)
        ea = next_head(naddress)
    plan_and_wait(seg_start_ea, seg_end_ea)
    return None

def is_inBlock(ea, start, end):
    if ea >= start and ea < end:
        return True
    else:
        return False
        
def get_func_blocks(func):
    func_blocks_start = [v.start_ea for v in FlowChart(func)]

    return func_blocks_start

def get_func_inst(func):
    addr = func.start_ea
    end = func.end_ea

    func_insts = []
    while addr < end:
        func_insts.append(addr)
        addr = next_head(addr)
    
    return func_insts



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
def find_father(succs, node, path):

    for i in range(len(succs)):
        if (i not in path) and node in succs[i]:
            return i

    return -1

def has_loop(func_ea):
    # x86 rep movsb
    func = get_func(func_ea)
    blocks = [v for v in idaapi.FlowChart(func)]
    new_blocks = []
    for bb in blocks:
        if is_inBlock(bb.start_ea, func.start_ea, func.end_ea) and is_inBlock(bb.end_ea, func.start_ea, func.end_ea + 1):
            new_blocks.append(bb)
    blocks = new_blocks
    
    func_cfg = nx.DiGraph()

    for bb in blocks:
        for suc in bb.succs():
            func_cfg.add_edge(bb.id, suc.id)
    
    try:
        #print("[+] finding loops.............")
        res = list(nx.simple_cycles(func_cfg)) # find the loop paths
        res = list(nx.cycle_basis(func_cfg))
    except:
        pass
    
    if res == []:   # no loop
        return False
    else:
        return True

def get_loops(func_ea):

    res = []

    func = get_func(func_ea)
    blocks = [v for v in idaapi.FlowChart(func)]
    new_blocks = []
    func_cfg = nx.DiGraph()

    for bb in blocks:
        if is_inBlock(bb.start_ea, func.start_ea, func.end_ea) and is_inBlock(bb.end_ea, func.start_ea, func.end_ea + 1):
            new_blocks.append(bb)
    blocks = new_blocks

    for bb in blocks:
        for suc in bb.succs():
            func_cfg.add_edge(bb.id, suc.id)
    try:
        #print("[+] finding loops.............")
        res = list(nx.simple_cycles(func_cfg)) # find the loop paths
        #print("[+] ok..............")
        #res = list(nx.cycle_basis(func_cfg))
    except:
        pass

    return res

def get_loops_and_start(func_ea):
    block_dict = {}
    loop_start_list = []
    loops = []
    res = []
    succs = []

    func = get_func(func_ea)

    blocks = [v for v in idaapi.FlowChart(func)]
    
    for i in range(len(blocks)):
        succs.append([])

    func_cfg = nx.DiGraph()
    for bb in blocks:
        block_dict[bb.id] = bb
    for bb in blocks:
        for suc in bb.succs():
            succs[bb.id].append(suc.id)
            func_cfg.add_edge(bb.id, suc.id)
    
    try:
        #print("[+] finding loops.............")
        res = list(nx.simple_cycles(func_cfg)) # find the loop paths
        #print("[+] ok..............")
        #res = list(nx.cycle_basis(G, 0))
    except:
        pass
    
    if res == []:   # no loop
        return loops, loop_start_list

    for path in res:    # get all loop paths
        loops.append(path)

    # need to know the entry and exit of loop
    # loop start: blocks with two entry
    # loop end: blocks with two exit

    #blocks_start = []
    for path in loops:
        #print(path)
        start_bb = None
        for id in path:
            start_bb = id
            #print("Block start: 0x%x" % start_ea)

            #blocks_start.append(start_ea)
            if find_father(succs, id, path) != -1:
                #print("Loop start: 0x%x" % start_ea)
                break
        loop_start_list.append(start_bb)

        #smallest_addr = sorted(blocks_start)[0]
        #loop_start_list.append(smallest_addr)

    return  loops, loop_start_list

def judge_loop_func(func_ea, loops):
    func = get_func(func_ea)

    blocks = [v for v in idaapi.FlowChart(func)]
    threshold = 0.5
    for path in loops:
        if len(blocks) * threshold < len(path):
            return True

    return False




#静态分析不能保证能够分析出所有的输入，在执行的过程中对错误进行分析
def loop_input_analysis(start_bb, path, blocks):
    loop_input = {} # reg: type
    start_id = path.index(start_bb)
    new_path = []
    num = len(path)
    for i in range(num):
        new_path.append(path[(start_id+i) % num])
    path_addr_tuple = []
    for bb_id in new_path:
        bb_start_ea = blocks[bb_id].start_ea
        bb_end_ea = blocks[bb_id].end_ea
        path_addr_tuple.append((bb_start_ea, bb_end_ea))
    for start_ea, end_ea in path_addr_tuple:
        ea = start_ea
        

    return loop_input


def analyze_args_type(func_ea):

    block_dict = {}
    func = get_func(func_ea)

    blocks = [v for v in idaapi.FlowChart(func)]
    for bb in blocks:
        block_dict[bb.id] = bb

    loops_path, loop_start_list = get_loops_and_start(func_ea)
    return None

def get_import_functions():
    segm = idaapi.get_segm_by_name("extern")
    import_functions = []
    for func_ea in Functions():
        func = get_func(func_ea)
        #func_name = get_func_name(func.start_ea)
        #print(func_name, func.flags)
        if func.flags == 5120:
            func_name = get_func_name(func.start_ea)
            import_functions.append(func_name)
    
    return import_functions

def get_prev_head(ea):
    func = get_func(ea)
    func_start = func.start_ea
    func_end = func.end_ea
    refs = list(CodeRefsTo(ea, True))
    prev_ea = []
    for ref in refs:
        if ref >= func_start and ref < func_end:
            prev_ea.append(ref)
    
    return prev_ea

def get_call(func_start_ea):
    call_insts = []
    calls_dict = dict() # addr: call_ea
    inst_info = idaapi.insn_t()
    for addr in FuncItems(func_start_ea):
        if not idaapi.decode_insn(inst_info, addr):
            continue
        if not idaapi.is_call_insn(inst_info):
            if print_insn_mnem(addr) not in ['jmp', 'b', 'j']:
                continue
        call_insts.append(addr)

    for addr in call_insts:
        for ref in XrefsFrom(addr, idaapi.XREF_FAR):
            if not ref.iscode:
                continue
            func = idaapi.get_func(ref.to)
            if not func:
                continue
            # ignore calls to imports / library calls / thunks
            if (func.flags & (idaapi.FUNC_THUNK | idaapi.FUNC_LIB)) != 0:
                continue
            calls_dict[addr] = ref.to
    return calls_dict

def get_call_names(calls_dict):
    calls_name_dict = dict()
    for addr, call_ea in calls_dict.items():
        func_name = get_func_name(call_ea)
        calls_name_dict[addr] = func_name

    return calls_name_dict

def get_all_call(func_start_ea, calls_ea = set()):

    calls_ea.add(func_start_ea)
    call_insts = []
    inst_info = idaapi.insn_t()
    for addr in FuncItems(func_start_ea):
        if not idaapi.decode_insn(inst_info, addr):
            continue
        if not idaapi.is_call_insn(inst_info):
            if print_insn_mnem(addr) not in ['jmp', 'b', 'j']:
                continue
        call_insts.append(addr)

    for addr in call_insts:
        for ref in XrefsFrom(addr, idaapi.XREF_FAR):
            if not ref.iscode:
                continue
            func = idaapi.get_func(ref.to)
            if not func:
                continue
            # ignore calls to imports / library calls / thunks
            if (func.flags & (idaapi.FUNC_THUNK | idaapi.FUNC_LIB)) != 0:
                continue

            if ref.to not in calls_ea:
                get_all_call(ref.to, calls_ea)
    return calls_ea

def get_all_call_name(calls_ea):
    func_names = dict() # call_ea: call name
    for func_addr in calls_ea:
        func_name = get_func_name(func_addr)
        func_names[func_addr] = func_name
    
    return func_names

def get_father_func(func_ea, callee_callers_dict = dict()):
    func = idaapi.get_func(func_ea)
    if func == None:
        print("[-] @0x%x is not a function..." % func_ea)
        return

    callers = set()
    func_ea = func.start_ea
    if func_ea in callee_callers_dict:
        return callee_callers_dict
    refs = list(CodeRefsTo(func_ea, True)) #not contain the dataref e.g. li      $a2, sub_462398
    '''
    add data refs in codes
    refs = list(DataRefsTo(func_ea, True))
    for ea in refs:
        func = idaapi.get_func(ea)
        if func != None:

    '''
    if refs == []:
        return callee_callers_dict
    for ea in refs:
        func = idaapi.get_func(ea)
        if func != None:
            callers.add(func.start_ea)
    if func_ea not in callee_callers_dict:
        callee_callers_dict[func_ea] = callers
    #call_sites = refs
    for ea in callers:
        get_father_func(ea, callee_callers_dict)

    return callee_callers_dict 

def get_call_site(func_ea):
    print("[+] Getting all call sites call @0x%x: %s" % (func_ea, get_func_name(func_ea)))
    func = idaapi.get_func(func_ea)
    if func == None:
        print("[-] @0x%x is not a function..." % func_ea)
        return

    func_ea = func.start_ea
    call_site_func = dict()

    refs = list(CodeRefsTo(func_ea, True))
    for ea in refs:
        func = idaapi.get_func(ea)
        if func != None:
            call_site_func[ea] = func.start_ea
        
    return call_site_func

def get_call_site_by_ea(caller_ea, callee_ea):
    '''
    find the first call site
    '''
    print("[+] caller: 0x%x, callee: 0x%x" % (caller_ea, callee_ea))
    call_site_func = get_call(caller_ea)
    for ea, func_ea in call_site_func.items():
        if func_ea == callee_ea:
            return ea
    return None

def get_all_call_site_by_ea(caller_ea, callee_ea):
    '''
    find the first call site
    '''
    print("[+] caller: 0x%x, callee: 0x%x" % (caller_ea, callee_ea))
    call_site_func = get_call(caller_ea)
    call_site_ea = []
    for ea, func_ea in call_site_func.items():
        if func_ea == callee_ea:
            call_site_ea.append(ea)
    return call_site_ea



def k_shortest_paths(G, source, target, k, weight=None):
    return list(islice(nx.shortest_simple_paths(G, source, target, weight=weight), k))


def k_simple_paths(G, source, target, k):
    return list(islice(nx.all_simple_paths(G, source, target), k))

def get_intra_path_by_id(call_site_ea, func_ea):
    print("[+] Getting block path for @0x%x in function 0x%x (%s)" % (call_site_ea, func_ea, get_func_name(func_ea)))
    block_dict = dict()
    call_site_id = None
    func = get_func(func_ea)
    if func == None:
        print("[-] @0x%x is not a function..." % func_ea)
        return
    blocks = [v for v in idaapi.FlowChart(func)]
    for bb in blocks:
        if call_site_ea >= bb.start_ea and call_site_ea <= bb.end_ea:
            call_site_id = bb.id
    func_cfg = nx.DiGraph()
    for bb in blocks:
        for suc in bb.succs():
            func_cfg.add_edge(bb.id, suc.id)
    root = list((v for v, d in func_cfg.in_degree() if d == 0))
    print("[+] Call site block id is %d" % call_site_id)
    print("[+] Root is:", root)
    #print("[+] DiGraph nodes:", func_cfg.nodes)
    #print("[+] DiGraph edges:", func_cfg.edges)

    block_paths = []

    if len(root) != 1:
        print("[-] Error in finding root block...")
        return block_paths
    #short_path = nx.shortest_path(func_cfg, root[0], call_site_id)
    #print(short_path)

    if len(blocks) > MAX_BLOCK_SIZE:
    #id_paths = nx.all_simple_paths(func_cfg, root[0], call_site_id)
    #id_paths = nx.shortest_simple_paths(func_cfg, root[0], call_site_id)
        id_paths = []
        print("[+] Finding %d (k) shortest simple paths..." % SHORT_PATH_THRESHOLD)
        temp_paths = k_shortest_paths(func_cfg, root[0], call_site_id, SHORT_PATH_THRESHOLD)
        id_paths.extend(temp_paths)
        #print("[+] Finding %d (k) a simple paths..." % ALL_SIMPLE_PATH_THRESHOLD)
        #temp_paths = k_simple_paths(func_cfg, root[0], call_site_id, ALL_SIMPLE_PATH_THRESHOLD)
        #id_paths.extend(temp_paths)
    else:
        id_paths = nx.all_simple_paths(func_cfg, root[0], call_site_id)
    #block_paths.extend(id_paths)

    
    for bb in blocks:
        block_dict[bb.id] = bb
    for path in id_paths:
        bb_path = []
        for id in path:
            bb_path.append(block_dict[id])
        block_paths.append(bb_path)

    '''
    for bb_path in block_paths:
        for bb in bb_path:
            print("0x%x" % bb.start_ea, end = " ")

        print(end = "\n")
    '''
    return block_paths
'''
def get_intra_path(call_site_ea, func_ea):
    func = get_func(func_ea)
    if func == None:
        print("[-] @0x%x is not a function..." % func_ea)
        return
    blocks = [(v.start_ea, v.end_ea) for v in idaapi.FlowChart(func)]
    for bb in blocks:
        if call_site_ea >= bb[0] and call_site_ea <= bb[1]:
            call_site_block = bb[0]
'''

def get_all_path(func_ea):
    call_g = nx.DiGraph()

    func = idaapi.get_func(func_ea)
    if func == None:
        print("[-] @0x%x is not a function..." % func_ea)
        return
    func_ea = func.start_ea
    callee_callers_dict = get_father_func(func_ea)
    for key, vals in callee_callers_dict.items():
        for ea in vals:
            call_g.add_edge(key, ea)
    root = func_ea
    leaves = (v for v, d in call_g.out_degree() if d == 0)
    #leaves = [v for v, d in call_g.out_degree() if d == 0]
    all_paths = []
    for leaf in leaves:
        paths = nx.all_simple_paths(call_g, root, leaf)
        all_paths.extend(paths)
    #print(all_paths)

    return all_paths
    

def get_all_bb_paths(func_ea, deepth = 0xffffffff, mode = 0):
    
    all_paths = get_all_path(func_ea)
    print("[+] Found all paths...")
    all_bb_paths = []

    for path in all_paths:
        callee_ea = func_ea
        for i in range(len(path) - 1):
            if i > deepth:
                break
            caller_ea = path[i+1]
            callee_ea = path[i]
            if mode == 0:
                call_site_ea = get_call_site_by_ea(caller_ea, callee_ea)
                if call_site_ea == None:
                    print("[-] No call site found...")
                    return all_bb_paths
                else:
                    print("[+] Finding block paths...")
                    bb_paths = get_intra_path_by_id(call_site_ea, caller_ea)
                    all_bb_paths.append(bb_paths)
                callee_ea = caller_ea
            else:
                call_site_ea_list = get_all_call_site_by_ea(caller_ea, callee_ea)
                if call_site_ea_list == []:
                    print("[-] No call site found...")
                    return all_bb_paths
                else:
                    print("[+] Finding block paths...")
                    for call_site_ea in call_site_ea_list:
                        bb_paths = get_intra_path_by_id(call_site_ea, caller_ea)
                        all_bb_paths.append(bb_paths)
                callee_ea = caller_ea

    return all_bb_paths


def get_rand_exe_bb_path(func_ea):
    random_path = []
    all_bb_paths = get_all_bb_paths(func_ea, 1)
    for i in range(len(all_bb_paths)):
        bb_paths = all_bb_paths[i]
        if len(bb_paths) > 0:
            rand = random.randint(0, len(bb_paths) - 1)
        else:
            continue
        random_path.append(bb_paths[rand])
    exe_bb_paths = []
    for path in random_path:
        exe_bb_paths = path + exe_bb_paths
    return exe_bb_paths

def split_asm_dst_src(ea):
    opcode = print_insn_mnem(ea)
    asm_code = generate_disasm_line(ea, 0)


def filter_vex_str(vex_str):
    ret_str = None
    if '(' in vex_str:
        pattern = r'\((.*?)\)'
        res = re.findall(pattern, vex_str)
        if len(res) != 1:
            print("[-] Found more than one '()' %s" % vex_str)
            return ret_str
        else:
            res = res[0]
            if ',' in res:
                ret_str = res.split(',')[0].strip(' ')
            else:
                ret_str = res
            return ret_str
    else:
        ret_str = vex_str
        return ret_str




def split_ir_dst_src(ea):
    ins_len = next_head(ea) - ea
    byte_code = ida_bytes.get_bytes(ea, ins_len)
    data_dict = {}
    arch = get_arch()
    inst_arch = vex_arch_dict[arch]
    irsb = pyvex.IRSB(byte_code, mem_addr = ea, arch = inst_arch, opt_level = 1,strict_block_end= True)
    print(irsb)
    for _, stmt in enumerate(irsb.statements):
        if isinstance(stmt, pyvex.stmt.Put):
            stmt_str = stmt.__str__(reg_name=irsb.arch.translate_register_name(stmt.offset, stmt.data.result_size(irsb.tyenv) // 8))
        elif isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.Get):
            stmt_str = stmt.__str__(reg_name=irsb.arch.translate_register_name(stmt.data.offset, stmt.data.result_size(irsb.tyenv) // 8))
        elif isinstance(stmt, pyvex.stmt.Exit):
            stmt_str = stmt.__str__(reg_name=irsb.arch.translate_register_name(stmt.offsIP, irsb.arch.bits // 8))
        else:
            stmt_str = stmt.__str__()
        if '=' in stmt_str:
            #print(stmt_str)
            dst_str, src_str = [x.strip(' ') for x in stmt_str.split('=')]
            #print(dst_str, src_str)
            dst = filter_vex_str(dst_str)
            if dst != None:
                src = filter_vex_str(src_str)
                data_dict[dst] = src

        else:
            continue
    return data_dict
def generate_tot_ea_in_paths(bb_paths, ea):
    tot_ea_paths = []
    for path in bb_paths:
        curr_ea = ea
        ea_path = []
        for i in range(len(path) - 1, -1, -1):
            bb = path[i]
            bb_start = bb.start_ea
            bb_end = bb.end_ea
            if curr_ea > bb_end or curr_ea < bb_start:
                curr_ea = bb_end
            while curr_ea >= bb_start:
                #asm_code = generate_disasm_line(curr_ea, 0)
                ea_path.append(curr_ea)
                curr_ea = prev_head(curr_ea)
            #analysis
                
        tot_ea_paths.append(ea_path)


    return tot_ea_paths

def get_block_vex_list(bb_start, bb_end):
    '''
    @input: block start address, block end address
    @return: the list of block irsb
    '''
    print("[+] Generating vex block @0x%x~@0x%x..." % (bb_start, bb_end))
    arch = get_arch()
    inst_arch = vex_arch_dict[arch]
    bb_irsb = []

    while bb_start < bb_end:
        block_bytes = ida_bytes.get_bytes(bb_start, bb_end - bb_start)
        irsb = pyvex.IRSB(block_bytes, mem_addr = bb_start, arch = inst_arch, opt_level = 1,strict_block_end= True)
        bb_irsb.append(irsb)
        if irsb.size == 0:
            bb_start = next_head(bb_start)
        else:
            bb_start = bb_start + irsb.size
    return bb_irsb

prev_bb_vex = {}
prev_bb_data_dict = {}

def generate_data_dict_vex(bb_paths, ea):
    print("[+] Generating data in vex until to @0x%x..." % ea)
    all_data_paths = []
    global prev_bb_vex
    global prev_bb_data_dict
    for path in bb_paths:
        per_data_path = []
        bb_num = len(path)
        for i in range(0, bb_num):
            bb = path[i]
            data_dict = {}
            bb_start = bb.start_ea
            
            bb_end = bb.end_ea
            if ea < bb_end:
                arch = get_arch()
                if 'mips' in arch:
                    bb_end = ea + 8
                else:
                    bb_end = ea
            if bb_start not in prev_bb_data_dict:
            #if bb_start not in prev_bb_vex:
                bb_irsbs = get_block_vex_list(bb_start, bb_end)
                #prev_bb_vex[bb_start] = bb_irsbs

                for irsb in bb_irsbs:
                    #print(irsb)
                    for _, stmt in enumerate(irsb.statements):
                        if isinstance(stmt, pyvex.stmt.Put):
                            stmt_str = stmt.__str__(reg_name=irsb.arch.translate_register_name(stmt.offset, stmt.data.result_size(irsb.tyenv) // 8))
                        elif isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.Get):
                            stmt_str = stmt.__str__(reg_name=irsb.arch.translate_register_name(stmt.data.offset, stmt.data.result_size(irsb.tyenv) // 8))
                        elif isinstance(stmt, pyvex.stmt.Exit):
                            stmt_str = stmt.__str__(reg_name=irsb.arch.translate_register_name(stmt.offsIP, irsb.arch.bits // 8))
                        else:
                            stmt_str = stmt.__str__()
                        if '=' in stmt_str and 'if' not in stmt_str:
                            #print(stmt_str)
                            dst_str, src_str = [x.strip(' ') for x in stmt_str.split('=')]
                            #print(dst_str, src_str)
                            dst = filter_vex_str(dst_str)
                            if dst != None:
                                src = filter_vex_str(src_str)
                                data_dict[dst] = src

                        else:
                            continue
                prev_bb_data_dict[bb_start] = data_dict
            else:
                data_dict = prev_bb_data_dict[bb_start]
            per_data_path.append(data_dict)
        all_data_paths.append(per_data_path)

        print("[+] Finish in generating data in vex until to @0x%x..." % ea)
    return all_data_paths



def get_stack_args_call_ea(func_ea):
    call_site_func_ea_dict = get_call_site(func_ea)
    stack_call_ea = set()
    for call_site_ea, func_start in call_site_func_ea_dict.items():

        block_paths = get_intra_path_by_id(call_site_ea, func_start)
        all_bb_vex_data_list = generate_data_dict_vex(block_paths, call_site_ea)
        print("[+] Analyzing the args...")
        args_list = ['a0', 'a1', 'a2', 'a3']
        all_args_flow = []
        for args in args_list:
            args_flow = []
            ori_args = args
            for per_path_vex_data_dict in all_bb_vex_data_list:
                #print("[+] Data propagates path...")
                #print("=" * 80)
                args = ori_args
                flow = '[E]<-'
                flow = flow + args + '<-'
                #print(flow, end='')
                for i in range(len(per_path_vex_data_dict)-1, -1, -1):
                    per_dict = per_path_vex_data_dict[i]
                    prev_var = [] #avoid loop
                    while args in per_dict and ('sp' not in args.lower()) and (args not in prev_var):
                        prev_var.append(args)
                        args = per_dict[args]
                        #print(args, end='<-')
                        flow = flow + args + '<-'
                    if 'sp' in args.lower():
                        break
                if 'sp' in args.lower():
                    flow = flow + '[S]'
                    args_flow.append(flow)
                    #print(args)
                    break
                flow = flow + '[S]'
                #print(args)
                args_flow.append(flow)
            all_args_flow.append(args_flow)
        #print(args_flow)
        #print("=" * 80)
        for args_flow in all_args_flow:
            for flow in args_flow:
                if 'sp' in flow:
                    stack_call_ea.add(call_site_ea)
    return list(stack_call_ea)


def generate_data_path(bb_paths, ea, var_name):

    totl_paths = []
    for path in bb_paths:
        curr_ea = ea
        asm_path = {}
        for i in range(len(path) - 1, -1, -1):
            bb = path[i]
            bb_start = bb.start_ea
            bb_end = bb.end_ea
            if curr_ea > bb_end or curr_ea < bb_start:
                curr_ea = bb_end
            while curr_ea >= bb_start:
                asm_code = generate_disasm_line(curr_ea, 0)
                asm_path[curr_ea] = asm_code
                curr_ea = prev_head(curr_ea)
            #analysis
                
        totl_paths.append(asm_path)


    return totl_paths






    
def get_phrase_inst(oprand):
    index = None
    base = None
    scale = None
    has_sib = oprand.specflag1
    sib = oprand.specflag2

    if has_sib:
        base = sib  & 7
        index = (sib >> 3) & 7
        scale = (sib >> 6) & 3
        reg_size = dt_qword if ph.flag & PR_USE64 else dt_dword
        size = reg_size_dict[reg_size]
        # print ('[{} + {}{}]'.format(
        #             get_reg_name(base, size),
        #             get_reg_name(index, size),
        #             '*{}'.format(2**scale) if scale else ''
        #         ))
        return base, index, scale, size
    else:
        base = oprand.reg
        reg_size = dt_qword if ph.flag & PR_USE64 else dt_dword
        size = reg_size_dict[reg_size]
        # print ('[{}]'.format(
        #         get_reg_name(base, size)
        #     ))
        return base, index, scale, size

def change_hex(val):
    bits = 64 if ph.flag & PR_USE64 else 32
    if val & (1 << (bits-1)):
        val -= 1 << bits
    return val

def get_displ_inst(oprand):
    index = None
    base = None
    scale = None
    offset = None
    has_sib = oprand.specflag1
    sib = oprand.specflag2

    if has_sib:
        base = sib  & 7
        index = (sib >> 3) & 7
        scale = (sib >> 6) & 3
        reg_size = dt_qword if ph.flag & PR_USE64 else dt_dword
        size = reg_size_dict[reg_size]
        if base != index:
            # print ('[{} + {}{} + {:x}h]'.format(
            #     get_reg_name(base, size),
            #     get_reg_name(index, size),
            #     '*{}'.format(2**scale) if scale else '',
            #     oprand.addr
            # ))
            offset = oprand.addr
            return base, index, scale, offset, size
        else:
            index = None
            scale = None
            # print ('[{} + {:x}h]'.format(
            #     get_reg_name(base, size),
            #     change_hex(oprand.addr)
            # ))
            offset = oprand.addr
            return base, index, scale, offset, size
    else:
        base = oprand.reg
        reg_size = dt_qword if ph.flag & PR_USE64 else dt_dword
        size = reg_size_dict[reg_size]
        # print ('[{} + {:x}h]'.format(
        #         get_reg_name(base, size),
        #         change_hex(oprand.addr)
        #     ))
        return base, index, scale, offset, size

def get_func_args(func):
    arch = get_arch()
    func_start = func.start_ea
    func_end = func.end_ea
    ea = func_start
    args_dict = OrderedDict()
    args_max_reg_num = 0
    if arch == 'x86':
        args_max_reg_num = args_max_reg_num_dict['x86']
    elif arch == 'x64':
        args_max_reg_num = args_max_reg_num_dict['x64']
    elif 'arm' in arch:
        args_max_reg_num = args_max_reg_num_dict['arm']
    elif 'mips' in arch:
        args_max_reg_num = args_max_reg_num_dict['mips']
    elif 'ppc' in arch:
        args_max_reg_num = args_max_reg_num_dict['ppc']
    
    while ea < func_end:
        tmp = insn_t()
        len = decode_insn(tmp, ea)
        for i in range(UA_MAXOP):
            oprand = tmp.ops[i]
            if oprand.type == o_reg:
                reg_id = oprand.reg
                reg_size = oprand.dtype
                reg_name = get_reg_name(reg_id, reg_size_dict[reg_size])
            elif oprand.type == o_phrase:
                print("@0x%x phrase" % ea)
                get_phrase_inst(oprand)
            elif oprand.type == o_displ:
                print("@0x%x displ" % ea)
                get_displ_inst(oprand)



        opcode = print_insn_mnem(ea)
        #generate_disasm_line()
        optype0 = get_operand_type(ea, 0)
        optype1 = get_operand_type(ea, 1)
        optype2 = get_operand_type(ea, 2)

        #if optype0 == 0x1 and optype1 == 0x4 :  #reg and reg+index memory
        #    src_reg, dst_reg = get_reg_name(ea, arch)

        ea = next_head(ea)

#参数的传递
#addiu   $a0, $sp, 0x218+var_200
#opcode dst, src

ida_get_sys_int_dict = OrderedDict([
    ('x86', (x86_get_sys_int_value)),
    ('x64', (x86_get_sys_int_value)),
    ('mipsbe', (mips_get_sys_int_value)),
    ('mipsle', (mips_get_sys_int_value)),
    ('mips64be', (mips_get_sys_int_value)),
    ('mips64le', (mips_get_sys_int_value)),
    ('armbe', (arm_get_sys_int_value)),
    ('armle', (arm_get_sys_int_value)),
    ('arm64be', (arm_get_sys_int_value)),
    ('arm64le', (arm_get_sys_int_value)),
    ('ppcbe', (ppc_get_sys_int_value)),
    ('ppcle', (ppc_get_sys_int_value)),
    ('ppc64be', (ppc_get_sys_int_value)),
    ('ppc64le', (ppc_get_sys_int_value))
])

def main():
    ea = get_screen_ea()

    exe_bb_paths = []
    func = get_func(ea)
    func_ea = func.start_ea
    loops, loop_start_list = get_loops_and_start(func_ea)
    for i in range(len(loop_start_list)):
        print("block id: %d" % loop_start_list[i])
        print(loops[i])
    #print(loop_start_list)
    #print(loops)
    #call_ea_list = get_stack_args_call_ea(func_ea)
    #for ea in call_ea_list:
    #    print("0x%x" %ea, end=" ")
    #print()
    #random_path = []
    #print(split_ir_dst_src(ea))
    '''
    call_site_ea = 0x43BC24
    block_paths = get_intra_path_by_id(call_site_ea, func.start_ea)
    all_bb_vex_data_list = generate_data_dict_vex(block_paths, call_site_ea)
    args_list = ['a0', 'a1', 'a2']
    all_args_flow = []
    for args in args_list:
        args_flow = []
        for per_path_vex_data_dict in all_bb_vex_data_list:
            #print("[+] Data propagates path...")
            #print("=" * 80)
            flow = '[E]<-'
            flow = flow + args + '<-'

            for i in range(len(per_path_vex_data_dict)-1, -1, -1):
                per_dict = per_path_vex_data_dict[i]
                while args in per_dict and ('sp' not in args.lower()):
                    args = per_dict[args]
                    #print(args, end='<-')
                    flow = flow + args + '<-'
                if 'sp' in args.lower():
                    break
            if 'sp' in args.lower():
                flow = flow + '[S]'
                args_flow.append(flow)
                #print(args)
                break
            flow = flow + '[S]'
            #print(args)
            args_flow.append(flow)
        all_args_flow.append(args_flow)
        #print(args_flow)
        #print("=" * 80)
    print(all_args_flow)
    '''
    #totl_paths = generate_data_path(block_paths, call_site_ea, 'eax')
    #for path in totl_paths:
    #    print(path)
    '''
    block_paths = get_intra_path_by_id(0x455178, func.start_ea)

    for bb_path in block_paths:
        for bb in bb_path:
            print("0x%x" % bb.start_ea, end = " ")

        print(end = "\n")
    all_bb_paths = get_all_bb_paths(func.start_ea)
    for i in range(len(all_bb_paths)):
        bb_paths = all_bb_paths[i]
        rand = random.randint(0, len(bb_paths) - 1)
        random_path.append(bb_paths[rand])

    exe_bb_paths = get_rand_exe_bb_path(func.start_ea)
    for path in random_path:
        for bb in path:
            print("0x%x" % bb.start_ea, end = ' ')
        print(end = '\n')
        
    #for path in random_path:
    #    exe_bb_paths = path + exe_bb_paths
    for bb in exe_bb_paths:
        print("0x%x" % bb.start_ea, end = ' ')
    print(end = '\n')

    for bb_paths in all_bb_paths:
        for path in bb_paths:
            for bb in path:
                print("0x%x" % bb.start_ea, end = ' ')
            print(end = '\n')
        #print(end = '\n')

    
    all_paths = get_all_path(func.start_ea)
    print(all_paths)
    for path in all_paths:
        for ea in path:
            print("0x%x" % ea, end = ' ')
        print(end = '\n')
    '''
    #func_insts = get_func_inst(func)
    #print(func_insts)

    #func_block_start = get_func_blocks(func)
    #print(func_block_start)

    #print(get_import_functions())
    #print(len(get_all_call(func.start_ea)))
    #get_func_args(func)

if __name__ == "__main__":
    fix_boundary()