#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0, SaTC
# @Date:   2021-09-13 19:45:37
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2021-09-13 20:10:05

import sys
import os
from os.path import dirname, abspath

import subprocess
import string
import archinfo
import binascii
import pyvex
import networkx
import angr
from idautils import *
import idaapi
from idaapi import *
from idc import *
from archinfo import Arch

import time
from opcodes import *

archinfo.ArchARMEL.registers = Arch._get_register_dict(archinfo.ArchARMEL)
archinfo.ArchAArch64.registers = Arch._get_register_dict(archinfo.ArchAArch64)
archinfo.ArchMIPS32.registers = Arch._get_register_dict(archinfo.ArchMIPS32)

ordered_argument_regs = {
    'ARMEL': [
        archinfo.ArchARMEL.registers['r0'][0],
        archinfo.ArchARMEL.registers['r1'][0],
        archinfo.ArchARMEL.registers['r2'][0],
        archinfo.ArchARMEL.registers['r3'][0],
        archinfo.ArchARMEL.registers['r4'][0],
        archinfo.ArchARMEL.registers['r5'][0],
        archinfo.ArchARMEL.registers['r6'][0],
        archinfo.ArchARMEL.registers['r7'][0],
        archinfo.ArchARMEL.registers['r8'][0],
        archinfo.ArchARMEL.registers['r9'][0],
        archinfo.ArchARMEL.registers['r10'][0],
        archinfo.ArchARMEL.registers['r11'][0],
        archinfo.ArchARMEL.registers['r12'][0]
    ],
    'AARCH64': [
        archinfo.ArchAArch64.registers['x0'][0],
        archinfo.ArchAArch64.registers['x1'][0],
        archinfo.ArchAArch64.registers['x2'][0],
        archinfo.ArchAArch64.registers['x3'][0],
        archinfo.ArchAArch64.registers['x4'][0],
        archinfo.ArchAArch64.registers['x5'][0],
        archinfo.ArchAArch64.registers['x6'][0],
        archinfo.ArchAArch64.registers['x7'][0],
    ],
    'MIPS32': [
        archinfo.ArchMIPS32.registers['a0'][0],
        archinfo.ArchMIPS32.registers['a1'][0],
        archinfo.ArchMIPS32.registers['a2'][0],
        archinfo.ArchMIPS32.registers['a3'][0],
    ],
}


return_regs = {
    'ARMEL': archinfo.ArchARMEL.registers['r0'][0],
    'AARCH64': archinfo.ArchAArch64.registers['x0'][0],
    'MIPS32': archinfo.ArchMIPS32.registers['v0'][0]
}

link_regs = {
    'ARMEL': archinfo.ArchARMEL.registers['lr'][0],
    'AARCH64': archinfo.ArchAArch64.registers['x30'][0],
    'MIPS32': archinfo.ArchMIPS32.registers['ra'][0]
}


def arg_reg_name(p, n):
    """
    Return the name of a register

    :param p: angr project
    :param n: register offset
    :return: register name
    """

    return p.arch.register_names[ordered_argument_regs[p.arch.name][n]]



# FIXME: so far we only consider arguments passed through registers
def get_ord_arguments_call(p, b_addr):
    """
    Retrieves the list of instructions setting arguments for a function call. It checks the arguments in order
    so to infer the arity of the function:
    Example: if the first argument (e.g., r0 in ARM) is not set, it assumes the arity's function is 0.

    :param p: angr project
    :param b_addr: basic block address
    :return: the arguments of a function call
    """

    set_params = []
    b = p.factory.block(b_addr)
    for reg_off in ordered_argument_regs[p.arch.name]:
        put_stmts = [s for s in b.vex.statements if s.tag == 'Ist_Put' and s.offset == reg_off]
        if not put_stmts:
            break

        # if more than a write, only consider the last one
        # eg r0 = 5
        # ....
        # r0 = 10
        # BL foo
        put_stmt = put_stmts[-1]
        set_params.append(put_stmt)

    return set_params


# FIXME: to check and finish last part
def find_memcpy_like(p, cfg=None):
    """
    Finds all the memcpy-like functions in a given binary (Linux and binary blob)

    :param p: angr project
    :param cfg: angr cfg
    :return: memcpy-like functions
    """

    #memcpy_like = [f.addr for f in p.kb.functions.values() if 'memcpy' in f.name]
    memcpy_like = []
    if cfg is None:
        return memcpy_like

    for fun in cfg.functions.values():
        css = []
        
        #if fun.addr != 0xA10C:
        #    continue
        #print("Function: 0x%x" % fun.addr)
        try:
            no = cfg.get_any_node(fun.addr)
            #css = [pred for pred in no.predecessors]
        except:
            pass

        #if not css:
        #    continue

        #cs = css[0]
        #args = get_ord_arguments_call(p, cs.addr)
        #print("args:%d" % len(args))
        #print(args)
        #if len(args) > 3 or len(args) < 2:
        #    continue
        if len(fun.graph.nodes) > 50:
            continue
        for loop in [x for x in networkx.simple_cycles(fun.graph)]:
            # CMPNE or CMPEQ
            if any([op for l in loop for op in p.factory.block(l.addr).vex.operations if 'cmpeq' in op.lower() or
                                                                                         'cmpne' in op.lower() or 
                                                                                         'cmplt' in op.lower()]):
                # INCREMENT
                wr_tmp = [st for l in loop for st in p.factory.block(l.addr).vex.statements if st.tag == 'Ist_WrTmp']

                cons = [w.constants for w in wr_tmp if hasattr(w, 'data') and hasattr(w.data, 'op') and
                        w.data.op == 'Iop_Add32']
                if cons:
                    cons = [c.value for cs in cons for c in cs]
                # using BootStomp thresholds
                if 1 in cons and len([x for x in fun.blocks]) <= 8:
                    memcpy_like.append(fun.addr)

    return list(set(memcpy_like))

def main():
    
    binary = get_input_file_path()
    try:
        proj = angr.Project(binary, auto_load_libs=False, use_sim_procedures=False)
    except:
        binary = get_idb_path()[0:-4]
        proj = angr.Project(binary, auto_load_libs=False, use_sim_procedures=False)
    cfg = proj.analyses.CFGFast(force_complete_scan=False)
    start_stime = time.time()
    memcpy_like = find_memcpy_like(proj, cfg)
    
    tp = 0
    fp = 0

    #tot = len(Functions())
    #true_copy = len(c_lib_cpy)
    #False_copy = tot - true_copy
    print("=" * 80)
    print("memcpy function:")
    print (memcpy_like)
    end_stime = time.time()
    for func_ea in memcpy_like:
        func_name = get_func_name(func_ea).strip("_")
        print(func_name, end = ', ')
        if func_name in c_lib_cpy:
            tp += 1
        else:
            fp += 1
    precision = tp / (tp + fp)
    recall = tp / len(c_lib_cpy)
    print("precision: %.2f" % precision)
    print("Recall: %.2f" % recall)
    print("Time: %f" % (end_stime - start_stime))

if __name__ == '__main__':
    main()