#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0, Karonte
# @Date:   2021-09-13 19:45:37
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2021-09-13 20:10:05

import sys
import os
from os.path import dirname, abspath
import subprocess
import string
import archinfo
from archinfo import Arch
import binascii
import pyvex
import networkx
import angr
from idautils import *
import idaapi
from idaapi import *
from idc import *

archinfo.ArchARMEL.registers = Arch._get_register_dict(archinfo.ArchARMEL)
archinfo.ArchAArch64.registers = Arch._get_register_dict(archinfo.ArchAArch64)
archinfo.ArchMIPS32.registers = Arch._get_register_dict(archinfo.ArchMIPS32)
ordered_agument_regs = {
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


return_regs ={
    'ARMEL': archinfo.ArchARMEL.registers['r0'][0],
    'AARCH64': archinfo.ArchAArch64.registers['x0'][0],
    'MIPS32': archinfo.ArchMIPS32.registers['v0'][0]
}

link_regs ={
    'ARMEL': archinfo.ArchARMEL.registers['lr'][0],
    'AARCH64': archinfo.ArchAArch64.registers['x30'][0],
    'MIPS32': archinfo.ArchMIPS32.registers['ra'][0]
}


def arg_reg_name(p, n):
    return p.arch.register_names[ordered_agument_regs[p.arch.name][n]]


def get_ord_arguments_call(p, b_addr):
    """
        Retrieves the list of instructions setting arguments for a function call. It checks the arguments in order
        so to infer the artity of the function:
        Example: if the first argument (e.g., r0 in ARM) is not set, it assumes the arity's function is 0.

        :param b: basic block address
        :return:
        """

    return get_ord_arguments_call_caller(p, b_addr)


# FIXME: so far we only consider arguments passed through registers
def get_ord_arguments_call_caller(p, b_addr):
    """
        Retrieves the list of instructions setting arguments for a function call. It checks the arguments in order
        so to infer the artity of the function:
        Example: if the first argument (e.g., r0 in ARM) is not set, it assumes the arity's function is 0.

        :param b: basic block address
        :return:
        """

    set_params = []
    b = p.factory.block(b_addr)
    for reg_off in ordered_agument_regs[p.arch.name]:
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



# FIXME: to finish
def find_memcpy_like(p, cfg=None):
    #memcpy_like = [f.addr for f in p.kb.functions.values() if 'memcpy' in f.name]
    memcpy_like = []
    if cfg is None:
        return memcpy_like

    tots = []
    for fun in cfg.functions.values():
        css = []
        print("Function: 0x%x" % fun.addr)
        try:
            no = cfg.get_any_node(fun.addr)
            css = [pred for pred in no.predecessors]
        except:
            pass

        if css == []:
            continue

        cs = css[0]
        args = get_ord_arguments_call(p, cs.addr)
        if len(args) > 3 or len(args) < 2:
            continue
        if len(fun.graph.nodes) > 50:
            continue
        for loop in [x for x in networkx.simple_cycles(fun.graph)]:
            # CMPNE or CMPEQ
            print(loop)
            if any([op for l in loop for op in p.factory.block(l.addr).vex.operations if 'cmpeq' in op.lower() or 'cmpne' in op.lower()]):
                tots.append(hex(fun.addr))
                # INCREMENT
                wr_tmp = [st for l in loop for st in p.factory.block(l.addr).vex.statements if st.tag == 'Ist_WrTmp']
                cons = [w.constants for w in wr_tmp if hasattr(w, 'data') and hasattr(w.data, 'op') and w.data.op == 'Iop_Add32']
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
    cfg = proj.analyses.CFG()
    memcpy_like = find_memcpy_like(proj, cfg)

    print(memcpy_like)

if __name__ == '__main__':
    main()