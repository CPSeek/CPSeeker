#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0
# @Date:   2021-04-22 15:45:53
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2021-04-22 15:45:48

import os
import networkx as nx

from unicorn import *
from unicorn.mips_const import *
from unicorn.arm_const import *
from unicorn.x86_const import *

from opcodes import *

def print_mips_regs(mu):
    reg_map =   {0: 'pc', 1: 'zer0', 2: 'at', 3: 'v0', 4: 'v1', 5: 'a0', 
            6:'a1', 7: 'a2', 8: 'a3', 9: 't0', 
            10: 't1', 11: 't2', 12: 't3', 13: 't4', 
            14: 't5', 15: 't6', 16: 't7', 17: 's0', 
            18: 's1', 19: 's2', 20: 's3', 21: 's4',
            22: 's5', 23: 's6', 24: 's7', 25: 't8', 
            26: 't9', 27: 'k0', 28: 'k1', 29: 
            'gp', 30:'sp', 31: 's8', 32:'ra'}
    regs = []
    for i in range(1, 34):
        regs.append(mu.reg_read(i))

    print ("{}: {}".format(reg_map[0], hex(regs[0])))
    for i in range(1, len(regs)):
        print ("{:2}: {:10}".format(reg_map[i], hex(regs[i])), end='\t')
        if (i % 4) == 0:
            print(end='\n')
    print(end='\n')

def print_arm_regs(mu):
    '''
    UC_ARM_REG_LR = 10, UC_ARM_REG_PC = 11, UC_ARM_REG_SP = 12

    UC_ARM_REG_R0 = 66, UC_ARM_REG_R1 = 67, UC_ARM_REG_R2 = 68
    UC_ARM_REG_R3 = 69, UC_ARM_REG_R4 = 70, UC_ARM_REG_R5 = 71
    UC_ARM_REG_R6 = 72, UC_ARM_REG_R7 = 73, UC_ARM_REG_R8 = 74
    UC_ARM_REG_R9 = 75, UC_ARM_REG_R10 = 76, UC_ARM_REG_R11 = 77
    UC_ARM_REG_R12 = 78
    '''
    reg_map =   {63: 'LR', 64: 'PC', 65: 'SP', 
            66: 'R0', 67: 'R1', 68: 'R2', 
            69:'R3', 70: 'R4', 71: 'R5', 72: 'R6', 
            73: 'R7', 74: 'R8', 75: 'R9', 76: 'R10', 
            77: 'R11', 78: 'R12'}
    regs = []
    for i in range(10, 13):
        regs.append(mu.reg_read(i))
    for i in range(66, 79):
        regs.append(mu.reg_read(i))
    for i in range(0, len(regs)):
        print ("{:4}: {:10}".format(reg_map[i+63], hex(regs[i])), end='\t')
        if (i % 4) == 0:
            print(end='\n')
    print(end='\n')
    return 0

def print_x86_regs(mu):

    reg_map =   {1: 'AH', 2: 'AL', 3: 'AX', 4: 'BH', 5:'BL', 
            6:'BP', 7: 'BPL', 8: 'BX', 9: 'CH', 
            10: 'CL', 11: 'CS', 12: 'CX', 13: 'DH', 
            14: 'DI', 15: 'DIL', 16: 'DL', 17: 'DS', 
            18: 'DX', 19: 'EAX', 20: 'EBP', 21: 'EBX',
            22: 'ECX', 23: 'EDI', 24: 'EDX', 25: 'EFLAGS', 
            26: 'EIP', 27: 'EIZ', 28: 'ES', 29: 'ESI', 30:'ESP', 
            31: 'FPSW', 32:'FS', 33: 'GS', 34: 'IP', 35: 'RAX',
            36: 'RBP', 37: 'RBX', 38: 'RCX', 39: 'RDI', 40: 'RDX',
            41: 'RIP', 42: 'RIZ', 43: 'RSI', 44: 'RSP'}
    regs = []
    for i in range(1, 45):
        regs.append(mu.reg_read(i))

    for i in range(1, len(regs) + 1):
        print ("{:6}: {:10}".format(reg_map[i], hex(regs[i-1])), end='\t')
        if (i % 4) == 0:
            print(end='\n')
    print(end='\n')
    return 0

def print_ppc_regs(mu):
    #to do
    return 0
