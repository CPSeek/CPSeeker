#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0
# @Date:   2021-08-11 08:45:53
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2021-08-11 09:45:48

from collections import OrderedDict
from unicorn import *
from unicorn.mips_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *

from print_registers import *



#unicorefuzz

args_max_reg_num_dict = OrderedDict([('x86', 0), ('x64', 6), ('arm', 4), ('mips', 4), ('ppc', 8)])

x86_call_reg_dict = OrderedDict([])

x86_reg_dict = OrderedDict([("EAX", (UC_X86_REG_EAX, 32, 0)),
                            ("EBX", (UC_X86_REG_EBX, 32, 0)),
                            ("ECX", (UC_X86_REG_ECX, 32, 0)),
                            ("EDX", (UC_X86_REG_EDX, 32, 0)),
                            ("ESI", (UC_X86_REG_ESI, 32, 0)),
                            ("EDI", (UC_X86_REG_EDI, 32, 0)),
                            ("EBP", (UC_X86_REG_EBP, 32, 0)),
                            ("ESP", (UC_X86_REG_ESP, 32, 0)),
                            ("EIP", (UC_X86_REG_EIP, 32, 0)),

                            ("AX", (UC_X86_REG_AX, 16, 0)),
                            ("BX", (UC_X86_REG_BX, 16, 0)),
                            ("CX", (UC_X86_REG_CX, 16, 0)),
                            ("DX", (UC_X86_REG_DX, 16, 0)),
                            ("SI", (UC_X86_REG_SI, 16, 0)),
                            ("DI", (UC_X86_REG_DI, 16, 0)),
                            ("BP", (UC_X86_REG_BP, 16, 0)),
                            ("SP", (UC_X86_REG_SP, 16, 0)),
                            ("IP", (UC_X86_REG_IP, 16, 0)),

                            ("ES", (UC_X86_REG_CS, 32, 0xffffffff)),
                            ("ES", (UC_X86_REG_DS, 32, 0xffffffff)),
                            ("ES", (UC_X86_REG_ES, 32, 0xffffffff)),
                            ("FS", (UC_X86_REG_FS, 32, 0xffffffff)),
                            ("GS", (UC_X86_REG_GS, 32, 0xffffffff)),

                            ("AL", (UC_X86_REG_AL, 8, 0)),
                            ("BL", (UC_X86_REG_BL, 8, 0)),
                            ("CL", (UC_X86_REG_CL, 8, 0)),
                            ("DL", (UC_X86_REG_DL, 8, 0)),
                            ("SIL", (UC_X86_REG_SIL, 8, 0)),
                            ("DIL", (UC_X86_REG_DIL, 8, 0)),
                            ("BPL", (UC_X86_REG_BPL, 8, 0)),
                            ("SPL", (UC_X86_REG_SPL, 8, 0)),
                            ("AH", (UC_X86_REG_AH, 8, 0)),
                            ("BH", (UC_X86_REG_BH, 8, 0)),
                            ("CH", (UC_X86_REG_CH, 8, 0)),
                            ("DH", (UC_X86_REG_DH, 8, 0)),


                            ("EFLAGS", (UC_X86_REG_EFLAGS, 32, 0))
                            ])

x64_call_reg_dict = OrderedDict([   ("RDI", (UC_X86_REG_RDI, 64, 0)),
                                    ("RSI", (UC_X86_REG_RSI, 64, 0)),
                                    ("RDX", (UC_X86_REG_RDX, 64, 0)),
                                    ("RCX", (UC_X86_REG_RCX, 64, 0)),
                                    ("R8", (UC_X86_REG_R8, 64, 0)),
                                    ("R9", (UC_X86_REG_R9, 64, 0))
                            ])
x64_reg_dict = OrderedDict([("RAX", (UC_X86_REG_RAX, 64, 0)),
                            ("RBX", (UC_X86_REG_RBX, 64, 0)),
                            ("RCX", (UC_X86_REG_RCX, 64, 0)),
                            ("RDX", (UC_X86_REG_RDX, 64, 0)),
                            ("RSI", (UC_X86_REG_RSI, 64, 0)),
                            ("RDI", (UC_X86_REG_RDI, 64, 0)),
                            ("RBP", (UC_X86_REG_RBP, 64, 0)),
                            ("RSP", (UC_X86_REG_RSP, 64, 0)),
                            ("RIP", (UC_X86_REG_RIP, 64, 0)),
                            ("R8", (UC_X86_REG_R8, 64, 0)),
                            ("R9", (UC_X86_REG_R9, 64, 0)),
                            ("R10", (UC_X86_REG_R10, 64, 0)),
                            ("R11", (UC_X86_REG_R11, 64, 0)),
                            ("R12", (UC_X86_REG_R12, 64, 0)),
                            ("R13", (UC_X86_REG_R13, 64, 0)),
                            ("R14", (UC_X86_REG_R14, 64, 0)),
                            ("R15", (UC_X86_REG_R15, 64, 0)),

                            ("EAX", (UC_X86_REG_EAX, 32, 0)),
                            ("EBX", (UC_X86_REG_EBX, 32, 0)),
                            ("ECX", (UC_X86_REG_ECX, 32, 0)),
                            ("EDX", (UC_X86_REG_EDX, 32, 0)),
                            ("ESI", (UC_X86_REG_ESI, 32, 0)),
                            ("EDI", (UC_X86_REG_EDI, 32, 0)),
                            ("EBP", (UC_X86_REG_EBP, 32, 0)),
                            ("ESP", (UC_X86_REG_ESP, 32, 0)),
                            ("EIP", (UC_X86_REG_EIP, 32, 0)),
                            ("R8D", (UC_X86_REG_R8D, 32, 0)),
                            ("R9D", (UC_X86_REG_R9D, 32, 0)),
                            ("R10D", (UC_X86_REG_R10D, 32, 0)),
                            ("R11D", (UC_X86_REG_R11D, 32, 0)),
                            ("R12D", (UC_X86_REG_R12D, 32, 0)),
                            ("R13D", (UC_X86_REG_R13D, 32, 0)),
                            ("R14D", (UC_X86_REG_R14D, 32, 0)),
                            ("R15D", (UC_X86_REG_R15D, 32, 0)),

                            ("AX", (UC_X86_REG_AX, 16, 0)),
                            ("BX", (UC_X86_REG_BX, 16, 0)),
                            ("CX", (UC_X86_REG_CX, 16, 0)),
                            ("DX", (UC_X86_REG_DX, 16, 0)),
                            ("SI", (UC_X86_REG_SI, 16, 0)),
                            ("DI", (UC_X86_REG_DI, 16, 0)),
                            ("BP", (UC_X86_REG_BP, 16, 0)),
                            ("SP", (UC_X86_REG_SP, 16, 0)),
                            ("IP", (UC_X86_REG_IP, 16, 0)),
                            ("R8W", (UC_X86_REG_R8W, 16, 0)),
                            ("R9W", (UC_X86_REG_R9W, 16, 0)),
                            ("R10W", (UC_X86_REG_R10W, 16, 0)),
                            ("R11W", (UC_X86_REG_R11W, 16, 0)),
                            ("R12W", (UC_X86_REG_R12W, 16, 0)),
                            ("R13W", (UC_X86_REG_R13W, 16, 0)),
                            ("R14W", (UC_X86_REG_R14W, 16, 0)),
                            ("R15W", (UC_X86_REG_R15W, 16, 0)),

                            ("AL", (UC_X86_REG_AL, 8, 0)),
                            ("BL", (UC_X86_REG_BL, 8, 0)),
                            ("CL", (UC_X86_REG_CL, 8, 0)),
                            ("DL", (UC_X86_REG_DL, 8, 0)),
                            ("SIL", (UC_X86_REG_SIL, 8, 0)),
                            ("DIL", (UC_X86_REG_DIL, 8, 0)),
                            ("BPL", (UC_X86_REG_BPL, 8, 0)),
                            ("SPL", (UC_X86_REG_SPL, 8, 0)),
                            ("R8B", (UC_X86_REG_R8B, 8, 0)),
                            ("R9B", (UC_X86_REG_R9B, 8, 0)),
                            ("R10B", (UC_X86_REG_R10B, 8, 0)),
                            ("R11B", (UC_X86_REG_R11B, 8, 0)),
                            ("R12B", (UC_X86_REG_R12B, 8, 0)),
                            ("R13B", (UC_X86_REG_R13B, 8, 0)),
                            ("R14B", (UC_X86_REG_R14B, 8, 0)),
                            ("R15B", (UC_X86_REG_R15B, 8, 0)),
                            ("AH", (UC_X86_REG_AH, 8, 0)),
                            ("BH", (UC_X86_REG_BH, 8, 0)),
                            ("CH", (UC_X86_REG_CH, 8, 0)),
                            ("DH", (UC_X86_REG_DH, 8, 0)),

                            ("RFLAGS", (UC_X86_REG_EFLAGS, 64, 0))
                            ])

arm_call_reg_dict = OrderedDict([   ("R0", (UC_ARM_REG_R0, 32, 0)),
                                    ("R1", (UC_ARM_REG_R1, 32, 0)),
                                    ("R2", (UC_ARM_REG_R2, 32, 0)),
                                    ("R3", (UC_ARM_REG_R3, 32, 0))
                                    ])

arm_reg_dict = OrderedDict([("R0", (UC_ARM_REG_R0, 32, 0)),
                            ("R1", (UC_ARM_REG_R1, 32, 0)),
                            ("R2", (UC_ARM_REG_R2, 32, 0)),
                            ("R3", (UC_ARM_REG_R3, 32, 0)),
                            ("R4", (UC_ARM_REG_R4, 32, 0)),
                            ("R5", (UC_ARM_REG_R5, 32, 0)),
                            ("R6", (UC_ARM_REG_R6, 32, 0)),
                            ("R7", (UC_ARM_REG_R7, 32, 0)),
                            ("R8", (UC_ARM_REG_R8, 32, 0)),

                            ("SB", (UC_ARM_REG_SB, 32, 0)),
                            ("SL", (UC_ARM_REG_SL, 32, 0)),
                            ("FP", (UC_ARM_REG_FP, 32, 0)),
                            ("IP", (UC_ARM_REG_IP, 32, 0)),
                            ("SP", (UC_ARM_REG_SP, 32, 0)),
                            ("LR", (UC_ARM_REG_LR, 32, 0)),
                            ("PC", (UC_ARM_REG_PC, 32, 0)),
                            ("CPSR", (UC_ARM_REG_CPSR, 32, 0)),
                            ("APSR", (UC_ARM_REG_APSR, 32, 0))

                            ])


arm64_reg_dict = OrderedDict([("X0", (UC_ARM64_REG_X0, 64, 0)),
                                      ("X1", (UC_ARM64_REG_X1, 64, 0)),
                                      ("X2", (UC_ARM64_REG_X2, 64, 0)),
                                      ("X3", (UC_ARM64_REG_X3, 64, 0)),
                                      ("X4", (UC_ARM64_REG_X4, 64, 0)),
                                      ("X5", (UC_ARM64_REG_X5, 64, 0)),
                                      ("X6", (UC_ARM64_REG_X6, 64, 0)),
                                      ("X7", (UC_ARM64_REG_X7, 64, 0)),
                                      ("X8", (UC_ARM64_REG_X8, 64, 0)),
                                      ("X9", (UC_ARM64_REG_X9, 64, 0)),
                                      ("X10", (UC_ARM64_REG_X10, 64, 0)),
                                      ("X11", (UC_ARM64_REG_X11, 64, 0)),
                                      ("X12", (UC_ARM64_REG_X12, 64, 0)),
                                      ("X13", (UC_ARM64_REG_X13, 64, 0)),
                                      ("X14", (UC_ARM64_REG_X14, 64, 0)),
                                      ("X15", (UC_ARM64_REG_X15, 64, 0)),
                                      ("X16", (UC_ARM64_REG_X16, 64, 0)),
                                      ("X17", (UC_ARM64_REG_X17, 64, 0)),
                                      ("X18", (UC_ARM64_REG_X18, 64, 0)),
                                      ("X19", (UC_ARM64_REG_X19, 64, 0)),
                                      ("X20", (UC_ARM64_REG_X20, 64, 0)),
                                      ("X21", (UC_ARM64_REG_X21, 64, 0)),
                                      ("X22", (UC_ARM64_REG_X22, 64, 0)),
                                      ("X23", (UC_ARM64_REG_X23, 64, 0)),
                                      ("X24", (UC_ARM64_REG_X24, 64, 0)),
                                      ("X25", (UC_ARM64_REG_X25, 64, 0)),
                                      ("X26", (UC_ARM64_REG_X26, 64, 0)),
                                      ("X27", (UC_ARM64_REG_X27, 64, 0)),
                                      ("X28", (UC_ARM64_REG_X28, 64, 0)),
                                      ("X29", (UC_ARM64_REG_X29, 64, 0)),
                                      ("X30", (UC_ARM64_REG_X30, 64, 0)),

                                      ("W0", (UC_ARM64_REG_W0, 32, 0)),
                                      ("W1", (UC_ARM64_REG_W1, 32, 0)),
                                      ("W2", (UC_ARM64_REG_W2, 32, 0)),
                                      ("W3", (UC_ARM64_REG_W3, 32, 0)),
                                      ("W4", (UC_ARM64_REG_W4, 32, 0)),
                                      ("W5", (UC_ARM64_REG_W5, 32, 0)),
                                      ("W6", (UC_ARM64_REG_W6, 32, 0)),
                                      ("W7", (UC_ARM64_REG_W7, 32, 0)),
                                      ("W8", (UC_ARM64_REG_W8, 32, 0)),
                                      ("W9", (UC_ARM64_REG_W9, 32, 0)),
                                      ("W10", (UC_ARM64_REG_W10, 32, 0)),
                                      ("W11", (UC_ARM64_REG_W11, 32, 0)),
                                      ("W12", (UC_ARM64_REG_W12, 32, 0)),
                                      ("W13", (UC_ARM64_REG_W13, 32, 0)),
                                      ("W14", (UC_ARM64_REG_W14, 32, 0)),
                                      ("W15", (UC_ARM64_REG_W15, 32, 0)),
                                      ("W16", (UC_ARM64_REG_W16, 32, 0)),
                                      ("W17", (UC_ARM64_REG_W17, 32, 0)),
                                      ("W18", (UC_ARM64_REG_W18, 32, 0)),
                                      ("W19", (UC_ARM64_REG_W19, 32, 0)),
                                      ("W20", (UC_ARM64_REG_W20, 32, 0)),
                                      ("W21", (UC_ARM64_REG_W21, 32, 0)),
                                      ("W22", (UC_ARM64_REG_W22, 32, 0)),
                                      ("W23", (UC_ARM64_REG_W23, 32, 0)),
                                      ("W24", (UC_ARM64_REG_W24, 32, 0)),
                                      ("W25", (UC_ARM64_REG_W25, 32, 0)),
                                      ("W26", (UC_ARM64_REG_W26, 32, 0)),
                                      ("W27", (UC_ARM64_REG_W27, 32, 0)),
                                      ("W28", (UC_ARM64_REG_W28, 32, 0)),
                                      ("W29", (UC_ARM64_REG_W29, 32, 0)),
                                      ("W30", (UC_ARM64_REG_W30, 32, 0)),

                                      ("D0", (UC_ARM64_REG_D0, 32, 0)),
                                      ("D1", (UC_ARM64_REG_D1, 32, 0)),
                                      ("D2", (UC_ARM64_REG_D2, 32, 0)),
                                      ("D3", (UC_ARM64_REG_D3, 32, 0)),
                                      ("D4", (UC_ARM64_REG_D4, 32, 0)),
                                      ("D5", (UC_ARM64_REG_D5, 32, 0)),
                                      ("D6", (UC_ARM64_REG_D6, 32, 0)),
                                      ("D7", (UC_ARM64_REG_D7, 32, 0)),
                                      ("D8", (UC_ARM64_REG_D8, 32, 0)),
                                      ("D9", (UC_ARM64_REG_D9, 32, 0)),
                                      ("D10", (UC_ARM64_REG_D10, 32, 0)),
                                      ("D11", (UC_ARM64_REG_D11, 32, 0)),
                                      ("D12", (UC_ARM64_REG_D12, 32, 0)),
                                      ("D13", (UC_ARM64_REG_D13, 32, 0)),
                                      ("D14", (UC_ARM64_REG_D14, 32, 0)),
                                      ("D15", (UC_ARM64_REG_D15, 32, 0)),
                                      ("D16", (UC_ARM64_REG_D16, 32, 0)),
                                      ("D17", (UC_ARM64_REG_D17, 32, 0)),
                                      ("D18", (UC_ARM64_REG_D18, 32, 0)),
                                      ("D19", (UC_ARM64_REG_D19, 32, 0)),
                                      ("D20", (UC_ARM64_REG_D20, 32, 0)),
                                      ("D21", (UC_ARM64_REG_D21, 32, 0)),
                                      ("D22", (UC_ARM64_REG_D22, 32, 0)),
                                      ("D23", (UC_ARM64_REG_D23, 32, 0)),
                                      ("D24", (UC_ARM64_REG_D24, 32, 0)),
                                      ("D25", (UC_ARM64_REG_D25, 32, 0)),
                                      ("D26", (UC_ARM64_REG_D26, 32, 0)),
                                      ("D27", (UC_ARM64_REG_D27, 32, 0)),
                                      ("D28", (UC_ARM64_REG_D28, 32, 0)),
                                      ("D29", (UC_ARM64_REG_D29, 32, 0)),
                                      ("D30", (UC_ARM64_REG_D30, 32, 0)),

                                      ])

mips_call_reg_dict = OrderedDict([  ("A0", (UC_MIPS_REG_A0, 32, 0)),
                                    ("A1", (UC_MIPS_REG_A1, 32, 0)),
                                    ("A2", (UC_MIPS_REG_A2, 32, 0)),
                                    ("A3", (UC_MIPS_REG_A3, 32, 0))
                                    ])
mips_reg_dict = OrderedDict([
                            ("PC", (UC_MIPS_REG_PC, 32, 0)),

                            ("ZERO", (UC_MIPS_REG_ZERO, 32, 0)),

                            ("AT", (UC_MIPS_REG_AT, 32, 0)),

                            ("V0", (UC_MIPS_REG_V0, 32, 0)),
                            ("V1", (UC_MIPS_REG_V1, 32, 0)),

                            ("A0", (UC_MIPS_REG_A0, 32, 0)),
                            ("A1", (UC_MIPS_REG_A1, 32, 0)),
                            ("A2", (UC_MIPS_REG_A2, 32, 0)),
                            ("A3", (UC_MIPS_REG_A3, 32, 0)),

                            ("T0", (UC_MIPS_REG_T0, 32, 0)),
                            ("T1", (UC_MIPS_REG_T1, 32, 0)),
                            ("T2", (UC_MIPS_REG_T2, 32, 0)),
                            ("T3", (UC_MIPS_REG_T3, 32, 0)),
                            ("T4", (UC_MIPS_REG_T4, 32, 0)),
                            ("T5", (UC_MIPS_REG_T5, 32, 0)),
                            ("T6", (UC_MIPS_REG_T6, 32, 0)),
                            ("T7", (UC_MIPS_REG_T7, 32, 0)),
                            ("T8", (UC_MIPS_REG_T8, 32, 0)),
                            ("T9", (UC_MIPS_REG_T9, 32, 0)),

                            ("S0", (UC_MIPS_REG_S0, 32, 0)),
                            ("S1", (UC_MIPS_REG_S1, 32, 0)),
                            ("S2", (UC_MIPS_REG_S2, 32, 0)),
                            ("S3", (UC_MIPS_REG_S3, 32, 0)),
                            ("S4", (UC_MIPS_REG_S4, 32, 0)),
                            ("S5", (UC_MIPS_REG_S5, 32, 0)),
                            ("S6", (UC_MIPS_REG_S6, 32, 0)),
                            ("S7", (UC_MIPS_REG_S7, 32, 0)),

                            ("K0", (UC_MIPS_REG_K0, 32, 0)),
                            ("K1", (UC_MIPS_REG_K1, 32, 0)),

                            ("GP", (UC_MIPS_REG_GP, 32, 0)),

                            ("SP", (UC_MIPS_REG_SP, 32, 0)),

                            ("FP", (UC_MIPS_REG_FP, 32, 0)),

                            ("RA", (UC_MIPS_REG_RA, 32, 0)),

                            ("F0", (UC_MIPS_REG_F0, 32, 0)),
                            ("F1", (UC_MIPS_REG_F1, 32, 0)),
                            ("F2", (UC_MIPS_REG_F2, 32, 0)),
                            ("F3", (UC_MIPS_REG_F3, 32, 0)),
                            ("F4", (UC_MIPS_REG_F4, 32, 0)),
                            ("F5", (UC_MIPS_REG_F5, 32, 0)),
                            ("F6", (UC_MIPS_REG_F6, 32, 0)),
                            ("F7", (UC_MIPS_REG_F7, 32, 0)),
                            ("F8", (UC_MIPS_REG_F8, 32, 0)),
                            ("F9", (UC_MIPS_REG_F9, 32, 0)),
                            ("F10", (UC_MIPS_REG_F10, 32, 0)),
                            ("F11", (UC_MIPS_REG_F11, 32, 0)),
                            ("F12", (UC_MIPS_REG_F12, 32, 0)),
                            ("F13", (UC_MIPS_REG_F13, 32, 0)),
                            ("F14", (UC_MIPS_REG_F14, 32, 0)),
                            ("F15", (UC_MIPS_REG_F15, 32, 0)),
                            ("F16", (UC_MIPS_REG_F16, 32, 0)),
                            ("F17", (UC_MIPS_REG_F17, 32, 0)),
                            ("F18", (UC_MIPS_REG_F18, 32, 0)),
                            ("F19", (UC_MIPS_REG_F19, 32, 0)),
                            ("F20", (UC_MIPS_REG_F20, 32, 0)),
                            ("F21", (UC_MIPS_REG_F21, 32, 0)),
                            ("F22", (UC_MIPS_REG_F22, 32, 0)),
                            ("F23", (UC_MIPS_REG_F23, 32, 0)),
                            ("F24", (UC_MIPS_REG_F24, 32, 0)),
                            ("F25", (UC_MIPS_REG_F25, 32, 0)),
                            ("F26", (UC_MIPS_REG_F26, 32, 0)),
                            ("F27", (UC_MIPS_REG_F27, 32, 0)),
                            ("F28", (UC_MIPS_REG_F28, 32, 0)),
                            ("F29", (UC_MIPS_REG_F29, 32, 0)),
                            ("F30", (UC_MIPS_REG_F30, 32, 0)),
                            ("F31", (UC_MIPS_REG_F31, 32, 0))
                        ])
ppc_reg_dict = OrderedDict([])
ppc_call_reg_dict = OrderedDict([])
'''
mips_reg_dict = {
    UC_MIPS_REG_PC: 0, UC_MIPS_REG_0: 0, UC_MIPS_REG_1: 0, UC_MIPS_REG_2: 0,
    UC_MIPS_REG_3: 0, UC_MIPS_REG_4: 0, UC_MIPS_REG_5: 0, UC_MIPS_REG_6: 0,
    UC_MIPS_REG_7: 0, UC_MIPS_REG_8: 0, UC_MIPS_REG_9: 0, UC_MIPS_REG_10: 0,
    UC_MIPS_REG_11: 0, UC_MIPS_REG_12: 0, UC_MIPS_REG_13: 0, UC_MIPS_REG_14: 0,
    UC_MIPS_REG_15: 0, UC_MIPS_REG_16: 0, UC_MIPS_REG_17: 0, UC_MIPS_REG_18: 0,
    UC_MIPS_REG_19: 0, UC_MIPS_REG_20: 0, UC_MIPS_REG_21: 0, UC_MIPS_REG_22: 0,
    UC_MIPS_REG_23: 0, UC_MIPS_REG_24: 0, UC_MIPS_REG_25: 0, UC_MIPS_REG_26: 0,
    UC_MIPS_REG_27: 0, UC_MIPS_REG_28: 0, UC_MIPS_REG_29: 0, UC_MIPS_REG_30: 0,
    UC_MIPS_REG_31: 0
}
'''

uc_arch_mode_dict = OrderedDict([
    ('x86', (UC_ARCH_X86,    UC_MODE_32)),
    ('x64', (UC_ARCH_X86,    UC_MODE_64)),
    ('mipsbe', (UC_ARCH_MIPS,   UC_MODE_MIPS32  | UC_MODE_BIG_ENDIAN )),
    ('mipsle', (UC_ARCH_MIPS,   UC_MODE_MIPS32  | UC_MODE_LITTLE_ENDIAN)),
    ('mips64be', (UC_ARCH_MIPS,   UC_MODE_MIPS64  | UC_MODE_BIG_ENDIAN)),
    ('mips64le', (UC_ARCH_MIPS,   UC_MODE_MIPS64  | UC_MODE_LITTLE_ENDIAN)),
    ('armbe', (UC_ARCH_ARM,    UC_MODE_ARM     | UC_MODE_BIG_ENDIAN)),
    ('armle', (UC_ARCH_ARM,    UC_MODE_ARM     | UC_MODE_LITTLE_ENDIAN)),
    ('arm64be', (UC_ARCH_ARM64,  UC_MODE_ARM     | UC_MODE_BIG_ENDIAN)),
    ('arm64le', (UC_ARCH_ARM64,  UC_MODE_ARM     | UC_MODE_LITTLE_ENDIAN)),
    ('ppcbe', (UC_ARCH_PPC, UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN)),
    ('ppcle', (UC_ARCH_PPC, UC_MODE_PPC32 | UC_MODE_LITTLE_ENDIAN)),
    ('ppc64be', (UC_ARCH_PPC, UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN)),
    ('ppc64le', (UC_ARCH_PPC, UC_MODE_PPC64 | UC_MODE_LITTLE_ENDIAN))
    ])

UC_PPC_REG_R3 = 0
uc_ret_reg_dict = OrderedDict([
    ('x86', (UC_X86_REG_EAX)),
    ('x64', (UC_X86_REG_RAX)),
    ('mipsbe', (UC_MIPS_REG_V0)),   #twe return reg, UC_MIPS_REG_V0, UC_MIPS_REG_V1
    ('mipsle', (UC_MIPS_REG_V0)),
    ('mips64be', (UC_MIPS_REG_V0)),
    ('mips64le', (UC_MIPS_REG_V0)),
    ('armbe', (UC_ARM_REG_R0)),
    ('armle', (UC_ARM_REG_R0)),
    ('arm64be', (UC_ARM64_REG_X0)),
    ('arm64le', (UC_ARM64_REG_X0)),
    ('ppcbe', (UC_PPC_REG_R3)),
    ('ppcle', (UC_PPC_REG_R3)),
    ('ppc64be', (UC_PPC_REG_R3)),
    ('ppc64le', (UC_PPC_REG_R3))
    ])

uc_reg_dict = OrderedDict([
    ('x86', (x86_reg_dict)),
    ('x64', (x64_reg_dict)),
    ('mipsbe', (mips_reg_dict)),
    ('mipsle', (mips_reg_dict)),
    ('mips64be', (mips_reg_dict)),
    ('mips64le', (mips_reg_dict)),
    ('armbe', (arm_reg_dict)),
    ('armle', (arm_reg_dict)),
    ('arm64be', (arm64_reg_dict)),
    ('arm64le', (arm64_reg_dict)),
    ('ppcbe', (ppc_reg_dict)),
    ('ppcle', (ppc_reg_dict)),
    ('ppc64be', (ppc_reg_dict)),
    ('ppc64le', (ppc_reg_dict))
    ])

x86_arg_reg_dict = []
x64_arg_reg_dict = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9]
mips_arg_reg_dict = [UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3]
ppc_arg_reg_dict = []
arm_arg_reg_dict = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]
arm64_arg_reg_dict = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5,UC_ARM64_REG_X6,UC_ARM64_REG_X7]

uc_arg_reg_dict = OrderedDict([
    ('x86', (x86_arg_reg_dict)),
    ('x64', (x64_arg_reg_dict)),
    ('mipsbe', (mips_arg_reg_dict)),
    ('mipsle', (mips_arg_reg_dict)),
    ('mips64be', (mips_arg_reg_dict)),
    ('mips64le', (mips_arg_reg_dict)),
    ('armbe', (arm_arg_reg_dict)),
    ('armle', (arm_arg_reg_dict)),
    ('arm64be', (arm64_arg_reg_dict)),
    ('arm64le', (arm64_arg_reg_dict)),
    ('ppcbe', (ppc_arg_reg_dict)),
    ('ppcle', (ppc_arg_reg_dict)),
    ('ppc64be', (ppc_arg_reg_dict)),
    ('ppc64le', (ppc_arg_reg_dict))
    ])

UC_PPC_REG_SP = 0

uc_sp_reg_dict = OrderedDict([
    ('x86', (UC_X86_REG_ESP)),
    ('x64', (UC_X86_REG_RSP)),
    ('mipsbe', (UC_MIPS_REG_SP)),
    ('mipsle', (UC_MIPS_REG_SP)),
    ('mips64be', (UC_MIPS_REG_SP)),
    ('mips64le', (UC_MIPS_REG_SP)),
    ('armbe', (UC_ARM_REG_SP)),
    ('armle', (UC_ARM_REG_SP)),
    ('arm64be', (UC_ARM64_REG_SP)),
    ('arm64le', (UC_ARM64_REG_SP)),
    ('ppcbe', (UC_PPC_REG_SP)),
    ('ppcle', (UC_PPC_REG_SP)),
    ('ppc64be', (UC_PPC_REG_SP)),
    ('ppc64le', (UC_PPC_REG_SP))
    ])
UC_PPC_REG_PC = 0
uc_ip_reg_dict = OrderedDict([
    ('x86', (UC_X86_REG_EIP)),
    ('x64', (UC_X86_REG_RIP)),
    ('mipsbe', (UC_MIPS_REG_PC)),
    ('mipsle', (UC_MIPS_REG_PC)),
    ('mips64be', (UC_MIPS_REG_PC)),
    ('mips64le', (UC_MIPS_REG_PC)),
    ('armbe', (UC_ARM_REG_PC)),
    ('armle', (UC_ARM_REG_PC)),
    ('arm64be', (UC_ARM64_REG_PC)),
    ('arm64le', (UC_ARM64_REG_PC)),
    ('ppcbe', (UC_PPC_REG_PC)),
    ('ppcle', (UC_PPC_REG_PC)),
    ('ppc64be', (UC_PPC_REG_PC)),
    ('ppc64le', (UC_PPC_REG_PC))
    ])

UC_PPC_REG_LR = 0

uc_lr_reg_dict = OrderedDict([
    ('x86', (UC_X86_REG_ESP)),
    ('x64', (UC_X86_REG_RSP)),
    ('mipsbe', (UC_MIPS_REG_RA)),
    ('mipsle', (UC_MIPS_REG_RA)),
    ('mips64be', (UC_MIPS_REG_RA)),
    ('mips64le', (UC_MIPS_REG_RA)),
    ('armbe', (UC_ARM_REG_LR)),
    ('armle', (UC_ARM_REG_LR)),
    ('arm64be', (UC_ARM64_REG_LR)),
    ('arm64le', (UC_ARM64_REG_LR)),
    ('ppcbe', (UC_PPC_REG_LR)),
    ('ppcle', (UC_PPC_REG_LR)),
    ('ppc64be', (UC_PPC_REG_LR)),
    ('ppc64le', (UC_PPC_REG_LR))
    ])


uc_print_reg_dict = OrderedDict([
    ('x86', (print_x86_regs)),
    ('x64', (print_x86_regs)),
    ('mipsbe', (print_mips_regs)),
    ('mipsle', (print_mips_regs)),
    ('mips64be', (print_mips_regs)),
    ('mips64le', (print_mips_regs)),
    ('armbe', (print_arm_regs)),
    ('armle', (print_arm_regs)),
    ('arm64be', (print_arm_regs)),
    ('arm64le', (print_arm_regs)),
    ('ppcbe', (print_ppc_regs)),
    ('ppcle', (print_ppc_regs)),
    ('ppc64be', (print_ppc_regs)),
    ('ppc64le', (print_ppc_regs))
])