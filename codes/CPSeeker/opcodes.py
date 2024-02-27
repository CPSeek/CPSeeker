#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0
# @Date:   2020-12-08 08:14:53
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2020-12-08 08:15:19

#extract the opcodes for IDA SDK allins.hpp

mips_load = {'lb','lbu','lh','lhu','lw','lwu','lwl','lwr','ld','ldl', 'ldr', 'ulh', 'uld', 'ulhu', 'ulw'}
mips_store = {'sb','sh','sw','swl','swr','sdl','sdr','sd', 'usd', 'ush', 'usw'}
mips_branch = {'bgez','bgezl','bgtz','bgtzl','blez','blezl','bltz','bltzl', \
            'beq','beql','bne','bnel', 'bnez', 'bnezl','beqz','beqzl', 'j'}
mips_arithmetic = {'add', 'addu', 'addi', 'addiu', 'sll'}
mips_move = {'move', 'movf', 'movt', 'movn', 'movz'}

mips_regs = {'$zer0': 0, '$at': 1, '$v0': 2, '$v1': 3, '$a0': 4, '$a1': 5,\
            '$a2': 6, '$a3': 7, '$t0': 8, '$t1': 9, '$t2': 10, '$t3': 11,\
            '$t4': 12, '$t5': 13, '$t6': 14, '$t7': 15, '$s0': 16, '$s1': 17,\
            '$s2': 18, '$s3': 19, '$s4': 20, '$s5': 21, '$s6': 22, '$s7': 23,\
            '$t8': 24, '$t9': 25, '$k0': 26, '$k1': 27, '$gp': 28, '$sp': 29,\
            '$s8': 30, '$ra': 31}
mips_call = {'jalr', 'jal', 'bal', 'beqlr'} #'b', 'j',

arm_load = {'LDR','LDRB','LDRD','LDRT','LDRBT','LDRH','LDRSB','LDRSH','LDM'}
arm_store = {'STR','STRB','STRD','STRT','STRBT','STRH','STM'}
arm_branch = {'BEQ','BNE','BLT','BLE','BGT','BGE','BLS','BHS','BLO', 'BCS'}
arm_arithmetic = {'ADD', 'ADC', 'ADDS'}
arm_regs = {'R0': 0, 'R1': 1, 'R2': 2, 'R3': 3, 'R4': 4, 'R5': 5,\
            'R6': 6, 'R7': 7, 'R8': 8, 'R9': 9, 'R10': 10, 'R11': 11,\
            'R12': 12, 'SP': 13, 'LR': 14, 'PC': 15}
arm_call = {'BL', 'BLX'}

ppc_load = {'lbz', 'lbzu', 'lbzux', 'lbzx', 'lha', 'lhau', 'lhaux', 'lhax', 'lhz', \
            'lhzu', 'lhzux', 'lhzx', 'lwz', 'lwzu', 'lwzux', 'lwzx'}
ppc_store = {'stb', 'stbu', 'stbux', 'stbx', 'sth', 'sthu', 'sthx', 
                'stw', 'stwu', 'stwux', 'stwx'}
ppc_branch = {'b', 'bne', 'beq', 'bge', 'ble', 'bgt','blt', 'bdnz'}
ppc_regs = {'r0': 0, 'r1': 1, 'r2': 2, 'r3': 3, 'r4': 4, 'r5': 5,\
            'r6': 6, 'r7': 7, 'r8': 8, 'r9': 9, 'r10': 10, 'r11': 11,\
            'r12': 12, 'r13': 13, 'r14': 14, 'r15': 15, 'r16': 16, 'r17': 17,\
            'r18': 18, 'r19': 19, 'r20': 20, 'r21': 21, 'r22': 22, 'r23': 23,\
            'r24': 24, 'r25': 25, 'r26': 26, 'r27': 27, 'r28': 28, 'r29': 29,\
            'r30': 30, 'r31': 31}
ppc_call = {'bl', 'beqlr', 'bctrl', 'bctr'}
#for ppc if 'u' in the end of opcode, this means it contains a update opcode (arithmetic)

ppc_arithmetic = {'addi','addic', 'addic.'}


x86_load = {'mov','movzx','movsz'}          #mov reg, {}
x86_store = {'mov','movzx','movzx'}         #mov {}, reg
x86_call = {'call'}

#rep movsb represents a loop with copy

x86_move = {'mov','movzx','movzx', 'rep'}
x86_branch = {'ja','jae','jb','jbe','jc','jcxz','jecxz','jrcxz','je','jg','jge','jl', \
            'jle','jna','jnae','jnb','jnbe','jnc','jne','jng','jnge','jnl','jnle','jno', \
            'jnp','jns','jnz','jo','jp','jpe','jpo','js','jz'}
x86_arithmetic = {'add', 'inc'}
x86_regs = {'eax': 0, 'ebx': 1, 'ecx': 2, 'edx': 3, 'esi': 4, 'edi': 5, 'ebp': 6, 'esp': 7, 'eip': 8}

x64_load = {}
x64_stoee = {}
x64_branch = {}


copy_funcs_name = {'memcpy', 'strcpy', 'memmove','strcat','strncat',\
                    'strncpy', 'memccpy','strxfrm','alps_lib_toupper',\
                    'base64_encode','base64_decode','ToBase64','FromBase64','CompressPath',\
                    'blt_str_utf8_cpy','pg_base64_encode','pg_based64_decode','hex_encode',\
                    'hex_decode','esc_encode','esc_decode','sstrncpy',\
                    'merge', 'sha1_transform', 'sha1_update', 'sha256_transform',\
                    'sha256_update', 'md5_transform', 'md5_update', 'md2_transform',\
                    'md2_update', 'xor_buf', 'aes_key_setup', 'arcfour_key_setup',\
                    'arcfour_generate_stream', 'blowfish_key_setup', 'int_to_string',\
                    '_memcpy', 'wcscat', 'wcscpy', 'wcsxfrm', 'mbsnrtowcs','strlcpy',\
                    'wcsncat', 'wcsncpy', 'wmemcpy', 'wmemmove', 'wcsnrtombs', 'util_memcpy',\
                    'resolv_domain_to_hostname','resolv_skip_name','rand_str','stpcpy','__cpy',\
                    'test_ternarySearch','test_jump_search','test_interpolationSearch',\
                    'test_fibMonaccianSearch','blowfish_key_setup', 'md5_final','rot13_test',\
                    'sha256_test','sha256_final','sha1_test','sha1_final','test_string','w_copy'}

c_lib_cpy = [
    "memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat", "strxfrm",
    "wcscat", "wcscpy", "wcsxfrm", "wcsncpy", "wmemmove", "wcsncat", "wmemcpy",
    "wcsnrtombs",
    "my_copy", "yystpcpy", "yy_flex_strncpy", "zmemcpy", "stpcpy", "unistrcpy",
    "BUF_strlcpy", "tr_strlcpy", "g_strlcpy", "wxStrncpy", "wxStrcpy", "wxStrcat",
    "w_copy", "strlcpy", "util_memcpy", "resolv_domain_to_hostname", "MD5_memcpy",
    "alpha_strcpy_fn", "StrnCpy_fn", "strncpy_w", "sstrncpy", "alps_lib_toupper"
    ]