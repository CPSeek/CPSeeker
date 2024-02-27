#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0
# @Date:   2021-04-22 15:45:53
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2021-04-22 15:45:48

import os

from collections import OrderedDict
from idautils import *
import idaapi
from idaapi import *
from idc import *

reg_size_dict ={
    dt_byte: 1,
    dt_word: 2,
    dt_dword: 4,
    dt_qword: 8
}


ida_x86_reg_dict = OrderedDict()
ida_x64_reg_dict = OrderedDict()
ida_arm_reg_dict = OrderedDict()
ida_mips_reg_dict = OrderedDict()
ida_ppc_reg_dict = OrderedDict()