#combine_block.py
import keypatch
from idaapi import *
import capstone
import struct

combine_blocks={}
ea_blcok_map={}
codes_map={}

def nop_block(block):
    nop_code=0x90
    for i in range(block.end_ea-block.start_ea):
        idc.patch_byte(block.start_ea+i,nop_code)


so_base=idaapi.get_imagebase()
fun_offset=0x25D0
f_blocks = idaapi.FlowChart(idaapi.get_func(so_base+fun_offset), flags=idaapi.FC_PREDS)
for block in f_blocks:
    if block.start_ea==block.end_ea:
        continue
    ea_blcok_map[block.start_ea]=block
    codes_map[block.start_ea]=get_bytes(block.start_ea,block.end_ea-block.start_ea)
    block_end=idc.prev_head(block.end_ea)
    if idc.print_insn_mnem(block_end).startswith('j'):
        next_block=get_operand_value(block_end,0)
        combine_blocks[block.start_ea]=next_block
    else:
        combine_blocks[block.start_ea]=block.end_ea
    # 将所有块nop后再将原始指令连接    
    nop_block(block)



first_block=so_base+fun_offset
wirte_offect=0

while True:
    if wirte_offect==0:
        block=ea_blcok_map[first_block]
    else:
        block=ea_blcok_map[next_block]
    
    codes=codes_map[block.start_ea]
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
    for code in md.disasm(codes,block.start_ea):
        if code.mnemonic=='jmp' or code.mnemonic.startswith('cmov') or code.mnemonic=='nop': #排除这些指令
            continue
        block_bytes=bytes(code.bytes)
        if code.mnemonic=='call':
            if code.op_str.startswith('0x'):
                called_addr=int(code.op_str,16)
                fix_addr=called_addr-fun_offset-wirte_offect-5
                fix_bytes=struct.pack('i',fix_addr)
                block_bytes=bytes(code.bytes[0:1])+fix_bytes
        print('combine_block:0x%x'%block.start_ea)
        patch_bytes(first_block+wirte_offect,block_bytes)
        wirte_offect=wirte_offect+len(block_bytes)

    if block.start_ea in combine_blocks:     
        next_block=combine_blocks[block.start_ea]
        if not next_block in ea_blcok_map:
            break
    else:
        break
    
    # print('0x%x,0x%x'%(key,combine_blocks[key]))



