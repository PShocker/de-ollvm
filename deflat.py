#---------------------------------------------------------------------
# Debug notification hook test
#
# This script start the executable and steps through the first five
# instructions. Each instruction is disassembled after execution.
#
# Original Author: Gergely Erdelyi <gergely.erdelyi@d-dome.net>
#
# Maintained By: IDAPython Team
#
#---------------------------------------------------------------------
from idaapi import *
import keypatch

patcher=keypatch.Keypatch_Asm()

fun_offset=0x25D0 #函数地址

class MyDbgHook(DBG_Hooks):
    """ Own debug hook class that implementd the callback functions """

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        print("Process started, pid=%d tid=%d name=%s" % (pid, tid, name))
        self.dbg_process_attach(pid, tid, ea, name, base, size)
 
    def dbg_process_exit(self, pid, tid, ea, code):
        print("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))
        for sub_dict in self.related_dict:
            if len(self.related_dict[sub_dict])==1:
              for sub_sub_dict_key in self.related_dict[sub_dict]:
                  if idc.print_insn_mnem(sub_dict).startswith('j'):
                        disasm='jmp'+' '+hex(self.related_dict[sub_dict][sub_sub_dict_key].pop())
                        patcher.patch_code(sub_dict,disasm,patcher.syntax,True,False)
                
 
    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        print("Process attach pid=%d tid=%d ea=0x%x name=%s base=%x size=%x" % (pid, tid, ea, name, base, size))
        self.pre_blcok=None
        self.ZF_flag=None
        self.related_dict=dict()
        self.block_addr_dict=dict()
        so_base=idaapi.get_imagebase()
        self.f_blocks = idaapi.FlowChart(idaapi.get_func(so_base+fun_offset), flags=idaapi.FC_PREDS)
        for block in self.f_blocks:
            start=block.start_ea
            end=idc.prev_head(block.end_ea)
            if (idc.print_insn_mnem(start)=='cmp' and idc.print_insn_mnem(idc.next_head(start)).startswith('j')) or \
                (idc.print_insn_mnem(start)=='mov' and idc.print_insn_mnem(idc.next_head(start))=='cmp' and idc.print_insn_mnem(idc.next_head(idc.next_head(start))).startswith('j')) or \
                idc.print_insn_mnem(start)=='jmp' or \
                idc.print_insn_mnem(start)=='nop' or \
                idc.print_insn_mnem(start).startswith('cmov'):
                continue
            add_bpt(end,0,BPT_SOFT)
            while start<block.end_ea:
                if idc.print_insn_mnem(start).startswith('ret'):
                    add_bpt(start,0,BPT_SOFT)
                    break
                start=idc.next_head(start)
                
                
    def dbg_bpt(self, tid, ea):
        print ("Break point at 0x%x pid=%d" % (ea, tid))

        if not self.block_addr_dict:
            so_base=idaapi.get_imagebase()
            blocks=idaapi.FlowChart(idaapi.get_func(so_base+fun_offset), flags=idaapi.FC_PREDS)
            for block in blocks:
                start=block.start_ea
                end=idc.prev_head(block.end_ea)
                self.block_addr_dict[end]=start

        if not self.pre_blcok==None:
            if self.pre_blcok in self.related_dict:
                ori_dict=self.related_dict[self.pre_blcok]
                if self.ZF_flag in ori_dict:
                    sub_set=ori_dict[self.ZF_flag]
                    sub_set.add(self.block_addr_dict[ea])
                else:
                    sub_set=set()
                    sub_set.add(self.block_addr_dict[ea])
                    ori_dict[self.ZF_flag]=sub_set
            else:
                # 不存在
                sub_set=set()
                sub_set.add(self.block_addr_dict[ea])
                sub_dict={self.ZF_flag:sub_set}
                self.related_dict.update({self.pre_blcok:sub_dict})

        self.pre_blcok=ea
        self.ZF_flag = get_reg_value("ZF")


        if idc.print_insn_mnem(ea).startswith('ret'):
            return 0
        else:
            idaapi.continue_process()
        # return values:
        #   -1 - to display a breakpoint warning dialog
        #        if the process is suspended.
        #    0 - to never display a breakpoint warning dialog.
        #    1 - to always display a breakpoint warning dialog.
        return 0
 
 
# Remove an existing debug hook
try:
    if debughook:
        print("Removing previous hook ...")
        debughook.unhook()
except:
    pass
 
# Install the debug hook
debughook = MyDbgHook()
debughook.hook()
debughook.steps = 0
 
# Stop at the entry point
ep = get_inf_attr(INF_START_IP)
request_run_to(ep)
 
# Step one instruction
request_step_over()
 
# Start debugging
run_requests()