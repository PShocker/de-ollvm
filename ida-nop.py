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


fun_offset=0x25d0

def patch_code(addr,code):
    insn = idaapi.insn_t()
    codelen=idaapi.decode_insn(insn,addr)
    for i in range(codelen):
        idc.patch_byte(addr+i,code[0])

#将指定地址的字节修改成nop
def nop(addr):
    nop_code=[0x90]
    patch_code(addr,nop_code)



class MyDbgHook(DBG_Hooks):
    """ Own debug hook class that implementd the callback functions """

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        print("Process started, pid=%d tid=%d name=%s" % (pid, tid, name))
        self.dbg_process_attach(pid, tid, ea, name, base, size)
 
    def dbg_process_exit(self, pid, tid, ea, code):
        print("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))
        for block in self.f_blocks:
            if block.start_ea in self.block_addrs:
                # 高亮该block
                start=block.start_ea
                while start<block.end_ea:
                    set_color(start, CIC_ITEM, 0x00ffff)
                    start=idc.next_head(start)
            else:
                # 说明没有执行,直接nop掉
                start=block.start_ea
                while start<block.end_ea:
                    nop(start)
                    start=idc.next_head(start)
                

    # def dbg_library_unload(self, pid, tid, ea, info):
    #     print("Library unloaded: pid=%d tid=%d ea=0x%x info=%s" % (pid, tid, ea, info))
    #     return 0
 
    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        print("Process attach pid=%d tid=%d ea=0x%x name=%s base=%x size=%x" % (pid, tid, ea, name, base, size))
        # self.f=open('address.txt','w')
        self.block_addrs=set()
        self.f_blocks=None
        so_base=idaapi.get_imagebase()
        blocks = idaapi.FlowChart(idaapi.get_func(so_base+fun_offset), flags=idaapi.FC_PREDS)
        for block in blocks:
            add_bpt(block.start_ea,0,BPT_SOFT)
            start=block.start_ea
            while start<block.end_ea:
                if idc.print_insn_mnem(start).startswith('ret'):
                    print('0x%x'%start)
                    add_bpt(start,0,BPT_SOFT)
                    break
                start=idc.next_head(start)
                
 
    # def dbg_process_detach(self, pid, tid, ea):
    #     print("Process detached, pid=%d tid=%d ea=0x%x" % (pid, tid, ea))
    #     return 0
 
    # def dbg_library_load(self, pid, tid, ea, name, base, size):
    #     print ("Library loaded: pid=%d tid=%d name=%s base=%x" % (pid, tid, name, base))
 
    def dbg_bpt(self, tid, ea):
        print ("Break point at 0x%x pid=%d" % (ea, tid))
        so_base=idaapi.get_imagebase()
        if self.f_blocks == None:
            self.f_blocks=idaapi.FlowChart(idaapi.get_func(so_base+fun_offset), flags=idaapi.FC_PREDS)


        self.block_addrs.add(ea)
        if idc.print_insn_mnem(ea).startswith('ret'):
            # request_exit_process()
            pass
        else:
            idaapi.continue_process()
        
        # return values:
        #   -1 - to display a breakpoint warning dialog
        #        if the process is suspended.
        #    0 - to never display a breakpoint warning dialog.
        #    1 - to always display a breakpoint warning dialog.
        return 0
 
    # def dbg_suspend_process(self):
    #     print ("Process suspended")
 
    # def dbg_exception(self, pid, tid, ea, exc_code, exc_can_cont, exc_ea, exc_info):
    #     print("Exception: pid=%d tid=%d ea=0x%x exc_code=0x%x can_continue=%d exc_ea=0x%x exc_info=%s" % (
    #         pid, tid, ea, exc_code & idaapi.BADADDR, exc_can_cont, exc_ea, exc_info))
    #     # return values:
    #     #   -1 - to display an exception warning dialog
    #     #        if the process is suspended.
    #     #   0  - to never display an exception warning dialog.
    #     #   1  - to always display an exception warning dialog.
    #     return 0
 
    # def dbg_trace(self, tid, ea):
    #     # eip = get_reg_value("EIP")
    #     # print("0x%x %s" % (eip, GetDisasm(eip)))
    #     # print("Trace tid=%d ea=0x%x" % (tid, ea))
    #     # return values:
    #     #   1  - do not log this trace event;
    #     #   0  - log it
    #     return 0
 
    # def dbg_step_into(self):
    #     eip = get_reg_value("EIP")
    #     print("0x%x %s" % (eip, GetDisasm(eip)))
 
    # def dbg_run_to(self, pid, tid=0, ea=0):
    #     print ("Runto: tid=%d" % tid)
    #     idaapi.continue_process()
 
 
    # def dbg_step_over(self):
    #     eip = get_reg_value("EIP")
    #     print("0x%x %s" % (eip, GetDisasm(eip)))
    #     self.steps += 1
    #     if self.steps >= 5:
    #         request_exit_process()
    #     else:
    #         request_step_over()
 
 
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