import ida_kernwin
import idautils
from time import time
import binascii
import idaapi
import idc
import ida_idaapi
import idaapi
import ida_ua
import ida_nalt
import triton
from triton     import *
import ida_bytes
import sys
Triton = TritonContext()
Triton.setArchitecture(ARCH.X86_64)
Triton.setMode(MODE.AST_OPTIMIZATIONS, True)
Triton.setMode(MODE.CONSTANT_FOLDING, True)
block = BasicBlock([])
#sys.setrecursionlimit(10**6)
# Symbolic optimization
Triton.setMode(MODE.ALIGNED_MEMORY, True)

# Define entry point
ENTRY = 0x0



# Init context memory

class tracer_Plugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "TritonTracer"
    help = ""
    wanted_name = "TritonTracer"
    wanted_hotkey = "CTRL+Q"
    Triton = TritonContext()

    # Define entry point
    ENTRY = 0x0

    # Init context memory
    insn_bytes_len = 0
    inst = Instruction()
    insn = ida_ua.insn_t()
    function = {
    }
    total_inst = 0
    pushval = 0

    def initContext(self):
    #Triton.setConcreteRegisterValue(Triton.registers.rsp, 0x7fff0fff)
    #Triton.setConcreteRegisterValue(Triton.registers.rbp, 0x7fff0fff)


        #self.Triton.setConcreteRegisterValue(Triton.registers.r10, 0x14002950E )

        #Triton.setConcreteRegisterValue(Triton.registers.r9, 0x53)

        return

    def init(self):
        self.Triton.setArchitecture(ARCH.X86_64)

        self.insn = ida_ua.insn_t()

    # Symbolic optimization
        self.Triton.setMode(MODE.ALIGNED_MEMORY, True)
        self.Triton.setMode(MODE.CONSTANT_FOLDING, True)
        self.Triton.setMode(MODE.AST_OPTIMIZATIONS, True)

        # Define entry point

        # Init context memory
        self.initContext()
        last_addr = idaapi.inf_get_max_ea()
        imagebase = ida_nalt.get_imagebase() + 0x1000
        size = last_addr - imagebase
        memory_bytes = ida_bytes.get_bytes(imagebase,size)
        a = self.Triton.setConcreteMemoryAreaValue(imagebase, memory_bytes)

        print("imgbase: ", hex(imagebase), ", size: ", len(memory_bytes), ", 0x2850e :", hex ( memory_bytes[0x2850e] ), ", MemoryAccess :", hex(self.Triton.getConcreteMemoryValue(MemoryAccess(0x14002950e, CPUSIZE.DWORD))) )
        return idaapi.PLUGIN_OK


    def set_memory(self,addr,value):
        memory_bytes = ida_bytes.get_bytes(addr,8)

        #print("setting memory at", hex(addr) )
        self.Triton.setConcreteMemoryValue(addr, memory_bytes[0])
        self.Triton.setConcreteMemoryValue(addr+1, memory_bytes[1])
        self.Triton.setConcreteMemoryValue(addr+2, memory_bytes[2])
        self.Triton.setConcreteMemoryValue(addr+3, memory_bytes[3])
        self.Triton.setConcreteMemoryValue(addr+4, memory_bytes[4])
        self.Triton.setConcreteMemoryValue(addr+5, memory_bytes[5])
        self.Triton.setConcreteMemoryValue(addr+6, memory_bytes[6])
        self.Triton.setConcreteMemoryValue(addr+7, memory_bytes[7])
        self.symb_ex(ea) # problem arises here

    def add_space(self,input_string):
        output = ""
        for i in range(0, len(input_string), 2):
            output += input_string[i:i+2] + " "
        return output.strip()



    def read_memory(self,addr,ea):
        memory_bytes = ida_bytes.get_bytes(addr,8)


        if memory_bytes == b"\xff\xff\xff\xff\xff\xff\xff\xff":
            #print("empty?xd")
            return


        print("reading memory at", hex(addr) , "to : ", memory_bytes )
        self.Triton.setConcreteMemoryValue(addr, memory_bytes[0])
        self.Triton.setConcreteMemoryValue(addr+1, memory_bytes[1])
        self.Triton.setConcreteMemoryValue(addr+2, memory_bytes[2])
        self.Triton.setConcreteMemoryValue(addr+3, memory_bytes[3])
        self.Triton.setConcreteMemoryValue(addr+4, memory_bytes[4])
        self.Triton.setConcreteMemoryValue(addr+5, memory_bytes[5])
        self.Triton.setConcreteMemoryValue(addr+6, memory_bytes[6])
        self.Triton.setConcreteMemoryValue(addr+7, memory_bytes[7])
        return Triton.processing(self.inst)

    def write_operand(self,ea):
        #print(hex(ea),self.inst.getOperands(),self.inst)

        """
        if len(self.inst.getOperands()) != 2:
            #print("no second operand")
            return 0
        if type ( self.inst.getOperands()[1] ) != type(MemoryAccess(4,8)):
            #print("second op is not memory access")
            return 0
        if Triton.getConcreteMemoryValue(MemoryAccess(ea, 8)) != 0:
            #print("memAcc already set")
            return
        """

        
        if ( self.inst.isMemoryRead() ) == False:
            #print(self.inst.isMemoryRead(), "-", Triton.registers.rip )
            return
        operands = self.inst.getOperands()



        if not ( len(operands) > 0):
            return

        if ( "push" in self.inst.getDisassembly() or "pop" in self.inst.getDisassembly() ) == True:
            return

        read_this_op = 0 
        for op in operands:
            if type(op) == type(MemoryAccess(4,8)):
                read_this_op = op.getAddress()
                print("read_this_op :", hex ( read_this_op ) )
                print ( hex(self.Triton.getConcreteMemoryValue(MemoryAccess(read_this_op, CPUSIZE.DWORD))) )
                #self.read_memory(read_this_op, ea)

        return 


    def symb_ex(self,ea):
        size = ida_ua.decode_insn(self.insn, ea)
        insn_bytes = ida_bytes.get_bytes(ea,size)
        self.insn_bytes_len = insn_bytes
        #print(self.function,insn_bytes)
        self.function[ea] = insn_bytes



        self.inst.setOpcode(self.function[ea])
        self.inst.setAddress(ea)



        self.Triton.processing(self.inst)

        #block_len = len(block.getInstructions() ) #losing performance here.


        if "ret" in self.inst.getDisassembly() and self.pushval == 1:
            block_len = len(block.getInstructions() ) 

            print ( "Removing:", block_len - 1 ,block.remove(block_len - 1 ) )




        if  not ( self.inst.getDisassembly()[0] == "j"  or "ret" in self.inst.getDisassembly() or  "call" in self.inst.getDisassembly() )  :
            block.add(Instruction(self.function[ea]))

        self.pushval = 0
        if "push" in self.inst.getDisassembly():
            self.pushval = 1

        self.write_operand(ea)

        #print(block_len, ' - Curr ip:', self.inst)
        print('Curr ip:', self.inst)

        # Next instruction
        ip = self.Triton.getRegisterAst(Triton.registers.rip).evaluate()



        ax = self.Triton.getConcreteRegisterValue(Triton.registers.rax)

        cx = self.Triton.getConcreteRegisterValue(Triton.registers.rcx)

        dx = self.Triton.getConcreteRegisterValue(Triton.registers.rdx)

        bx = self.Triton.getConcreteRegisterValue(Triton.registers.rbx)

        si = self.Triton.getConcreteRegisterValue(Triton.registers.rsi)

        di = self.Triton.getConcreteRegisterValue(Triton.registers.rdi)

        sp = self.Triton.getConcreteRegisterValue(Triton.registers.rsp)

        bp = self.Triton.getConcreteRegisterValue(Triton.registers.rbp)


        self.rax = ax
        r8 = self.Triton.getConcreteRegisterValue(Triton.registers.r8)

        r9 = self.Triton.getConcreteRegisterValue(Triton.registers.r9)

        r10 = self.Triton.getConcreteRegisterValue(Triton.registers.r10)

        r11 = self.Triton.getConcreteRegisterValue(Triton.registers.r11)

        r12 = self.Triton.getConcreteRegisterValue(Triton.registers.r12)

        r13 = self.Triton.getConcreteRegisterValue(Triton.registers.r13)

        r14 = self.Triton.getConcreteRegisterValue(Triton.registers.r14)

        r15 = self.Triton.getConcreteRegisterValue(Triton.registers.r15)



        print('Next ip:', hex(ip), "rax: ", hex(ax), "rcx:", hex(cx),"rdx:", hex(dx),"rbx:", hex(bx),"rsi:", hex(si),"rdi:", hex(di),"rsp:", hex(sp), "rbp:", hex(bp), "r8:",hex(r8),"r9:",hex(r9),"r10:",hex(r10),"r11:",hex(r11),"r12:",hex(r12),"r13:",hex(r13),"r14:",hex(r14),"r15:",hex(r15), )
        
        return ip


    def run_symb_ex(self,ea,end):
        while True:
            ea = self.symb_ex(ea)
            if ea == end:

                return


    symb_ex_end = 0
    patch_start = 0

    def run(self, arg):
        
        if self.symb_ex_end == 0:
            self.symb_ex_end = idaapi.get_screen_ea()
            return

        if self.patch_start == 0:
            self.patch_start = idaapi.get_screen_ea()
            return
        
        # Retrieve the current cursor position

        function = {}
        rn = time()
        
        inst = Instruction()
        ea = idaapi.get_screen_ea()
        self.run_symb_ex(ea,self.symb_ex_end )
        #self.symb_ex(ea)

        """
        self.Triton.disassembly(block, ea)
        print(block)

        sblock = Triton.simplify(block)
        self.Triton.disassembly(sblock, ea)
        print("simplified: " , sblock)


        #esblock = Triton.simplify(sblock)
        #Triton.disassembly(esblock, 0x14000102C)

        inst = sblock.getInstructions()
        byte_ = b""
        for instruction in inst:
            byte_ = byte_ + ( instruction.getOpcode() )

        byte_ = byte_ + b'\xc3'

        #print("bytes:",  self.add_space(str( binascii.hexlify(byte_) ) ) )

        print("byteslength: ", self.total_inst)

        idaapi.patch_bytes(self.patch_start ,byte_)



        

        evsblock = Triton.simplify(esblock)
        self.Triton.disassembly(evsblock, 0x14000102C)
        
        print("even more simplified: " , sblock)

        
        self.rax = Triton.getRegisterAst(Triton.registers.rax)
        ast    = Triton.getAstContext()
        print(self.rax)
        unro  = ast.unroll(self.rax)
        print(f'[+] Return value: {hex(self.rax.evaluate())}')

        ppast1 = (str(unro) if len(str(unro)) < 100 else 'In: %s ...' %(str(unro)[0:100]))
        print(f'[+] Devirt expr: {ppast1}')
        synth  = Triton.synthesize(self.rax)
        ppast2 = (str(synth) if len(str(synth)) < 100 else 'In: %s ...' %(str(unro)[0:100]))
        print(f'[+] Synth expr: {ppast2}\n')
        print ( Triton.liftToLLVM(synth if synth else self.rax) )
        """

        #fd = idaapi.fixup_data_t()
        #ida_fixup.set_fixup(0x14007C815,newfd)
        #ida_fixup.get_fixup(fd,0x14007C815)
        #fd.sel etc.
        #fd.set_type(0xc)
        #

    def term(self):
        pass

def PLUGIN_ENTRY():
    return tracer_Plugin()