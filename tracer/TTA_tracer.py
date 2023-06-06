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
from triton import *


from tracer.ui2 import tracer_read_dialog, tracer_read_size_dialog, tracer_write_data_dialog, tracer_change_register, tracer_context_menu_dialog
import ida_bytes
import sys

WHITE = 0xFFFFFF
BLUE = 0xDDFF03
YELLOW = 0x05FCD7
CIC_ITEM = 0x1


class TritonTracer():

	Triton = TritonContext()
	insn_bytes_len = 0
	inst = Instruction()
	insn = ida_ua.insn_t()
	function = {}
	pushval = 0
	block = BasicBlock([])
	symb_ex_end = 0
	patch_start = 0
	registers = [] 

	def loadBinary(self):
		last_addr = idaapi.inf_get_max_ea()
		imagebase = ida_nalt.get_imagebase() + 0x1000
		size = last_addr - imagebase
		memory_bytes = ida_bytes.get_bytes(imagebase,size)
		a = self.Triton.setConcreteMemoryAreaValue(imagebase, memory_bytes)
		print("imgbase: ", hex(imagebase), ", size: ", len(memory_bytes), ", 0x2850e :", hex ( memory_bytes[0x2850e] ), ", MemoryAccess 0x2850e :", hex(self.Triton.getConcreteMemoryValue(MemoryAccess(0x14002950e, CPUSIZE.DWORD))) )


	def __init__(self): # X86_64 ONLY FOR NOW
		self.Triton.setArchitecture(ARCH.X86_64)
		self.insn = ida_ua.insn_t()

		self.Triton.setMode(MODE.ALIGNED_MEMORY, True)
		self.Triton.setMode(MODE.CONSTANT_FOLDING, True)
		self.Triton.setMode(MODE.AST_OPTIMIZATIONS, True)
		self.registers = [     self.Triton.registers.rax,
    self.Triton.registers.rcx,
    self.Triton.registers.rdx,
    self.Triton.registers.rbx,
    self.Triton.registers.rsi,
    self.Triton.registers.rdi,
    self.Triton.registers.rsp,
    self.Triton.registers.rbp,
    self.Triton.registers.r8,
    self.Triton.registers.r9,
    self.Triton.registers.r10,
    self.Triton.registers.r11,
    self.Triton.registers.r12,
    self.Triton.registers.r13,
    self.Triton.registers.r14,
    self.Triton.registers.r15,
    self.Triton.registers.cf,
    self.Triton.registers.sf,
    self.Triton.registers.zf,
    self.Triton.registers.df ]


	def symb_ex(self,ea):
		size = ida_ua.decode_insn(self.insn, ea)
		insn_bytes = ida_bytes.get_bytes(ea,size)

		self.insn_bytes_len = insn_bytes

		self.function[ea] = insn_bytes



		self.inst.setOpcode(self.function[ea])
		self.inst.setAddress(ea)
		self.Triton.processing(self.inst)


		if "ret" in self.inst.getDisassembly() and self.pushval == 1:
			block_len = len(self.block.getInstructions() ) 

			print ( "Removing:", block_len - 1 ,self.block.remove(block_len - 1 ) )




		if  not ( self.inst.getDisassembly()[0] == "j"  or "ret" in self.inst.getDisassembly() or  "call" in self.inst.getDisassembly() )  :
			self.block.add(Instruction(self.function[ea]))

		self.pushval = 0

		if "push" in self.inst.getDisassembly():
			self.pushval = 1

		#self.log_read_write(ea)

		#print(block_len, ' - Curr ip:', self.inst)
		print('Curr ip:', self.inst)

		# Next instruction
		ip = self.Triton.getRegisterAst(self.Triton.registers.rip).evaluate()

		#registers

		ax = self.Triton.getConcreteRegisterValue(self.Triton.registers.rax)

		cx = self.Triton.getConcreteRegisterValue(self.Triton.registers.rcx)

		dx = self.Triton.getConcreteRegisterValue(self.Triton.registers.rdx)

		bx = self.Triton.getConcreteRegisterValue(self.Triton.registers.rbx)

		si = self.Triton.getConcreteRegisterValue(self.Triton.registers.rsi)

		di = self.Triton.getConcreteRegisterValue(self.Triton.registers.rdi)

		sp = self.Triton.getConcreteRegisterValue(self.Triton.registers.rsp)

		bp = self.Triton.getConcreteRegisterValue(self.Triton.registers.rbp)

		r8 = self.Triton.getConcreteRegisterValue(self.Triton.registers.r8)

		r9 = self.Triton.getConcreteRegisterValue(self.Triton.registers.r9)

		r10 = self.Triton.getConcreteRegisterValue(self.Triton.registers.r10)

		r11 = self.Triton.getConcreteRegisterValue(self.Triton.registers.r11)

		r12 = self.Triton.getConcreteRegisterValue(self.Triton.registers.r12)

		r13 = self.Triton.getConcreteRegisterValue(self.Triton.registers.r13)

		r14 = self.Triton.getConcreteRegisterValue(self.Triton.registers.r14)

		r15 = self.Triton.getConcreteRegisterValue(self.Triton.registers.r15)

		#flags

		cf = self.Triton.getConcreteRegisterValue(self.Triton.registers.cf)

		sf = self.Triton.getConcreteRegisterValue(self.Triton.registers.sf)

		zf = self.Triton.getConcreteRegisterValue(self.Triton.registers.zf)

		df = self.Triton.getConcreteRegisterValue(self.Triton.registers.df)




		print('Next ip:', hex(ip), "rax: ", hex(ax), "rcx:", hex(cx),"rdx:", hex(dx),"rbx:", hex(bx),"rsi:", hex(si),"rdi:", hex(di),"rsp:", hex(sp), "rbp:", hex(bp), "r8:",hex(r8),"r9:",hex(r9),"r10:",hex(r10),"r11:",hex(r11),"r12:",hex(r12),"r13:",hex(r13),"r14:",hex(r14),"r15:",hex(r15), "zf:",hex(zf),"sf:",hex(sf) ,"df:",hex(df),"cf:",hex(cf), )
		
		return ip

	def run_symb_ex(self,ea,end):
		while True:
			ea = self.symb_ex(ea)
			if ea == end:
				return


	def set_sym_ex_end(self):
		idc.set_color(self.symb_ex_end, CIC_ITEM, color = WHITE )
		self.symb_ex_end = idaapi.get_screen_ea()
		idc.set_color(self.symb_ex_end, CIC_ITEM, color = BLUE )

	def set_paste(self):
		idc.set_color(self.patch_start, CIC_ITEM, color = WHITE )
		self.patch_start = idaapi.get_screen_ea()
		idc.set_color(self.patch_start, CIC_ITEM, color = YELLOW )


	def read_Memory_Access(self):
		read_memory_address = tracer_read_dialog()
		read_memory_address.Compile()
		read_memory_address.Execute()
		read_memory_size = tracer_read_size_dialog()
		read_memory_size.Compile()
		read_memory_size.Execute()

		value = self.Triton.getConcreteMemoryValue( MemoryAccess( read_memory_address.address.value, read_memory_size.size.value ) )

		print(hex(value))


	def write_Memory_Access(self):
		write_memory_address = tracer_read_dialog()
		write_memory_address.Compile()
		write_memory_address.Execute()
		write_memory_value = tracer_write_data_dialog()
		write_memory_value.Compile()
		write_memory_value.Execute()


		addr_value = write_memory_value.addr_value.value 
		addr_bytes = addr_value.to_bytes((addr_value.bit_length() + 7) // 8, 'little')
		
		self.Triton.setConcreteMemoryAreaValue( write_memory_address.address.value, addr_bytes)


	def context_menu_dialog(self):
		a = tracer_context_menu_dialog( self , [ [register, str(hex (self.Triton.getConcreteRegisterValue(register) ) ) ] for register in self.registers ] )
		a.show()

	def change_register_dialog(self, register):
		write_memory_address = tracer_change_register(register.getName())
		write_memory_address.Compile()
		write_memory_address.reg_val.value = self.Triton.getConcreteRegisterValue(register)
		write_memory_address.Execute()
		self.change_register(register, write_memory_address.reg_val.value)
		return write_memory_address.reg_val.value

	def change_register(self, register, value):
		self.Triton.setConcreteRegisterValue(register,value)
		return

	def clear_selection(self,ea):
		current_ea = ea

		if (current_ea == self.patch_start):
			idc.set_color(self.patch_start, CIC_ITEM, color = WHITE )
			self.patch_start = 0

		if (current_ea == self.symb_ex_end):
			idc.set_color(self.symb_ex_end, CIC_ITEM, color = WHITE )
			self.symb_ex_end = 0

		return
		


	def run(self):
		inst = Instruction()
		ea = idaapi.get_screen_ea()

		if self.symb_ex_end == 0:
			idaapi.warning("Please set an endpoint")
			return

		self.run_symb_ex(ea, self.symb_ex_end )

		self.Triton.disassembly(self.block, ea)
		#print(self.block)

		sblock = self.Triton.simplify(self.block)
		self.Triton.disassembly(sblock, ea)
		#print("simplified: " , sblock)


		#esblock = Triton.simplify(sblock)
		#Triton.disassembly(esblock, 0x14000102C)

		inst = sblock.getInstructions()
		byte_ = b""
		for instruction in inst:
			byte_ = byte_ + ( instruction.getOpcode() )

		byte_ = byte_ + b'\xc3'

		#print("bytes:",  self.add_space(str( binascii.hexlify(byte_) ) ) )

		#print("byteslength: ", self.total_inst)

		idaapi.patch_bytes(self.patch_start ,byte_)

	def term(self):
		self.clear_selection(self.patch_start)
		self.clear_selection(self.symb_ex_end)