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


from tracer.ui2 import tracer_read_dialog, tracer_read_size_dialog, tracer_write_data_dialog, tracer_change_register, tracer_context_menu_dialog, tracer_taint_mem_dialog, tracer_taint_mem_size_dialog, tracer_taint_menu_dialog
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
	block = BasicBlock([Instruction(b"\x90"),Instruction(b"\x90"),Instruction(b"\x90"),Instruction(b"\x90"),Instruction(b"\x90"),Instruction(b"\x90"),Instruction(b"\x68\x11\xCA\x00\x00")])
	symb_ex_end = 0
	patch_start = 0
	registers = [] 
	WriteList = []
	peephole = False
	peepholeRegister = None
	dontrun = False
	ip = 0
	retard_registers = []

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
		self.Triton.taintRegister(self.Triton.registers.ecx)
		self.Triton.taintRegister(self.Triton.registers.edx)
		#self.Triton.taintRegister(self.Triton.registers.rsp)

	

	def log_read_write(self,ea):
		this_inst = self.inst
		if  (not self.inst.isMemoryRead() and not self.inst.isMemoryWrite()) or this_inst.getType() == OPCODE.X86.POP or this_inst.getType() == OPCODE.X86.PUSH or this_inst.getType() == OPCODE.X86.PUSHF or this_inst.getType() == OPCODE.X86.POPF :
			return


		operands = self.inst.getOperands()

		if len(operands) <= 1:
			return
			
		if operands[0].getType() == OPERAND.MEM:
			return
			if self.Triton.isMemoryTainted(value = self.Triton.getConcreteMemoryValue( MemoryAccess( operands[0], operands[0].getSize() ) )):
				return

		if len(operands) <= 2:
			return

		if operands[1].getType() == OPERAND.MEM:
			if self.Triton.isMemoryTainted(value = self.Triton.getConcreteMemoryValue( MemoryAccess( operands[1], operands[1].getSize() ) )):
				print("memory tainted")
				return
		
		
		self.constPropagation(operands[0],newval,ea)


	def constPropagation(self,operand,newval,ea):
		fake = []

		register_byte_mapping = {

		self.Triton.registers.r8b: b"\x41\xb0", # bytes of each - mov reg  (, imm (added later) )
		self.Triton.registers.r9b: b"\x41\xb1",
		self.Triton.registers.r10b: b"\x41\xb2",
		self.Triton.registers.r11b: b"\x41\xb3",
		self.Triton.registers.r12b: b"\x41\xb4",
		self.Triton.registers.r13b: b"\x41\xb5",
		self.Triton.registers.r14b: b"\x41\xb6",
		self.Triton.registers.r15b: b"\x41\xb7",
		
		self.Triton.registers.r8d: b"\x41\xb8",
		self.Triton.registers.r9d: b"\x41\xb9",
		self.Triton.registers.r10d: b"\x41\xba",
		self.Triton.registers.r11d: b"\x41\xbb",
		self.Triton.registers.r12d: b"\x41\xbc",
		self.Triton.registers.r13d: b"\x41\xbd",
		self.Triton.registers.r14d: b"\x41\xbe",
		self.Triton.registers.r15d: b"\x41\xbf",
		
		self.Triton.registers.r8: b"\x49\xb8",
		self.Triton.registers.r9: b"\x49\xb9",
		self.Triton.registers.r10: b"\x49\xba",
		self.Triton.registers.r11: b"\x49\xbb",
		self.Triton.registers.r12: b"\x49\xbc",
		self.Triton.registers.r13: b"\x49\xbd",
		self.Triton.registers.r14: b"\x49\xbe",
		self.Triton.registers.r15: b"\x49\xbf",

		self.Triton.registers.al: b"\xB0",
		self.Triton.registers.cl: b"\xB1",
		self.Triton.registers.dl: b"\xB2",
		self.Triton.registers.bl: b"\xB3",

		self.Triton.registers.ah: b"\xB4",
		self.Triton.registers.ch: b"\xB5",
		self.Triton.registers.dh: b"\xB6",
		self.Triton.registers.bh: b"\xB7",

		self.Triton.registers.spl: b"\x40\xb4",
		self.Triton.registers.bpl: b"\x40\xb5",
		self.Triton.registers.sil: b"\x40\xb6",
		self.Triton.registers.dil: b"\x40\xb7",


		self.Triton.registers.ax: b"\x66\xB8",
		self.Triton.registers.cx: b"\x66\xB9",
		self.Triton.registers.dx: b"\x66\xBA",
		self.Triton.registers.bx: b"\x66\xBB",
		self.Triton.registers.sp: b"\x66\xBC",
		self.Triton.registers.bp: b"\x66\xBD",
		self.Triton.registers.si: b"\x66\xBE",
		self.Triton.registers.di: b"\x66\xBF",

		self.Triton.registers.eax: b"\xb8",
		self.Triton.registers.ecx: b"\xb9",
		self.Triton.registers.edx: b"\xba",
		self.Triton.registers.ebx: b"\xbb",
		self.Triton.registers.esp: b"\xbc",
		self.Triton.registers.ebp: b"\xbd",
		self.Triton.registers.esi: b"\xbe",
		self.Triton.registers.edi: b"\xbf",

		self.Triton.registers.rax: b"\x48\xB8",
		self.Triton.registers.rcx: b"\x48\xb9",
		self.Triton.registers.rdx: b"\x48\xba",
		self.Triton.registers.rbx: b"\x48\xbb",
		self.Triton.registers.rsp: b"\x48\xbc",
		self.Triton.registers.rbp: b"\x48\xbd",
		self.Triton.registers.rsi: b"\x48\xbe",
		self.Triton.registers.rdi: b"\x48\xbf",

		
		
		

		
		}

		if operand in register_byte_mapping:
			print(operand,operand.getSize())
			fake.append(register_byte_mapping[operand] + newval.to_bytes(operand.getSize(), 'little'))
			print(fake[0])
			self.function[ea] = fake[0]
			self.peephole = True
			self.peepholeRegister = operand



	def peepholeOpt(self,ea):

		this_inst = self.inst
		operands = this_inst.getOperands()

		if this_inst.getType() == OPCODE.X86.CMP or this_inst.getType() == OPCODE.X86.TEST or this_inst.getType() == OPCODE.X86.POP or this_inst.getType() == OPCODE.X86.PUSH:
			return

		if len(operands) < 1:
			self.dontrun = False
			return

		if operands[0].getType() == OPERAND.REG:
			if self.Triton.isRegisterTainted(operands[0]):
				print("register tainted")
				return
		else:
			return
		if len(operands) == 2:
			if operands[1].getType() == OPERAND.REG:
				if self.Triton.isRegisterTainted(operands[1]):
					print("second register tainted")
					return

		self.ip = self.Triton.getRegisterAst(self.Triton.registers.rip).evaluate()
		self.dontrun = True
		print(self.inst)
		newval = self.Triton.getConcreteRegisterValue(operands[0])


		self.constPropagation(operands[0],newval,ea)
		print("peepholing",operands[0], newval)
		return 






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

		self.log_read_write(ea)
		self.peepholeOpt(ea)




		if  not ( self.inst.getDisassembly()[0] == "j"  or "ret" in self.inst.getDisassembly() or  "call" in self.inst.getDisassembly() )   :

			self.block.add(Instruction(self.function[ea]))

		self.pushval = 0

		if "push" in self.inst.getDisassembly():
			self.pushval = 1

		

		#print(block_len, ' - Curr ip:', self.inst)
		print('Curr ip:', self.inst)

		# Next instruction
		if not self.dontrun:
			self.ip = self.Triton.getRegisterAst(self.Triton.registers.rip).evaluate()

		self.dontrun = False
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




		print('Next ip:', hex(self.ip), "rax: ", hex(ax), "rcx:", hex(cx),"rdx:", hex(dx),"rbx:", hex(bx),"rsi:", hex(si),"rdi:", hex(di),"rsp:", hex(sp), "rbp:", hex(bp), "r8:",hex(r8),"r9:",hex(r9),"r10:",hex(r10),"r11:",hex(r11),"r12:",hex(r12),"r13:",hex(r13),"r14:",hex(r14),"r15:",hex(r15), "zf:",hex(zf),"sf:",hex(sf) ,"df:",hex(df),"cf:",hex(cf), )
		
		return self.ip

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

	def taint_memory(self):
		read_memory_address = tracer_taint_mem_dialog()
		read_memory_address.Compile()
		read_memory_address.Execute()
		read_memory_size = tracer_taint_mem_size_dialog()
		read_memory_size.Compile()
		read_memory_size.Execute()

		taintval = MemoryAccess( read_memory_address.address.value, read_memory_size.size.value )

		isTainted = self.Triton.isMemoryTainted(taintval)

		print("isTainted: ", isTainted)

		if isTainted:
			return self.Triton.untaintMemory( taintval )


		value = self.Triton.taintMemory( taintval )


	def tracer_taint_menu_dialog(self):
		a = tracer_taint_menu_dialog( self , [ [register, str( (self.Triton.isRegisterTainted(register) ) ) ] for register in self.Triton.getAllRegisters() ] )
		a.show()

	def taint_register(self, register):
		if self.Triton.isMemoryTainted(register):
			return self.Triton.untaintRegister( register )
		self.Triton.taintRegister(register)
		return

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

		#self.symb_ex(ea)

		#if True:
		#	return

		self.Triton.disassembly(self.block, ea)

		#print(self.block)

		sblock = self.Triton.simplify(self.block)
		self.Triton.disassembly(sblock, ea)
		#print("simplified: " , sblock)


		#esblock = self.Triton.simplify(sblock)
		#self.Triton.disassembly(esblock, 0x14000102C)

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