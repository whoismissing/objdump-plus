from binaryninja.log import log_info
from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.function import InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType, SegmentFlag, SectionSemantics

from .objdump_plus import ObjdumpPlus
from .objdump_plus import ObjdumpPlus as op

BASE_ADDR = 0x100d0

class TiamatDisasm(ObjdumpPlus):
    def __init__(
        self, 
        filepath, 
        inst_alignment=4, 
        max_inst_len=4
    ):
        super().__init__(filepath)
        self._arch_pos = 0
        self._pc_pos = 2
        self._opcode_pos = 3
        self.inst_map = self.load_instruction_map(filepath)

    def get_opcode(self, tokens) -> (bytes, int):
        """
        Example disassembly:
        MIPS B 0x109f8:	e3a00001	sc	$zero, 1($sp)
        SPARC L 0x109fc:	01606020	fba,pn	%fcc2, 0x28a7c
        SPARC B 0x10a00:	0400a520	bn,a	-0x6af5f0
        RISCV B 0x10a04:	0283da63	bge	t2, s0, 0x34
        ARM B 0x10a08:	0d001084	stceq	p0, c1, [r0, #-0x210]

        tokens = [ "MIPS", "L", "0x101cc:", "e3a02004", "bltz", ... ]
        """
        # Opcodes are hardcoded to be at token 3
        opcode = ""
        opcode = bytes.fromhex(tokens[self._opcode_pos])
        return opcode, self._opcode_pos

    def load_instruction_map(self, filename):
        instructions = {}
        with open(filename, "r") as fd:
            for line in fd:
                tokens = line.split()
                arch = tokens[self._arch_pos]
                hex_addr = tokens[self._pc_pos].replace(":", "")
                address = int(hex_addr, 16)
                # Insert arch into instruction string
                tokens.insert(self._opcode_pos + 1, arch)
                # == HACK: 1-to-1 mapping of opcodes had a conflict
                # instead, we map and disassemble based on the instruction address
                # example:
                # 0x1000ff1e used in ARM and MIPS
                position = self._opcode_pos
                instruction = " ".join(tokens[position + 1:])
                instructions[address] = instruction
        return instructions

    # We are not really disassembling, 
    # we map the instruction text based on the objdump instruction address
    def lazy_disasm(self, address) -> (str, int):
        """
        :param address: int representing the program counter
        :returns instruction:
        :returns instruction_len:
        """
        instruction = "NONE"
        instruction_len = 0
        not_dword = False

        try:
            instruction = self.inst_map[address]
            instruction_len = 4 # HARDCODED
        except KeyError:
            log_info("--FAILED to decode")
            pass

        return instruction, instruction_len


class TiamatView(BinaryView):
    name = 'Tiamat'
    long_name = 'Tiamat ROM'

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)                                      
        self.raw = data
        self.platform = Architecture['Tiamat'].standalone_platform
        self.add_auto_segment(BASE_ADDR, BASE_ADDR+0x404*4, 0, len(data), SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)

    @classmethod
    def is_valid_for_data(self, data):
        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return 0x00

artifacts = op.get_artifacts_path()
disasm_file = artifacts / "./tiamat/tiamat.disasm.txt"
dis = TiamatDisasm(disasm_file, inst_alignment=4, max_inst_len=4)

class Tiamat(Architecture):
    name = 'Tiamat'
    address_size = 4
    default_int_size = 4
    instr_alignment = dis.inst_alignment
    max_instr_length = dis.max_inst_len

    def get_instruction_info(self, data, addr):
        (instruction_text, instruction_len) = dis.lazy_disasm(addr)
        if instruction_len == 0:
            return None

        result = InstructionInfo()
        result.length = instruction_len

        if len(instruction_text) == 0:
            return result

        tokens = instruction_text.split()
        arch = tokens[0]
        instruction = tokens[1].lower()
        raw_offset = tokens[-1]

        if 'ret' in instruction:
            result.add_branch(BranchType.FunctionReturn)
            return result

        if op.instruction_is_call(instruction):
            call_offset = addr + int(raw_offset, 16)
            result.add_branch(BranchType.CallDestination, call_offset)
            return result

        if not op.instruction_is_branch(instruction):
            return result

        if arch == "MIPS": 
            # b	0x10184
            # bgtz	$zero, -0x6c90
            # bgez	$zero, 0x14ca0
            # bne	$v0, $s2, 0x12508
            # bnez	$t8, 0x14d94
            # bltzall	$v0, 0x13cd8
            # bltzal	$t3, -0x7018
            # bltz	$t0, 0x1371c
            # bltz	$zero, -0x69e0
            # bltz	$at, 0x1502c
            if op.is_conditional_branch(instruction_text):
                branch_offset = addr + int(raw_offset, 16)
                result.add_branch(BranchType.TrueBranch, branch_offset)
                result.add_branch(BranchType.FalseBranch, addr + instruction_len)
            else: # UNCONDITIONAL BRANCH
                branch_offset = int(raw_offset, 16)
                result.add_branch(BranchType.UnconditionalBranch, branch_offset)
        elif arch == "ARM":
            # bicsvs	r8, sl, #0x8000000
            # bicsls	r2, r0, r0, lsl r0
            # bicsls	r2, r0, r0, lsl r0
            # bicsls	r2, r0, r0, lsl r0
            # blgt	#0x814c9c
            # bge	#0xfffd0b78
            # bhi	#0x200b08
            # bhi	#0x419078
            # bvs	#0x11e10
            # bvs	#0x1225c 
            is_overflow_set = 'bvs' in instruction_text
            if op.is_conditional_branch(instruction_text) or is_overflow_set:
                branch_offset = int(raw_offset.replace("#", ""), 16) - BASE_ADDR
                result.add_branch(BranchType.TrueBranch, branch_offset)
                result.add_branch(BranchType.FalseBranch, addr + instruction_len)
        elif arch == "RISCV":
            # blez	s8, 0x20
            # bge	t0, a2, 0x24
            # bge	sp, t2, 0x164
            # bge	t2, sp, 0x15c
            # bge	t0, sp, 0x1c
            # bge	t2, s0, 0x34
            # bge	s1, t0, 0x1c
            # j	-0x24
            # j	-0x130
            # j	-0x140
            # j	-0x1b4
            # j	-0x260
            # j	0x1bc
            # j	0x4a8
            # j	0x15c
            # j	0x4a8
            # bne	t1, t0, 0x110
            # bne	t1, t0, 0x100
            # bne	t1, t0, 0xf4
            # bne	t1, t0, 0x48c
            # bnez	sp, 0x40
            # beqz	sp, 0x148
            # beqz	sp, 0x140
            # beqz	t0, 0x20
            # beqz	sp, -0xbc
            # beq	tp, t0, 0x78
            # beq	tp, t0, 8 
            if op.is_conditional_branch(instruction_text):
                branch_offset = addr + int(raw_offset, 16)
                result.add_branch(BranchType.TrueBranch, branch_offset)
                result.add_branch(BranchType.FalseBranch, addr + instruction_len)
            else: # UNCONDITIONAL JUMP
                branch_offset = addr + int(raw_offset, 16)
                result.add_branch(BranchType.UnconditionalBranch, branch_offset)
        elif arch == "SPARC":
            # brz,pn	%o3, 0x15240
            # bn	%icc, -0x46210
            # bg,a	-0x6927dc
            # bn,a	-0x3cf180
            # bn,a	-0x6af488
            # bn,pn	%icc, 0x38e98
            # bn,pn	%xcc, 0x90fd0
            # fbne	-0x69bc14
            # fbn	%fcc0, -0x46b2c
            # fbn	-0x36edec
            # fbn	0x3b969c
            # fbn	0x26d94
            # fbn	0x7722f0
            # fblg,pn	%fcc3, 0x390f4
            is_branch = 'bn' in instruction_text
            if is_branch:
                branch_offset = int(raw_offset, 16) + addr
                result.add_branch(BranchType.UnconditionalBranch, branch_offset)

        return result

    def get_instruction_text(self, data, addr):
        log_info(str(data))
        (instruction_text, instruction_len) = dis.lazy_disasm(addr)
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken, instruction_text)]

        text_tokens = instruction_text.split()
        instruction = text_tokens[1].lower()
        raw_offset = text_tokens[-1]

        if op.instruction_is_call(instruction):
            call_offset = addr + int(raw_offset, 16)
            tokens.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(call_offset), call_offset))

        return tokens, instruction_len

    # Required NOP
    def get_instruction_low_level_il(self, data, addr, il):
        return None
