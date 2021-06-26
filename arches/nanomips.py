from binaryninja.log import log_info
from binaryninja.architecture import Architecture
from binaryninja.function import InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType

from .objdump_plus import ObjdumpPlus
from .objdump_plus import ObjdumpPlus as op

import string

class NanomipsDisasm(ObjdumpPlus):
    def __init__(
        self, 
        filepath, 
        inst_alignment=4, 
        max_inst_len=4
    ):
        super().__init__(filepath)
        self.inst_map = self.load_instruction_map(filepath)

    def get_opcode(self, tokens):
        """
        Example tokens:
        '4003ee:	4320 0002 	lw	t9,0(gp)' => ['4003ee:', '4320', '0002', 'lw', 't9,0(gp)']
        '4003f2:	11ff      	move	t3,ra' => ['4003f2:', '11ff', 'move', 't3,ra']
        """
        opcode = ""
        last_position = 0
        for token in tokens:
            if all(char in string.hexdigits for char in token):
                if len(token) == 4:
                    # --HACK: swap endianness
                    opcode += token[2:] + token[:2]
                    last_position += 1
        opcode = bytes.fromhex(opcode)
        return opcode, last_position

    def load_instruction_map(self, filename):
        instructions = {}
        with open(filename, "r") as fd:
            for line in fd:
                tokens = line.split()
                opcode, position = self.get_opcode(tokens)
                instr_len = len(opcode)
                if instr_len > self.max_inst_len:
                    self.max_inst_len = instr_len
                instruction = " ".join(tokens[position + 1:])
                instructions[opcode] = instruction
        return instructions

    def lazy_disasm(self, data):
        instruction = "NONE"
        instruction_len = 0
        not_dword = False

        # Check 4-byte opcode
        try:
            instruction = self.inst_map[data]
            instruction_len = len(data)
        except KeyError:
            not_dword = True
            pass

        # Check 2-byte opcode
        if not_dword:
            try:
                data = data[:2]
                instruction = self.inst_map[data]
                instruction_len = len(data)
            except KeyError:
                log_info("--FAILED to decode")
                pass
        return instruction, instruction_len

artifacts = op.get_artifacts_path()
objdump_file = artifacts / "./nanomips/nanomips-objdump.txt"
dis = NanomipsDisasm(objdump_file, inst_alignment=4, max_inst_len=1)

class Nanomips(Architecture):
    name = 'Nanomips'
    address_size = 4
    default_int_size = 4
    instr_alignment = dis.inst_alignment
    max_instr_length = dis.max_inst_len

    def get_instruction_info(self, data, addr):
        (instruction_text, instruction_len) = dis.lazy_disasm(data)
        if instruction_len == 0:
            return None

        result = InstructionInfo()
        result.length = instruction_len

        if len(instruction_text) == 0:
            return result

        if instruction_text[0].lower() == 'b':
            tokens = instruction_text.split()
            token = tokens[1]
            # Unconditional Branch
            if all(char in string.hexdigits for char in token):
                # --HACK: base address offset
                dest = int('0x' + token, 16) - 0x400000
                result.add_branch(BranchType.UnconditionalBranch, dest)
                return result
            # Conditional Branch
            if op.is_conditional_branch(instruction_text):
                tokens = instruction_text.split()
                for token in tokens:
                    csv = token.split(",")
                    check = csv[-1]
                    if all(char in string.hexdigits for char in check):
                        # --HACK: base address offset
                        dest = int('0x' + check, 16) - 0x400000
                        result.add_branch(BranchType.TrueBranch, dest)
                        result.add_branch(BranchType.FalseBranch, addr + instruction_len)
                        return result
        return result

    def get_instruction_text(self, data, addr):
        log_info(str(data))
        (instruction_text, instruction_len) = dis.lazy_disasm(data)
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken, instruction_text)]
        return tokens, instruction_len

    # Required NOP
    def get_instruction_low_level_il(self, data, addr, il):
        return None
