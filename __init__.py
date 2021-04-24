from binaryninja.log import log_info
from binaryninja.architecture import Architecture
from binaryninja.function import InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType

from os.path import expanduser
from struct import unpack, pack
import string

home = expanduser("~")

# TODO: Get objdump file from user-input
objdump_file = f"{home:}/.binaryninja/plugins/objdump-plus/examples/nanomips-objdump.txt"
g_max_instr_len = 1

def get_opcode(tokens):
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

def get_instruction_map(filename):
    global g_max_instr_len
    instructions = {}
    with open(filename, "r") as fd:
        for line in fd:
            tokens = line.split()
            opcode, position = get_opcode(tokens)
            instr_len = len(opcode)
            if instr_len > g_max_instr_len:
                g_max_instr_len = instr_len
            instruction = " ".join(tokens[position + 1:])
            instructions[opcode] = instruction
    return instructions

def lazy_disasm(data):
    global g_max_instr_len
    global instruction_map

    instruction = "NONE"
    instruction_len = 0
    not_dword = False

    # Check 4-byte opcode
    try:
        instruction = instruction_map[data]
        instruction_len = len(data)
    except KeyError:
        not_dword = True
        pass

    # Check 2-byte opcode
    if not_dword:
        try:
            data = data[:2]
            instruction = instruction_map[data]
            instruction_len = len(data)
        except KeyError:
            log_info("--FAILED to decode")
            pass
    return instruction, instruction_len

def is_conditional_branch(instruction_text):
    lowered = instruction_text.lower()
    is_conditional = False
    if 'eq' in lowered:
        is_conditional = True
    elif 'ne' in lowered:
        is_conditional = True
    elif 'lt' in lowered:
        is_conditional = True
    elif 'gt' in lowered:
        is_conditional = True
    return is_conditional

instruction_map = get_instruction_map(objdump_file)

class ObjdumpPlus(Architecture):
    global g_max_instr_len
    name = 'ObjdumpPlus'
    address_size = 4
    default_int_size = 4
    instr_alignment = 4
    max_instr_length = g_max_instr_len

    def get_instruction_info(self, data, addr):
        (instruction_text, instruction_len) = lazy_disasm(data)
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
            if is_conditional_branch(instruction_text):
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
        (instruction_text, instruction_len) = lazy_disasm(data)
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken, instruction_text)]
        return tokens, instruction_len

    # Required NOP
    def get_instruction_low_level_il(self, data, addr, il):
        return None

ObjdumpPlus.register()

