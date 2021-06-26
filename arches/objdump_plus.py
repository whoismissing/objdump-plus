from pathlib import Path
import platform

class ObjdumpPlus():

    def __init__(
        self, 
        filepath, 
        inst_alignment=4, 
        max_inst_len=4
    ):
        """
        :param filename: filename of linear disassembly text file to lift
                         disassembly from.
        :param inst_map: Dictionary mapping of key: op-codes to value: ASM.
                         Program counter can also be used as a key instead.
        :param inst_alignment: int representing the instruction alignment
                               for the CPU arch being disassembled.
        :param max_inst_len: int representing maximum length of an 
                             instruction for the CPU arch being disassembled.
        """
        self.filepath = filepath
        self.inst_map = None
        self.inst_alignment = inst_alignment
        self.max_inst_len = max_inst_len
        
    def get_opcode(self, tokens) -> (bytes, int):
        """
        Given a list of strings after a line.split(), parse the tokens
        and return an opcode as a byte-string and the index of the last
        token that was parsed.
        :param tokens: a list of strings after a line.split() by spaces
        :returns (opcode, last_position):
        """
        raise NotImplementedError

    def load_instruction_map(self, filename):
        """
        Open and read a linear disassembly text file and create a dictionary
        mapping of opcodes (or program counters) as keys to asm text
        instructions as values.
        :param filename: Path to linear disassembly text file
        :returns instructions: dictionary of opcode-asm key-value pairs
        """
        raise NotImplementedError

    def lazy_disasm(self, data) -> (str, int):
        """
        Using the instruction map, obtain the corresponding asm text and
        instruction length as a tuple for a given key (opcode or program counter).
        :param data: key to the instruction map to obtain corresponding disassembly
        :returns instruction: string representing instruction text
        :returns instruction_len: int representing instruction length
        """
        raise NotImplementedError

    @classmethod
    def get_plugins_path(cls):
        if platform.system() == 'Linux':
            plugins = Path("~/.binaryninja/plugins/")
        elif platform.system() == 'Windows':
            import os
            plugins = Path(os.path.expandvars("%APPDATA%/Binary Ninja/plugins/"))
        else:
            raise RuntimeError("Unknown platform, plugin is NOT supported!")
        return plugins

    @classmethod
    def get_artifacts_path(cls):
        plugins = ObjdumpPlus.get_plugins_path()
        artifacts = plugins / "./objdump-plus/arches/artifacts"
        return artifacts

    @classmethod
    def is_conditional_branch(cls, instruction_text):
        """
        Static method to check if a given instruction text
        is a conditional branch.
        :param instruction_text: str instruction text
        :returns is_conditional: boolean True if is_conditional_branch,
                                 otherwise False
        """
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

    @classmethod
    def instruction_is_branch(cls, instruction):
        """
        Static method to check if a given instruction text
        is a branch.
        :param instruction: str instruction text
        :returns is_conditional: boolean True if is_branch,
                                 otherwise False
        """
        is_branch = False
        and_link = False
        if len(instruction) > 1:
            if instruction[1] == 'a':
                and_link = True
        if instruction[0] == 'b' and not and_link:
            is_branch = True
        # Match RISCV
        # j 0x1bc
        elif instruction[0] == 'j' and not and_link:
            is_branch = True
        # Match SPARC
        # fbne	-0x69bc14
        # fbn	0x7722f0
        # fblg,pn	%fcc3, 0x390f4
        elif instruction[0] == 'f' and 'fb' in instruction:
            is_branch = True
        return is_branch

    @classmethod
    def instruction_is_call(cls, instruction):
        """
        Static method to check if a given instruction text
        is a call
        :param instruction: str instruction text
        :returns is_conditional: boolean True if is_call,
                                 otherwise False
        """
        # RISCV L 0x10168:	ef00004a	jal	0x4a0
        # RISCV L 0x1067c:	eff05ff2	jal	-0xdc
        # MIPS B 0x10d60:	0c281084	jal	0xa04210
        # SPARC B 0x10900:	6f73a534	call	-0x42306230
        is_call = False
        and_link = False
        if len(instruction) > 1:
            if instruction[1] == 'a':
                and_link = True
        if instruction[0] == 'j' and and_link:
            is_call = True
        elif instruction[0] == 'c' and and_link:
            is_call = True
