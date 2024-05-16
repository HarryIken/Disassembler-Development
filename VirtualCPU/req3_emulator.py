# from req1_sum import decode_instruction
#
# Define a class to represent ARM instructions
class Instruction:
    def __init__(self, hex_opcode, binary_opcode, assembly_instruction, condition_code, s_bit, reg_n, reg_dest,
                 operand2_imm=None, operand2_reg=None):
        # Initialize Instruction object with opcode details
        self.hex_opcode = hex_opcode
        self.binary_opcode = binary_opcode
        self.assembly_instruction = assembly_instruction
        self.condition_code = condition_code
        self.s_bit = s_bit
        self.reg_n = reg_n
        self.reg_dest = reg_dest
        self.operand2_imm = operand2_imm
        self.operand2_reg = operand2_reg
        self.reg_dest_decimal = int(reg_dest, 2)  # Convert binary register destination to decimal
        self.reg_n_decimal = int(reg_n, 2)  # Convert binary reg_n to decimal

    # def __str__(self):
    #     # String representation of the instruction
    def __str__(self):
        reg_n_assumption = f"r{self.reg_n_decimal} = 0"  # We are assuming the content of our registers are empty
        # String representation of the instruction
        if self.assembly_instruction == "TST":
            return f"{self.hex_opcode} {self.assembly_instruction} flags set as result of {reg_n_assumption} & {self.operand2_imm or self.operand2_reg}"
        elif self.assembly_instruction == "TEQ":
            return f"{self.hex_opcode} {self.assembly_instruction} flags set as result of {reg_n_assumption} ^ {self.operand2_imm or self.operand2_reg}"
        elif self.assembly_instruction == "CMP":
            return f"{self.hex_opcode} {self.assembly_instruction}  flags set as result of {reg_n_assumption} - {self.operand2_imm or self.operand2_reg}"
        elif self.assembly_instruction == "CMN":
            return f"{self.hex_opcode} {self.assembly_instruction}  flags set as result of {reg_n_assumption} + {self.operand2_imm or self.operand2_reg}"
        elif self.assembly_instruction in ["MOV", "MVN"]:
            return f"{self.hex_opcode} {self.assembly_instruction} r{self.reg_dest_decimal}, {self.operand2_imm}"
        else:
            return f"{self.hex_opcode} {self.assembly_instruction} r{self.reg_dest_decimal}, r{self.reg_n_decimal}, {self.operand2_imm or self.operand2_reg}"


# Function to convert hexadecimal opcode to binary representation
def hex_to_binary(hex_opcode):
    # Convert hexadecimal opcode to binary representation
    hex_opcode = hex_opcode.replace(" ", "")  # Remove spaces
    try:
        return bin(int(hex_opcode, 16))[2:].zfill(32)  # Convert to binary, strip '0b' prefix, pad with zeros
    except ValueError:
        print("Invalid hexadecimal opcode:", hex_opcode)
        return None


# Function to extract fields from the binary opcode
def extract_fields(binary_opcode):
    # Extract fields from the binary opcode
    condition_code = binary_opcode[0:4]
    s_bit = binary_opcode[11]
    reg_n = binary_opcode[12:16]
    reg_dest = binary_opcode[16:20]

    if binary_opcode[6] == "1":  # Check immediate bit at index 26
        operand2_imm = binary_opcode[20:]
        operand2_imm = int(operand2_imm, 2)
        operand2_imm = f"#{operand2_imm}"
        operand2_reg = None
    else:
        operand2_imm = None
        operand2_reg = binary_opcode[20:]
        operand2_reg = int(operand2_reg, 2)
        operand2_reg = f"r{operand2_reg}"

    return condition_code, s_bit, reg_n, reg_dest, operand2_imm, operand2_reg


# Function to decode the instruction from hexadecimal opcode
def decode_instruction(hex_opcode):
    # Decode the instruction from hexadecimal opcode
    binary_opcode = hex_to_binary(hex_opcode.strip())
    if binary_opcode is None:
        return None

    # Extract opcode and get the assembly instruction
    opcode = binary_opcode[7:11]
    assembly_instruction = decode_assembly_instruction(opcode)

    # Fetch necessary fields
    condition_code, s_bit, reg_n, reg_dest, operand2_imm, operand2_reg = extract_fields(binary_opcode)

    # Create Instruction object
    instruction = Instruction(hex_opcode, binary_opcode, assembly_instruction, condition_code, s_bit, reg_n, reg_dest,
                              operand2_imm, operand2_reg)

    final_arm_instruction = format_arm_instruction(instruction)
    return {
        "instruction": instruction,
        "final_arm_instruction": final_arm_instruction
    }


# Function to map opcode to assembly instruction
def decode_assembly_instruction(opcode):
    instructions = {
        "0000": "AND",
        "0001": "EOR",
        "0010": "SUB",
        "0011": "RSB",
        "0100": "ADD",
        "0101": "ADC",
        "0110": "SBC",
        "0111": "RSC",
        "1000": "TST",
        "1001": "TEQ",
        "1010": "CMP",
        "1011": "CMN",
        "1100": "ORR",
        "1101": "MOV",
        "1110": "BIC",
        "1111": "MVN"
    }

    return instructions.get(opcode, "Unknown")


# Class to represent the ARM processor
class FlagProcessor:
    def __init__(self):
        # Initialize ARM Processor with flags
        self.flags = {'N': 0, 'Z': 0, 'C': 0, 'V': 0}

    # Method to set processor flags based on condition code
    def set_flags(self, condition_code):
        if condition_code == "0000":  # Equal
            self.flags['Z'] = 1
        elif condition_code == "0001":  # Not Equal
            self.flags['Z'] = 0
        elif condition_code == "0010":  # Carry Set
            self.flags['C'] = 1
        elif condition_code == "0011":  # Carry Clear
            self.flags['C'] = 0
        elif condition_code == "0100":  # Minus
            self.flags['N'] = 1
        elif condition_code == "0101":  # Plus
            self.flags['N'] = 0
        elif condition_code == "0110":  # Overflow Set
            self.flags['V'] = 1
        elif condition_code == "0111":  # Overflow Clear
            self.flags['V'] = 0
        elif condition_code == "1000":  # Higher
            self.flags['C'] = 1
            self.flags['Z'] = 0
        elif condition_code == "1001":  # Lower or Same
            self.flags['C'] = 0
            self.flags['Z'] = 1
        elif condition_code == "1010":  # Greater or Equal
            self.flags['N'] = 0
            self.flags['V'] = 0
        elif condition_code == "1011":  # Less Than
            self.flags['N'] = 1
            self.flags['V'] = 1
        elif condition_code == "1100":  # Greater Than
            self.flags['Z'] = 0
            self.flags['N'] = 0
        elif condition_code == "1101":  # Less or Equal
            self.flags['Z'] = 1
            self.flags['N'] = 1
        # No flag settings for "Always" (1110) and "Never" (1111)

    # Method to execute ARM instruction based on opcode
    def execute_instruction(self, opcode):
        instruction = decode_instruction(opcode)
        if instruction is None:
            return
        condition_code = instruction.condition_code
        if condition_code == "1111":  # Never executes
            print("Instruction not executed. Flags are irrelevant.")
        else:
            self.set_flags(condition_code)  # Set flags based on the condition code
            print(instruction)


def format_arm_instruction(instruction):
    if instruction.assembly_instruction in ["MOV", "CMP", "TST", "TEQ", "CMN"]:
        return f"{instruction.hex_opcode.upper()} {instruction.assembly_instruction} r{instruction.reg_dest_decimal}, {instruction.operand2_imm or instruction.operand2_reg}"
    else:
        return f"{instruction.hex_opcode.upper()} {instruction.assembly_instruction} r{instruction.reg_dest_decimal}, r{instruction.reg_n_decimal}, {instruction.operand2_imm or instruction.operand2_reg}"


class ARMProcessor:
    def __init__(self):
        self.registers = {f"R{i}": "00000000" for i in range(16)}
        self.registers["R13"] = "00010000"
        self.registers["R15"] = "00000104"  # Initialize program counter as a string
        self.RegN = 0
        self.RegDest = 0
        self.Operand2 = 0
        self.carry_flag = 0

    def execute_instruction(self, opcode):
        decoded_result = decode_instruction(
            opcode)  # Returns a dictionary containing the instruction object and final ARM instruction.
        instruction = decoded_result['instruction']  # Access the Instruction object using its key.

        print(f"Op-Code    Assembly Mnemonic")
        print("----------------------------------")
        # Call the appropriate method based on the instruction type
        if instruction.assembly_instruction == "MOV":
            self.move(instruction)
        elif instruction.assembly_instruction == "ADD":
            self.execute_ADD(instruction)
        elif instruction.assembly_instruction == "SUB":
            self.execute_SUB(instruction)
        # Include additional elif blocks for other instructions like CMP, AND, etc.

        # Check if the instruction type is one of the specified types
        if instruction.assembly_instruction in ["MOV", "CMP", "TST", "TEQ", "CMN"]:
            print(
                f"Final ARM instruction: {instruction.hex_opcode.upper()} = {instruction.assembly_instruction} r{instruction.reg_dest_decimal}, {instruction.operand2_imm or instruction.operand2_reg}")
        else:
            print(
                f"Final ARM instruction: {instruction.hex_opcode.upper()} = {instruction.assembly_instruction} r{instruction.reg_dest_decimal}, r{instruction.reg_n_decimal}, {instruction.operand2_imm or instruction.operand2_reg}")

        self.print_registers()
        input("Press <return> for next instruction.")
        self.update_pc()

    def move(self, instruction):
        if instruction.operand2_imm:
            immediate_value = instruction.operand2_imm.strip('#')
            reg = self.registers[f"R{instruction.reg_dest_decimal}"]
            replace_length = min(len(immediate_value), len(reg))
            self.registers[f"R{instruction.reg_dest_decimal}"] = reg[:-replace_length] + immediate_value[
                                                                                         -replace_length:]

    def update_pc(self):
        # Increment the value stored in register 15 (the program counter) by 4
        pc = self.registers['R15']  # Assuming register 15 is represented by 'R15'
        pc_value = int(pc, 16)  # Convert hexadecimal value to integer
        pc_value += 4  # Increment by 4
        pc_value %= 0x10000  # Ensure it wraps around if it exceeds 0xFFFF
        pc = format(pc_value, '04X')  # Convert back to hexadecimal string with leading zeros
        self.registers['R15'] = pc  # Update the program counter register

    def print_registers(self):
        for i in range(16):
            register_value = self.registers[f'R{i}'].zfill(8)  # Pad with leading zeros to ensure eight bits
            print(f"R{i}: {register_value}", end=" ")
            if i % 4 == 3:
                print()

    def execute_AND(self):
        self.RegDest = self.RegN & self.Operand2

    def execute_EOR(self):
        self.RegDest = self.RegN ^ self.Operand2

    # def execute_SUB(self):
    #     self.RegDest = self.RegN - self.Operand2
    def execute_SUB(self, instruction):
        # Fetch value from source register (RegN)
        source_value = int(self.registers[f"R{instruction.reg_n_decimal}"], 16)

        # Determine if Operand2 is an immediate value or a register value
        if instruction.operand2_imm:
            operand_value = int(instruction.operand2_imm.strip('#'), 16)
        else:
            # Extract the numeric part of the operand2 register, assuming operand2_reg format is like 'r1', 'r2', etc.
            operand_index = self.clean_register_key(instruction.operand2_reg)
            operand_value = int(self.registers[f"R{operand_index}"], 16)

        # Compute the result of the subtraction
        result = source_value - operand_value

        # Store the result back into the destination register
        self.registers[f"R{instruction.reg_dest_decimal}"] = f"{result:08X}"

    def execute_RSB(self):
        self.RegDest = self.Operand2 - self.RegN

    def execute_ADD(self, instruction):
        # print(f"Debug: operand2_reg = {instruction.operand2_reg}")  # This will show what is being passed.

        # Fetch value from source register (RegN)
        source_value = int(self.registers[f"R{instruction.reg_n_decimal}"], 16)

        # Determine if Operand2 is an immediate value or a register value
        if instruction.operand2_imm:
            operand_value = int(instruction.operand2_imm.strip('#'), 16)
        else:
            # Correctly format the register name by stripping non-numeric characters
            reg_index = self.clean_register_key(instruction.operand2_reg)
            reg_key = f"R{reg_index}"
            # print(f"Attempting to access register: {reg_key}")  # Check the exact register key
            operand_value = int(self.registers[reg_key], 16)

        # Compute the result
        result = source_value + operand_value
        # Format result as hex string and store in destination register
        self.registers[f"R{instruction.reg_dest_decimal}"] = f"{result:08X}"

    def clean_register_key(self, reg):
        # Remove non-numeric characters from the register key
        return ''.join(filter(str.isdigit, reg))

    def execute_ADC(self):
        self.RegDest = self.RegN + self.Operand2 + self.carry_flag

    def execute_SBC(self):
        self.RegDest = self.RegN - self.Operand2 - (not self.carry_flag)

    def execute_RSC(self):
        self.RegDest = self.Operand2 - self.RegN - (not self.carry_flag)

    def execute_TST(self):
        result = self.RegN & self.Operand2
        # Set flags based on the result

    def execute_TEQ(self):
        result = self.RegN ^ self.Operand2
        # Set flags based on the result

    def execute_CMP(self, instruction):
        # Fetch value from source register (RegN)
        n_value = int(self.registers[f"R{instruction.reg_n_decimal}"], 16)

        # Determine if Operand2 is an immediate value or a register value
        if instruction.operand2_imm:
            operand_value = int(instruction.operand2_imm.strip('#'), 16)
        else:
            # Use helper function to clean the register key if needed
            operand_index = self.clean_register_key(instruction.operand2_reg)
            operand_value = int(self.registers[f"R{operand_index}"], 16)

        # Compute the result of the subtraction
        result = n_value - operand_value

        # Set flags based on the result
        self.set_flags(result)

        # Note: In CMP, the result is not stored; only flags are affected

    def set_flags(self, result):
        # Assuming we're just updating the Zero (Z) and Negative (N) flags
        if result == 0:
            self.flags['Z'] = 1  # Set Zero flag if result is zero
        else:
            self.flags['Z'] = 0  # Clear Zero flag if result is non-zero

        if result < 0:
            self.flags['N'] = 1  # Set Negative flag if result is negative
        else:
            self.flags['N'] = 0  # Clear Negative flag if result is non-negative

    def execute_CMN(self):
        result = self.RegN + self.Operand2
        # Set flags based on the result

    def execute_ORR(self):
        self.RegDest = self.RegN | self.Operand2

    def execute_MOV(self):
        self.RegDest = self.Operand2

    def execute_BIC(self):
        self.RegDest = self.RegN & ~self.Operand2

    def execute_MVN(self):
        self.RegDest = ~self.Operand2



class BranchInstruction:
    def __init__(self, condition_code, link_bit, offset):
        self.condition_code = condition_code
        self.link_bit = link_bit
        self.offset = offset
        self.total_cycles = 0

    def __str__(self):
        return f"Condition code: {self.condition_code}, Link bit: {self.link_bit}, Offset: {self.offset}"

    def print_elapsed_time(self):
        print(f"Total cycles elapsed: {self.total_cycles}")


class SingleDataTransferInstruction:
    def __init__(self, hex_opcode):
        self.binary_opcode = bin(int(hex_opcode, 16))[2:].zfill(32)

    def decode(self):
        condition_code = int(self.binary_opcode[0:4], 2)
        immediate = int(self.binary_opcode[6], 2)
        pre_post = int(self.binary_opcode[7], 2)
        up_down = int(self.binary_opcode[8], 2)
        byte_word = int(self.binary_opcode[9], 2)
        writeback = int(self.binary_opcode[10], 2)
        load_store = int(self.binary_opcode[11], 2)
        reg_n = int(self.binary_opcode[12:16], 2)
        reg_dest = int(self.binary_opcode[16:20], 2)
        offset = int(self.binary_opcode[20:], 2)
        return {
            "condition_code": condition_code,
            "immediate": immediate,
            "pre_post": pre_post,
            "up_down": up_down,
            "byte_word": byte_word,
            "writeback": writeback,
            "load_store": load_store,
            "reg_n": reg_n,
            "reg_dest": reg_dest,
            "offset": offset
        }


class SWIInstruction:
    def __init__(self, hex_opcode):
        self.binary_opcode = bin(int(hex_opcode, 16))[2:].zfill(32)
        self.interrupt_code = int(self.binary_opcode[8:], 2)  # Extract interrupt code during initialization
        self.total_cycles = 0

    def decode(self):
        condition_code = int(self.binary_opcode[0:4], 2)
        return {
            "condition_code": condition_code,
            "interrupt_code": self.interrupt_code  # Return the stored interrupt code
        }

    def execute_instruction(self):
        cycle_count = 5  # Default cycle count for SWI instruction
        if self.interrupt_code == 0x01:
            cycle_count = 5  # Adjust cycle count as needed for specific interrupt codes

        print("Cycle count:", cycle_count)
        self.total_cycles += cycle_count
        return cycle_count

    def print_elapsed_time(self):
        print(f"Total cycles elapsed: {self.total_cycles}")


class ExtendedARMProcessor(ARMProcessor):
    def __init__(self):
        super().__init__()
        self.total_cycles = 0

    def execute_instruction(self, opcode):
        decoded_result = decode_instruction(opcode)
        instruction = decoded_result['instruction']

        if instruction.assembly_instruction == "MOV":
            self.move(instruction)
        elif instruction.assembly_instruction == "ADD":
            self.execute_ADD(instruction)
        elif instruction.assembly_instruction == "SUB":
            self.execute_SUB(instruction)
        # Add more elif blocks for other instructions like CMP, AND, etc.

        if instruction.assembly_instruction in ["MOV", "CMP", "TST", "TEQ", "CMN"]:
            self.total_cycles += 1  # Add 1 cycle for data processing operations
        elif instruction.assembly_instruction == "LDR":
            self.total_cycles += 3 + 2  # Add 3 cycles for LDR (+ 2 if RegDest is PC)
        elif instruction.assembly_instruction == "STR":
            self.total_cycles += 2  # Add 2 cycles for STR
        elif instruction.assembly_instruction in ["B", "BL"]:
            self.total_cycles += 3  # Add 3 cycles for B or BL
        elif instruction.assembly_instruction == "SWI":
            self.total_cycles += 5  # Add 5 cycles for SWI

    def execute_branch_instruction(self, hex_opcode):
        branch_instruction = parse_branch_instruction(hex_opcode)
        # Execute branch instruction and update total cycles
        if branch_instruction.link_bit == '1':
            self.total_cycles += 3  # Add 3 cycles for BL
        else:
            self.total_cycles += 3  # Add 3 cycles for B

    def execute_single_data_transfer(self, hex_opcode):
        instruction = SingleDataTransferInstruction(hex_opcode)
        decoded_fields = instruction.decode()
        # Execute single data transfer instruction and update total cycles
        if decoded_fields['load_store'] == 0:
            self.total_cycles += 2 if decoded_fields['byte_word'] == 0 else 3
        else:
            self.total_cycles += 2  # Add 2 cycles for STR

    def execute_swi_instruction(self, hex_opcode):
        swi = SWIInstruction(hex_opcode)
        decoded_fields = swi.decode()
        # Execute SWI instruction and update total cycles
        self.total_cycles += swi.execute_instruction()

    def print_elapsed_time(self):
        print(f"Total cycles elapsed: {self.total_cycles}")


def parse_branch_instruction(hex_opcode):
    binary_opcode = hex_to_binary(hex_opcode)
    if binary_opcode is None:
        return None

    # Ensure the binary opcode is at least 32 characters long
    if len(binary_opcode) < 32:
        raise ValueError("Binary opcode must be at least 32 characters long")

    condition_code = binary_opcode[0:4]
    link_bit = binary_opcode[24]
    offset = binary_opcode[25:]  # Extract the offset part from the binary opcode

    return BranchInstruction(condition_code, link_bit, offset)


def main():
    arm_processor = ExtendedARMProcessor()
    arm_processor_2 = ARMProcessor()
    instructions = [
        "E3A00001",
        "E3A01002", 
        "E0802001", 
        "E2822005", 
    ]
    
    for opcode in instructions:
        arm_processor_2.execute_instruction(opcode)
        for opcode in instructions:
            if opcode.startswith('9'):
                arm_processor.execute_branch_instruction(opcode)
            elif opcode.startswith('E3') or opcode.startswith('E1'):
                arm_processor.execute_single_data_transfer(opcode)
            elif opcode.startswith('EF'):
                arm_processor.execute_swi_instruction(opcode)
            else:
                arm_processor.execute_instruction(opcode)

    arm_processor.print_elapsed_time()

    print('Program end. Terminating.')

    

if __name__ == "__main__":
    main()
