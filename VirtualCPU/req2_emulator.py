# Define a class to represent ARM instructions
class Instruction:
    def __init__(self, hex_opcode, binary_opcode, assembly_instruction, condition_code, s_bit, reg_n, reg_dest,
                 operand2_imm=None, operand2_reg=None):
        # Initialize Instruction object with opcode details
        self.hex_opcode = hex_opcode # Store hexadecimal opcode
        self.binary_opcode = binary_opcode # Store binary representation of opcode
        self.assembly_instruction = assembly_instruction # Store assembly instruction depending on the opcode
        self.condition_code = condition_code # Store condition opcode
        self.s_bit = s_bit # Store S_bit
        self.reg_n = reg_n # Store reg_n opcode
        self.reg_dest = reg_dest # Store register destination opcode
        self.operand2_imm = operand2_imm # Store Store immediate operand (if applicable)
        self.operand2_reg = operand2_reg # Store register operand (if applicable)
        self.reg_dest_decimal = int(reg_dest, 2)  # Convert binary register destination to decimal
        self.reg_n_decimal = int(reg_n, 2)  # Convert binary reg_n to decimal

    # def __str__(self):
    #     # String representation of the instruction
    def __str__(self):
        reg_n_assumption = f"r{self.reg_n_decimal} = 0"  # We are assuming the content of all registers are empty except R13 and R15
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
        return bin(int(hex_opcode, 16))[2:].zfill(32)  # Convert to binary, remove '0b' prefix, pad with zeros to the left until 32bits
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
    binary_opcode = hex_to_binary(hex_opcode.strip()) # Removes white spaces between hexadecimal opcodes
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


# Class to represent Flags
class ARMFlags:
    def __init__(self):
        # Initialize ARM Processor with flags
        self.flags = {'N': 0, 'Z': 0, 'C': 0, 'V': 0}

    # Method to set flags based on condition code
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
    if instruction.assembly_instruction == "TST":
        return f"{instruction.hex_opcode} {instruction.assembly_instruction} flags set as result of r{instruction.reg_n_decimal} = 0 & {instruction.operand2_imm or instruction.operand2_reg}"
    elif instruction.assembly_instruction == "TEQ":
        return f"{instruction.hex_opcode} {instruction.assembly_instruction} flags set as result of r{instruction.reg_n_decimal} = 0 ^ {instruction.operand2_imm or instruction.operand2_reg}"
    elif instruction.assembly_instruction == "CMP":
        return f"{instruction.hex_opcode} {instruction.assembly_instruction} flags set as result of r{instruction.reg_n_decimal} = 0 - {instruction.operand2_imm or instruction.operand2_reg}"
    elif instruction.assembly_instruction == "CMN":
        return f"{instruction.hex_opcode} {instruction.assembly_instruction} flags set as result of r{instruction.reg_n_decimal} = 0 + {instruction.operand2_imm or instruction.operand2_reg}"
    elif instruction.assembly_instruction in ["MOV", "MVN"]:
        return f"{instruction.hex_opcode} {instruction.assembly_instruction} r{instruction.reg_dest_decimal}, {instruction.operand2_imm}"
    else:
        return f"{instruction.hex_opcode} {instruction.assembly_instruction} r{instruction.reg_dest_decimal}, r{instruction.reg_n_decimal}, {instruction.operand2_imm or instruction.operand2_reg}"

class ARMRegisters:
    def __init__(self):
        self.registers = {f"R{i}": "00000000" for i in range(16)}
        self.registers["R13"] = "00010000"  # set to the top of stack position
        self.registers["R15"] = "00000104"  # Initialize program counter as a string
  
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
       
        # all instruction being executed
        if instruction.assembly_instruction in ["MOV", "MVN"]:
            print(
                f"Final ARM instruction: {instruction.hex_opcode.upper()} = {instruction.assembly_instruction} r{instruction.reg_dest_decimal}, {instruction.operand2_imm or instruction.operand2_reg}")
        elif instruction.assembly_instruction == ["CMP", "CMN", "TEQ", "TST"]:
            print(
                f"Final ARM instruction: {instruction.hex_opcode.upper()} = {instruction.assembly_instruction} r{instruction.reg_n_decimal}, {instruction.operand2_imm or instruction.operand2_reg}")    
        else:
            print(
                f"Final ARM instruction: {instruction.hex_opcode.upper()} = {instruction.assembly_instruction} r{instruction.reg_dest_decimal}, r{instruction.reg_n_decimal}, {instruction.operand2_imm or instruction.operand2_reg}")

        self.print_registers()
        input("Press <return> for next instruction.")
        self.update_pc()

    def move(self, instruction):
        if instruction.operand2_imm: # Check if the operand is an immediate value
            immediate_value = instruction.operand2_imm.strip('#') # Extract the immediate value and remove the '#' prefix
            reg = self.registers[f"R{instruction.reg_dest_decimal}"] # Retrieve the value stored in the destination register
            replace_length = min(len(immediate_value), len(reg))  # Determine the length to replace
            self.registers[f"R{instruction.reg_dest_decimal}"] = reg[:-replace_length] + immediate_value[
                                                                                         -replace_length:]  # Replace the appropriate portion of the register's value with the immediate value

    def update_pc(self):
        # Increment the value stored in register 15 (the program counter) by 4
        pc = self.registers['R15']  # Assuming register 15 is represented by 'R15'
        pc_value = int(pc, 16)  # Convert hexadecimal value to integer
        pc_value += 4  # Increment by 4
        pc_value %= 0x10000  # Ensure it wraps around if it exceeds 0xFFFF
        pc = format(pc_value, '04X')  # Convert back to hexadecimal string with leading zeros
        self.registers['R15'] = pc  # Update the program counter register

    def print_registers(self):  # Method to print the contents of the ARM processor registers
        for i in range(16):  # Iterate over the 16 registers
            register_value = self.registers[f'R{i}'].zfill(8)  # Pad with leading zeros to ensure eight bits
            print(f"R{i}: {register_value}", end=" ")  # Print the register number and its value
            if i % 4 == 3:  # Print a newline after every 4 registers
                print()

    def execute_AND(self):
        self.RegDest = self.RegN & self.Operand2

    def execute_EOR(self):
        self.RegDest = self.RegN ^ self.Operand2

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

instructions = [
    "E3A00001",  
    "E3A01002",  
    "E0802001",  
    "E2822005" 
]

# Create an instance of ARMRegisters
processor = ARMRegisters()

# Execute each instruction
for instruction in instructions:
    processor.execute_instruction(instruction)

print('Program end. Terminating.')