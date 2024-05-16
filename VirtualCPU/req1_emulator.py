# Define a class to represent ARM(opcode) instructions
class Instruction:
    def __init__(self, hex_opcode, binary_opcode, assembly_instruction, condition_code, s_bit, reg_n, reg_dest, operand2_imm=None, operand2_reg=None):
        # Initialize Instruction object with details of opcodes
        self.hex_opcode = hex_opcode  # Store hexadecimal opcode
        self.binary_opcode = binary_opcode  # Store binary representation of opcode
        self.assembly_instruction = assembly_instruction  # Store assembly instruction
        self.condition_code = condition_code  # Store condition code
        self.s_bit = s_bit  # Store s_bit
        self.reg_n = reg_n  # Store binary representation of reg_n
        self.reg_dest = reg_dest  # Store binary representation of reg_dest
        self.operand2_imm = operand2_imm  # Store immediate operand (if applicable)
        self.operand2_reg = operand2_reg  # Store register operand (if applicable)
        self.reg_dest_decimal = int(reg_dest, 2)  # Converts  register destination from binary to decimal
        self.reg_n_decimal = int(reg_n, 2)  # Convert reg_n from  binary to decimal

    def __str__(self):
        # Method used to generate string for the instruction
        reg_n_assumption = f"r{self.reg_n_decimal} = 0"  # We are assuming the contents of our registers are empty
        if self.assembly_instruction == "TST":
            return f"{self.hex_opcode} {self.assembly_instruction} flags set as result of {reg_n_assumption} & {self.operand2_imm or self.operand2_reg}"
        elif self.assembly_instruction == "TEQ":
            return f"{self.hex_opcode} {self.assembly_instruction} flags set as result of {reg_n_assumption} ^ {self.operand2_imm or self.operand2_reg}"
        elif self.assembly_instruction == "CMP":
            return f"{self.hex_opcode} {self.assembly_instruction} flags set as result of {reg_n_assumption} - {self.operand2_imm or self.operand2_reg}"
        elif self.assembly_instruction == "CMN":
            return f"{self.hex_opcode} {self.assembly_instruction} flags set as result of {reg_n_assumption} + {self.operand2_imm or self.operand2_reg}"
        elif self.assembly_instruction in ["MOV", "MVN"]:
            return f"{self.hex_opcode} {self.assembly_instruction} r{self.reg_dest_decimal}, {self.operand2_imm}"
        else:
            return f"{self.hex_opcode} {self.assembly_instruction} r{self.reg_dest_decimal}, r{self.reg_n_decimal}, {self.operand2_imm or self.operand2_reg}"

# Function to convert hexadecimal opcode to binary representation
def hex_to_binary(hex_opcode):
    hex_opcode = hex_opcode.replace(" ", "")  # Remove spaces
    try:
        return bin(int(hex_opcode, 16))[2:].zfill(32)  # Convert to binary, remove '0b' prefix, add zeros to the left until 32bits
    except ValueError:
        print("Invalid hexadecimal opcode:", hex_opcode)
        return None

# Function to extract fields from the binary opcode
def extract_fields(binary_opcode):
    condition_code = binary_opcode[0:4]
    s_bit = binary_opcode[11]
    reg_n = binary_opcode[12:16]
    reg_dest = binary_opcode[16:20]

    if binary_opcode[6] == "1":  # Check immediate bit at index 26, this determines if operand2 is a register or number
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
    binary_opcode = hex_to_binary(hex_opcode.strip()) # Removes white spaces between hexadecimal opcodes
    if binary_opcode is None:
        return None

    # Extract opcode and get the assembly instruction
    opcode = binary_opcode[7:11]
    assembly_instruction = decode_assembly_instruction(opcode)

    # Fetch necessary fields
    condition_code, s_bit, reg_n, reg_dest, operand2_imm, operand2_reg = extract_fields(binary_opcode)

    # Create Instruction object
    instruction = Instruction(hex_opcode, binary_opcode, assembly_instruction, condition_code, s_bit, reg_n, reg_dest, operand2_imm, operand2_reg)

    return instruction

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

# Class to represent the ARM Flags
class ARMFlags:
    def __init__(self):
        # Initialize ARM flags
        self.flags = {'N': 0, 'Z': 0, 'C': 0, 'V': 0}

    # Method to set flags according to condition code
    def set_flags(self, condition_code):
        # Set flags based on the condition code
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
        # Decode the instruction, set flags, and execute if applicable
        instruction = decode_instruction(opcode)
        if instruction is None:
            return
        condition_code = instruction.condition_code
        if condition_code == "1111":  # Never executes if condition code is 1111
            print("Instruction not executed. Flags are irrelevant.")
        else:
            self.set_flags(condition_code)  # Set flags based on the condition code
            print(instruction)

# Main function to execute and Decode ARM instructions
def main():
    print("Op-Code Final ARM instruction")
    print("----------------------------------")
    
    arm_processor = ARMFlags()

    instructions = [
        "E3A00001",  
        "E3A01002",  
        "E0802001",  
        "E2822005" 
    ]

    for opcode in instructions:
        arm_processor.execute_instruction(opcode)

if __name__ == "__main__":
    main()
