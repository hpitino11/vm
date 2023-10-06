/* 
    COP3402 System Software
    HW1
    Group 62
    Zachary Cary
    Hanna Pitino
    Blake Yerks
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "bof.h"
#include "file_location.h"
#include "instruction.h"
#include "regname.h"
#include "utilities.h"
#include "machine_types.h"

#define BYTES_PER_WORD 4
#define MEMORY_SIZE_IN_BYTES (65536 - BYTES_PER_WORD)
#define MEMORY_SIZE_IN_WORDS (MEMORY_SIZE_IN_BYTES / BYTES_PER_WORD)

static union mem_u
{
    byte_type bytes[MEMORY_SIZE_IN_BYTES];
    word_type words[MEMORY_SIZE_IN_WORDS];
    bin_instr_t instrs[MEMORY_SIZE_IN_WORDS];
} memory;

// Initialization of Global variables
bool tracing; // Flag to start or stop tracing
int p_flag; // Flag for knowing whether or not we are using -p instructions
int instr_flag = 0; // Flag to start instructs printed
int trigger_flag = 0; // Flag used to help if we trace or not
int PC = 0; // Global PC variable used to update values
int LBU_flag = 0; // Tells us if LBU was called important in printing out Y
int data_count = 0;
int print_counter = 0;

// Was having issues using the regname.c file so had to make our own
typedef enum
{
    // Register numbering based on the provided details
    R0 = 0, // always 0 (can’t write to this register!)
    AT,     // assembler temporary $at
    V0,
    V1, // function results $v0, $v1
    A0,
    A1,
    A2,
    A3, // function arguments $a0−$a3
    T0,
    T1,
    T2,
    T3,
    T4,
    T5,
    T6,
    T7, // temporaries $t0−$t7
    S0,
    S1,
    S2,
    S3,
    S4,
    S5,
    S6,
    S7, // temporaries $s0−$s7
    T8,
    T9, // temporaries $t8, $t9
    OS0,
    OS1,    // reserved for use by OS
    GP_REG, // Global Pointer $gp
    SP_REG, // Stack Pointer $sp
    FP_REG, // Frame Pointer $fp
    RA_REG  // Return Address $ra
} RegisterNumber;

typedef struct
{
    word_type GPR[32]; // 32 general-purpose registers
    word_type PC;      // Program counter
    word_type HI;      // High part of multiplication or remainder of division
    word_type LO;      // Low part of multiplication or quotient of division
} SRM_Registers;

// Function headers
void print_state(BOFFILE bf, BOFHeader header, int i, const char *tempfile, const char *tempfile2);
void print_state_p(BOFFILE bf, BOFHeader header);
BOFFILE bof_read_open(const char *filename);
BOFHeader bof_read_header(BOFFILE bf);
bin_instr_t instruction_read(BOFFILE bf);
word_type bof_read_word(BOFFILE bf);
void bof_close(BOFFILE bf);
void invariant_check();

SRM_Registers srm_registers; // Creates a set of registers for SRM

// Helper functions used to load all of the regs, instrs, and data 
void load_registers(SRM_Registers *regs, BOFFILE bf, BOFHeader bh)
{
    // Here the global pointer, stack pointer, and frame pointer are part of the GPR array
    regs->GPR[GP_REG] = bh.data_start_address; // gp = start of address
    if (regs->GPR[FP_REG] == bh.stack_bottom_addr || regs->GPR[SP_REG] == bh.stack_bottom_addr)
    {
        exit(0);
    }
    else
    {
        regs->GPR[FP_REG] = bh.stack_bottom_addr;
        regs->GPR[SP_REG] = bh.stack_bottom_addr;
        // set to bottom of stack
    }
    regs->PC = bh.text_start_address; // start address
}

// loads the instructions into the array of instr binary instructions
void load_instructions(BOFFILE bf, BOFHeader bh)
{
    for (int i = 0; i < bh.text_length / BYTES_PER_WORD; i++)
    {
        memory.instrs[i] = instruction_read(bf);
    }
}

void load_data(BOFFILE bf, BOFHeader bh)
{
    int word_address = bh.data_start_address;
    data_count = bh.data_length / BYTES_PER_WORD;
    for (int i = 0; i < data_count; i++)
    {
        memory.words[word_address] = bof_read_word(bf);
        word_address += 4;
    }
}

void load_bof_file(SRM_Registers *regs, BOFFILE bf, BOFHeader bh)
{
    load_instructions(bf, bh);
    load_data(bf, bh);
    load_registers(regs, bf, bh);
}

// Print function used for printing out the instruction strinmg
void print_instructions(BOFFILE bf, int instructions_count)
{
    // Only have "Addr Instruction" if we have -p
    if (p_flag == 1)
    {
        printf("Addr Instruction\n");
    }

    // If we have our instr_flag = 1 that means we are allowed to print out the instructions
    if (instr_flag == 1)
    {
        bin_instr_t instruction = instruction_read(bf);
        printf(" %s\n", instruction_assembly_form(instruction));
    }
    else
    {
        for (int i = 0; i < instructions_count; i++)
        {
            bin_instr_t instruction = instruction_read(bf);
            if (p_flag == 1)
            {
                printf("%4d %s\n", i * BYTES_PER_WORD, instruction_assembly_form(instruction));
            }
        }
    }
}

// Helper function that reads in the data and returns 0 if there is no data within that value
// Used to determine if we need to print a 0 or the actual value in print_data_values
int read_and_check_data(word_type *data_values, int data_count, BOFFILE bf)
{
    int zero_data = 1;
    int i = 0;

    while (i < data_count)
    {
        data_values[i] = bof_read_word(bf);
        if (data_values[i] != 0)
        {
            zero_data = 0;
        }
        i++;
    }
    return zero_data;
}

// Used for printing out when we do -p
void print_data_values(word_type *data_values, int data_count, int data_start_address, int zero_data)
{
    // If there is no data, then print just 0 after
    if (zero_data)
    {
        printf("%8d: 0   ...\n", data_start_address);
    }
    // If there is data print the data that is inside of it
    else
    {
        for (int i = 0; i < data_count; i++)
        {
            printf("%8d: %d ", data_start_address + i * BYTES_PER_WORD, data_values[i]);
            if (i % 5 == 4)
            {
                printf("\n");
            }
        }
        printf("%8d: 0   ...\n", data_start_address + data_count * BYTES_PER_WORD);
    }
    if (p_flag == 0)
    {
        printf("%8d: 0   ...\n", srm_registers.GPR[30]);
    }
}

// Helper functions for the print_data_non_p
bool should_print_newline(int line_counter)
{
    return line_counter % 5 == 0;
}

bool is_stack_pointer_start(int register_index)
{
    const int stack_pointer_index = 28;
    return register_index == stack_pointer_index;
}

// Printing function based on the announcement about test case 6
// Used to print the memory locations at the end of the non -p
void print_data_non_p(int start_reg, int end_reg)
{
    int line_counter = 0;
    bool has_printed_dots = false;

    for (int address = srm_registers.GPR[start_reg]; address <= srm_registers.GPR[end_reg]; address += 4)
    {
        bool is_memory_word_non_zero = (memory.words[address] != 0);

        if (should_print_newline(line_counter))
        {
            printf("\n");
        }

        if (is_memory_word_non_zero)
        {
            printf("%8d: %-4d", address, memory.words[address]);
            line_counter++;
            has_printed_dots = false;
        }
        else if (!has_printed_dots)
        {
            printf("%8d: %-4d\t...", address, memory.words[address]);
            line_counter++;
            has_printed_dots = true;

            if (is_stack_pointer_start(start_reg))
            {
                break;
            }
        }
    }
}

// Processing the BOF file used for -p
void process_bof_file(const char *filename)
{
    BOFFILE bf = bof_read_open(filename);
    BOFHeader bh = bof_read_header(bf);
    print_instructions(bf, bh.text_length / BYTES_PER_WORD);

    int data_count = bh.data_length / BYTES_PER_WORD;
    word_type data_values[data_count];

    int zero_data = read_and_check_data(data_values, data_count, bf);

    print_data_values(data_values, data_count, bh.data_start_address, zero_data);

    bof_close(bf);
}

// Print Y if we have tracing involved
void tracing_print()
{
    if (!tracing && (trigger_flag == 1))
    {
        printf("Y");
        print_counter++;
    }
}

void execute_instruction(BOFFILE bf, BOFHeader bh, const char *tempfile, const char *tempfile2)
{

    bin_instr_t ins = memory.instrs[PC / 4];
    int rs, rt, rd, shift, func, op, code, immed;
    trigger_flag = 0;

    // Updating PC by bytes
    PC += 4;

    op = ins.reg.op;
    tracing_print();
    invariant_check();
    if (ins.reg.op == 0)
    { // R-type instructions
        rs = ins.reg.rs;
        rt = ins.reg.rt;
        rd = ins.reg.rd;
        shift = ins.reg.shift;
        func = ins.reg.func;
        switch (ins.reg.func)
        {
        case ADD_F:
            srm_registers.GPR[rd] = srm_registers.GPR[rs] + srm_registers.GPR[rt];
            print_counter++;
            break;
        case SUB_F:
            srm_registers.GPR[rd] = srm_registers.GPR[rs] - srm_registers.GPR[rt];
            print_counter++;
            break;
        case MUL_F:
        {
            uint64_t result = (uint64_t)srm_registers.GPR[rs] * (uint64_t)srm_registers.GPR[rt];
            srm_registers.LO = result & 0xFFFFFFFF;
            srm_registers.HI = result >> 32;
            print_counter++;
        }
        break;
        case DIV_F:
            if (srm_registers.GPR[rt] == 0)
            {
                fprintf(stderr, "Division by zero\n");
                exit(EXIT_FAILURE);
            }
            srm_registers.LO = srm_registers.GPR[rs] / srm_registers.GPR[rt];
            srm_registers.HI = srm_registers.GPR[rs] % srm_registers.GPR[rt];
            print_counter++;
            break;
        case MFHI_F:
            srm_registers.GPR[rd] = srm_registers.HI;
            print_counter++;
            break;
        case MFLO_F:
            srm_registers.GPR[rd] = srm_registers.LO;
            print_counter++;
            break;
        case AND_F:
            srm_registers.GPR[rd] = srm_registers.GPR[rs] & srm_registers.GPR[rt];
            print_counter++;
            break;
        case BOR_F:
            srm_registers.GPR[rd] = srm_registers.GPR[rs] | srm_registers.GPR[rt];
            print_counter++;
            break;
        case NOR_F:
            srm_registers.GPR[rd] = !(srm_registers.GPR[rs] | srm_registers.GPR[rt]);
            print_counter++;
            break;
        case XOR_F:
            srm_registers.GPR[rd] = srm_registers.GPR[rs] ^ srm_registers.GPR[rt];
            print_counter++;
            break;
        case SLL_F:
            srm_registers.GPR[rd] = srm_registers.GPR[rt] << shift;
            print_counter++;
            break;
        case SRL_F:
            srm_registers.GPR[rd] = srm_registers.GPR[rt] >> shift;
            print_counter++;
            break;
        case JR_F:
            PC = srm_registers.GPR[rs];
            print_counter++;
            break; // Do not update PC for jump register instruction
        case SYSCALL_F:
            op = ins.syscall.op;
            code = ins.syscall.code;
            func = ins.syscall.func;
            switch (code)
            {
            case 10: // EXIT/HALT
                tracing_print();
                if (LBU_flag == 1)
                {
                    printf("Y\n");
                }
                exit(0);
            case 4: // print str
                fprintf(stdout, "%p", &memory.words[srm_registers.GPR[A0]]);
                print_counter++;
                trigger_flag = 0;
                break;
            case 11: // print char
                srm_registers.GPR[V0] = fputc(srm_registers.GPR[A0], stdout);
                print_counter++;
                trigger_flag = 0;
                break;
            case 12: // read char
                print_counter++;
                getc(stdin);
                trigger_flag = 0;
            case 256:
                print_counter++;
                tracing = true;
                trigger_flag = 0;
                break;
            case 257:
                print_counter++;
                tracing = false;
                trigger_flag = 1;
                break;
            default:
                fprintf(stderr, "Unknown system call code: %u\n", op);
                exit(EXIT_FAILURE);
            }
            break;
        default:
            fprintf(stderr, "Unknown R-type instruction: %u\n", func);
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        op = ins.immed.op;
        rs = ins.immed.rs;
        rt = ins.immed.rt;
        immed = ins.immed.immed;
        switch (op)
        {
        case 9: // ADDI
            srm_registers.GPR[rt] =
            srm_registers.GPR[rs] + machine_types_sgnExt(immed);
            print_counter++;
            break;
        case 12: // ANDI
            srm_registers.GPR[rt] =
            srm_registers.GPR[rs] & machine_types_sgnExt(immed);
            print_counter++;
            break;
        case 13: // BORI
            srm_registers.GPR[rt] =
            srm_registers.GPR[rs] | machine_types_sgnExt(immed);
            print_counter++;
            break;
        case 14: // XORI
            srm_registers.GPR[rt] =
            srm_registers.GPR[rs] ^ machine_types_sgnExt(immed);
            print_counter++;
            break;
        case 4: // BEQ
            if (srm_registers.GPR[rs] == srm_registers.GPR[rt])
            {
                PC += machine_types_formOffset(immed);
            }
            print_counter++;
            break;
        case 1: // BGEZ
            if (srm_registers.GPR[rs] >= 0)
            {
                PC += machine_types_formOffset(immed);
                print_counter++;
            }
            break;
        case 7: // BGTZ
            if (srm_registers.GPR[rs] > 0)
            {
                PC += machine_types_formOffset(immed);
                print_counter++;
            }
            break;
        case 6: // BLEZ
            if (srm_registers.GPR[rs] <= 0)
            {
                PC += machine_types_formOffset(immed);
                print_counter++;
            }
            break;
        case 8: // BLTZ
            if (srm_registers.GPR[rs] < 0)
            {
                PC += machine_types_formOffset(immed);
                print_counter++;
            }
            break;
        case 5: // BNE
            if (srm_registers.GPR[rs] != srm_registers.GPR[rt])
            {
                PC += machine_types_formOffset(immed);
            }
            print_counter++;
            break;
        case 36: // LBU
            srm_registers.GPR[rt] = machine_types_zeroExt(memory.words[srm_registers.GPR[rs] + machine_types_formOffset(immed)]);
            LBU_flag = 1;
            print_counter++;
            break;
        case 35: // LW
            srm_registers.GPR[rt] = memory.words[srm_registers.GPR[rs] + machine_types_formOffset(immed)];
            print_counter++;
            break;
        case 40: // SB
            memory.words[srm_registers.GPR[rs] + machine_types_formOffset(immed)] = srm_registers.GPR[rt];
            print_counter++;
            break;
        case 43: // SW
            memory.words[srm_registers.GPR[rs] + machine_types_formOffset(immed)] = srm_registers.GPR[rt];
            print_counter++;
            break;
        case 2:                                                // JMP
            PC = machine_types_formAddress(PC, ins.jump.addr); // PC updated to jump address
            print_counter++;
            break;
        case 3: // JAL
            print_counter++;
            srm_registers.GPR[31] = PC;                        // return address saved at 31
            PC = machine_types_formAddress(PC, ins.jump.addr); // PC updated to jump address
            break;
        default:
            fprintf(stderr, "Unknown op code: %u\n", op);
            exit(EXIT_FAILURE);
        }
    }
}

// Check for certain invariants
void invariant_check()
{
    if (PC % BYTES_PER_WORD != 0)
    {
        exit(EXIT_FAILURE);
    }
    else if (srm_registers.GPR[GP_REG] % BYTES_PER_WORD != 0)
    {
        exit(EXIT_FAILURE);
    }
    else if (srm_registers.GPR[SP_REG] % BYTES_PER_WORD != 0)
    {
        exit(EXIT_FAILURE);
    }
    else if (srm_registers.GPR[FP_REG] % BYTES_PER_WORD != 0)
    {
        exit(EXIT_FAILURE);
    }
    else if (srm_registers.GPR[GP_REG] == 0)
    {
        exit(EXIT_FAILURE);
    }
    else if (srm_registers.GPR[GP_REG] >= srm_registers.GPR[SP])
    {
        exit(EXIT_FAILURE);
    }
    else if (srm_registers.GPR[FP_REG] >= MEMORY_SIZE_IN_BYTES) // pdf says MAX_STACK_HEIGHT, I imagine it is talking about the maximum memory allotted
    {
        exit(EXIT_FAILURE);
    }
    else if (PC <= 0)
    {
        exit(EXIT_FAILURE);
    }
    else if (PC >= MEMORY_SIZE_IN_BYTES && srm_registers.GPR[0] != 0)
    {
        exit(EXIT_FAILURE);
    }
}

// Check to see if we need to print the HI and LO, if not just print PC as usual
void hi_lo_check()
{
    if (srm_registers.LO > 0 || srm_registers.HI > 0)
    {
        printf("      PC: %d HI: %d       LO: %d\n", PC, srm_registers.HI, srm_registers.LO);
    }
    else
    {
        printf("      PC: %d\n", PC);
    }
}

// Printing the state of the VM normally (without -p)
void print_state(BOFFILE bf, BOFHeader header, int i, const char *tempfile, const char *tempfile2)
{
    int counter = 0;

    if (trigger_flag != 1)
    {
        hi_lo_check();

        for (int j = 0; j < 32; j++)
        {
            printf("GPR[%-3s]: %-6d\t", regname_get(j), srm_registers.GPR[j]);
            if ((j + 1) % 6 == 0) // To format the output as in the example
            {
                printf("\n");
            }
        }
        printf("\n");
        printf("\n");
    }

    // Temp header and file to read instructions without disrupting the other set
    BOFFILE temp = bof_read_open(tempfile);
    BOFHeader temp_header = bof_read_header(temp);

    print_instructions(temp, temp_header.text_length / BYTES_PER_WORD);

    if (trigger_flag != 1)
    {
        // Passing in the 28, 29, 30 represents the locations in memory we need to print
        // Using the non p function since they are implemented differently if -p is passed in
        print_data_non_p(28, 29);
        print_data_non_p(29, 30);
        printf("\n");
        printf("==> addr:%5d", PC);
        printf(" %s\n", instruction_assembly_form(memory.instrs[PC / 4]));
    }

    counter++;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: ./vm [-p] filename.bof\n");
        return 1;
    }
    const char *filename;
    const char *tempfile;
    const char *tempfile2;
    // Check if -p flag is provided
    if (strcmp(argv[1], "-p") == 0 && (argc > 2))
    {
        filename = argv[2];
        p_flag = 1;
        process_bof_file(filename);
        // read_and_printBOF(argv[2]);
    }
    else if (argc == 2)
    {
        filename = argv[1];
        tempfile = filename;
        tempfile2 = filename;
        p_flag = 0;

        BOFFILE bf = bof_read_open(filename);
        BOFHeader bh = bof_read_header(bf);

        // filename = argv[1];
        load_bof_file(&srm_registers, bf, bh);

        // First print the initial state
        tracing = true;
        print_state(bf, bh, print_counter, tempfile, tempfile2);

        // Using an infinite loop to execute the instructions in order to get exit to properly break out of the code
        while (1)
        {
            execute_instruction(bf, bh, tempfile, tempfile2);
            if (tracing == true)
            {
                print_state(bf, bh, print_counter, tempfile, tempfile2);
            }
        }
    }
    else
    {
        printf("Invalid arguments. Usage: %s [-p] <filename>\n", argv[0]);
        return 1;
    }
    return 0;
}