import sys
import struct
import getopt

verbose = False
def set_defaults(architecture):
    '''
    Sets the defaults according to architecture
    '''
    global DEFAULT_KERNEL_TEXT_START, ULONG_SIZE, ULONG_PATTERN, LABEL_ALIGN, U16_SIZE, U16_PATTERN, STEXT_TEXT_OFFSET
    if architecture == "64":
        #The default address at which the kernel text segment is loaded
        DEFAULT_KERNEL_TEXT_START = 0xffffffc000080000
        
        #The size of a ulong in the relevant architecture
        ULONG_SIZE = struct.calcsize("Q")
        ULONG_PATTERN = "<Q"
        
        #The alignment of labels in the resulting kernel file, I have no idea why it's 0x100
        LABEL_ALIGN = 0x100
        
        #The addreess difference of _text and stext in the kernel, it was 0x40 on my 64bit kernels
        STEXT_TEXT_OFFSET = 0x40
    else:
        #The default address at which the kernel text segment is loaded
        DEFAULT_KERNEL_TEXT_START = 0xC0008000
        
        #The size of a ulong in the relevant architecture
        ULONG_SIZE = struct.calcsize("I")
        ULONG_PATTERN = "<I"
        
        #The alignment of labels in the resulting kernel file
        LABEL_ALIGN = ULONG_SIZE * 4
        
        #The addreess difference of _text and stext in the kernel, it was 0x00 on my 32bit kernels
        STEXT_TEXT_OFFSET = 0x00

    U16_SIZE = struct.calcsize("H")
    U16_PATTERN = "<H"

def get_start_pattern(kernel_text_start):
    '''
    Builds the pattern for searching the kallsyms table
    '''
    return struct.pack(ULONG_PATTERN, kernel_text_start) + struct.pack(ULONG_PATTERN, kernel_text_start + STEXT_TEXT_OFFSET)

def read_ulong(kernel_data, offset):
    '''
    Reads an unsigned long (platform specific) from the given offset within the kernel data
    '''
    return struct.unpack(ULONG_PATTERN, kernel_data[offset : offset + ULONG_SIZE])[0]

def read_word(kernel_data, offset):
    '''
    Reads a WORD from the given offset within the kernel data
    '''
    return struct.unpack(U16_PATTERN, kernel_data[offset : offset + U16_SIZE])[0]

def read_byte(kernel_data, offset):
    '''
    Reads an unsigned byte from the given offset within the kernel data
    '''
    return struct.unpack("<B", kernel_data[offset : offset + 1])[0]

def read_c_string(kernel_data, offset):
    '''
    Reads a NUL-delimited C-string from the given offset
    '''
    current_offset = offset
    result_str = ""
    while kernel_data[current_offset] != '\x00':
        result_str += kernel_data[current_offset]
        current_offset += 1
    return result_str

def label_align_next(address):
    '''
    Aligns the given value to the closest label output boundry
    '''
    return (address + LABEL_ALIGN) & ~(LABEL_ALIGN-1)

def find_kallsyms_addresses(kernel_data, kernel_text_start):
    '''
    Searching for the beginning of the kernel's symbol table
    Returns the offset of the kernel's symbol table, or -1 if the symbol table could not be found
    '''
    search_str = get_start_pattern(kernel_text_start)
    return kernel_data.find(search_str)

def get_kernel_symbol_table(kernel_data, kernel_text_start):    
    '''
    Retrieves the kernel's symbol table from the given kernel file
    '''

    #Getting the beginning and end of the kallsyms_addresses table
    kallsyms_addresses_off = find_kallsyms_addresses(kernel_data, kernel_text_start)
    kallsyms_addresses_end_off = kernel_data.find(struct.pack(ULONG_PATTERN, 0), kallsyms_addresses_off)
    num_symbols = (kallsyms_addresses_end_off - kallsyms_addresses_off) / ULONG_SIZE
    if verbose: print "Number of symbols: %d" % num_symbols
    if verbose: print "Symbol table start offset: %x" % kallsyms_addresses_off
    if verbose: print "Symbol table end offset: %x" % kallsyms_addresses_end_off
    
    #Making sure that kallsyms_num_syms matches the table size
    kallsyms_num_syms_off = label_align_next(kallsyms_addresses_end_off)
    kallsyms_num_syms = read_ulong(kernel_data, kallsyms_num_syms_off)
    if kallsyms_num_syms != num_symbols:
        print "[-] Actual symbol table size: %d, read symbol table size: %d" % (num_symbols, kallsyms_num_syms)
        return None    

    #Calculating the location of the markers table
    kallsyms_names_off = label_align_next(kallsyms_num_syms_off)
    current_offset = kallsyms_names_off
    for i in range(0, num_symbols):
        current_offset += read_byte(kernel_data, current_offset) + 1
    kallsyms_markers_off = label_align_next(current_offset)
    if verbose: print "Symbol table names offset: %x" % kallsyms_names_off
    if verbose: print "Symbol table markers offset: %x" % kallsyms_markers_off
    
    #Reading the token table
    kallsyms_token_table_off = label_align_next(kallsyms_markers_off + (((num_symbols) >> 8) * ULONG_SIZE))
    current_offset = kallsyms_token_table_off
    for i in range(0, 256):
        token_str = read_c_string(kernel_data, current_offset)
        current_offset += len(token_str) + 1
    kallsyms_token_index_off = label_align_next(current_offset)
    if verbose: print "Symbol table tokens offset: %x" % kallsyms_token_table_off
    
    #Creating the token table
    token_table = []
    for i in range(0, 256):
        index = read_word(kernel_data, kallsyms_token_index_off + i * U16_SIZE)
        token_table.append(read_c_string(kernel_data, kallsyms_token_table_off + index))

    #Decompressing the symbol table using the token table
    offset = kallsyms_names_off
    symbol_table = []
    for i in range(0, num_symbols):
        num_tokens = read_byte(kernel_data, offset)
        offset += 1
        symbol_name = ""
        for j in range(num_tokens, 0, -1):
            token_table_idx = read_byte(kernel_data, offset)
            symbol_name += token_table[token_table_idx]
            offset += 1

        symbol_address = read_ulong(kernel_data, kallsyms_addresses_off + i * ULONG_SIZE)
        symbol_table.append((symbol_address, symbol_name[0], symbol_name[1:]))
        
    return symbol_table

def usage():
    print "Usage: python static_kallsyms.py [-a <architecture (64/32)>] [-b <kernel_base_address>] [-v] kernel_file"

def main():
    global verbose
    architecture = None
    kernel_text_start = None
    #Verifying the arguments
    try:
        opts, args = getopt.getopt(sys.argv[1:], "a:b:v")
    except getopt.GetoptError as err:
        # print help information and exit:
        print str(err)  # will print something like "option -a not recognized"
        usage()
        sys.exit(2)
    for o, a in opts:
        if o == "-b":
            kernel_text_start = int(a, 16)
        elif o == "-a":
            assert a in ["32", "64"], "Architecture must be either 32 or 64"
            architecture = a
        elif o == "-v":
            verbose = True
        else:
            assert False, "unhandled option"
    if len(args) != 1:
        usage()
        return
    
    kernel_data = open(args[0], "rb").read()
    set_defaults(architecture)
    if kernel_text_start == None:
        kernel_text_start = DEFAULT_KERNEL_TEXT_START
        
    #Getting the kernel symbol table
    symbol_table = get_kernel_symbol_table(kernel_data, kernel_text_start)
    for symbol in symbol_table:
        print "%08x %s %s" % symbol
    

if __name__ == "__main__":
    main()
