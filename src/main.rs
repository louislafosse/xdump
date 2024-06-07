use std::{
    fs::File,
    io::{
        self,
        Read,
        stdout,
        Write
    },
};

use goblin::{
    elf::Elf,
    pe::PE,
};

use iced_x86::{
    Decoder,
    DecoderOptions,
    Formatter,
    Instruction,
};

use crossterm::{
    cursor,
    event::{
        Event,
        KeyCode,
        KeyEvent, MouseEvent
    },
    execute,
    style::Stylize,
    terminal::{
        self,
        ClearType
    }
};

use clap::{
    Arg,
    Command
};

use chrono::{
    DateTime,
    TimeZone,
    Utc
};

static REGISTERS_X86: &[&str] = &[
    // General-purpose registers (64-bit, 32-bit, 16-bit, 8-bit)
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
    "al", "ah", "bl", "bh", "cl", "ch", "dl", "dh",

    // Special-purpose registers
    "rip", "rflags",
    
    // Segment registers
    "cs", "ss", "ds", "es", "fs", "gs",

    // x87 FPU registers
    "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",

    // MMX registers
    "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7",

    // SSE registers
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
    "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
    
    // AVX registers (YMM)
    "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7",
    "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15",

    // AVX-512 registers (ZMM)
    "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7",
    "zmm8", "zmm9", "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15",
    "zmm16", "zmm17", "zmm18", "zmm19", "zmm20", "zmm21", "zmm22", "zmm23",
    "zmm24", "zmm25", "zmm26", "zmm27", "zmm28", "zmm29", "zmm30", "zmm31",

    // Control registers
    "cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cr6", "cr7",
    "cr8", "cr9", "cr10", "cr11", "cr12", "cr13", "cr14", "cr15",

    // Debug registers
    "dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7",
    "dr8", "dr9", "dr10", "dr11", "dr12", "dr13", "dr14", "dr15",

    // Test registers (obsolete in modern x86 processors, but included for completeness)
    "tr0", "tr1", "tr2", "tr3", "tr4", "tr5", "tr6", "tr7",

    // System registers
    "gdtr", "ldtr", "idtr", "tr",
    
    // Floating Point Unit (FPU) control/status/tag registers
    "fctrl", "fstat", "ftag", "fiseg", "fioff", "foseg", "fooff", "fop",
    
    // MXCSR control/status register
    "mxcsr",

    // Extended control registers
    "xcr0", "xcr1", "xcr2", "xcr3", "xcr4", "xcr5", "xcr6", "xcr7",
    "xcr8", "xcr9", "xcr10", "xcr11", "xcr12", "xcr13", "xcr14", "xcr15",

    // Model-specific registers (MSRs, numerous and architecture-dependent, examples)
    "msr_efer", "msr_star", "msr_lstar", "msr_cstar", "msr_sfmask",
    
    // Extended feature registers (for new instructions sets and features)
    "k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7",
];

trait FormatterTrait {
    fn format_instruction(&mut self, instruction: &Instruction, output: &mut String);
}

impl FormatterTrait for iced_x86::IntelFormatter {
    fn format_instruction(&mut self, instruction: &Instruction, output: &mut String) {
        self.format(instruction, output);
    }
}

impl FormatterTrait for iced_x86::MasmFormatter {
    fn format_instruction(&mut self, instruction: &Instruction, output: &mut String) {
        self.format(instruction, output);
    }
}

impl FormatterTrait for iced_x86::NasmFormatter {
    fn format_instruction(&mut self, instruction: &Instruction, output: &mut String) {
        self.format(instruction, output);
    }
}

impl FormatterTrait for iced_x86::FastFormatter {
    fn format_instruction(&mut self, instruction: &Instruction, output: &mut String) {
        self.format(instruction, output);
    }
}

impl FormatterTrait for iced_x86::GasFormatter {
    fn format_instruction(&mut self, instruction: &Instruction, output: &mut String) {
        self.format(instruction, output);
    }
}

enum BinaryType<'a> {
    PE(PE<'a>),
    ELF(Elf<'a>),
}

fn parse_binary(buffer: &[u8]) -> Result<BinaryType, &'static str> {
    if let Ok(pe) = PE::parse(buffer) {
        return Ok(BinaryType::PE(pe));
    }

    if let Ok(elf) = Elf::parse(buffer) {
        return Ok(BinaryType::ELF(elf));
    }

    Err("Failed to parse binary")
}


fn color_registers(operands: &str) -> String {
    let mut result = String::new();
    let registers_set: std::collections::HashSet<&str> = REGISTERS_X86.iter().copied().collect();
    let re = regex::RegexBuilder::new(r"(?-u)\b[a-zA-Z0-9]+\b")
        .unicode(false)
        .dfa_size_limit(100 * (1 << 20))
        .build()
        .unwrap();

    for word in re.find_iter(operands) {
        let part = word.as_str();
        if registers_set.contains(part) {
            result.push_str(&part.red().to_string());
        }
        else {
            result.push_str(&part.on_black().white().to_string());
        }
        result.push(' ');
    }

    result.trim_end().to_string()
}

fn print_elf_header_info(progname: &str, elf: &Elf, output: &mut String) {
    output.push_str(&format!("{} :\n", format!("{}", progname)).bold().underlined().green().slow_blink().to_string());
    output.push_str(&format!("{}: {}\n", "Magic".cyan(), elf.header.e_ident.iter().map(|&b| format!("{:02X}", b)).collect::<Vec<String>>().join(" ")).black().to_string());
    output.push_str(&format!("{}: {} | {}\n", "Class".cyan(), match elf.header.e_ident[4] {
        goblin::elf::header::ELFCLASS64 => "ELF64".yellow(),
        goblin::elf::header::ELFCLASS32 => "ELF32".yellow(),
        _ => "Unknown".red(),
    }, match elf.header.e_ident[5] {
        goblin::elf::header::ELFDATA2LSB => "Little Endian".yellow(),
        goblin::elf::header::ELFDATA2MSB => "Big Endian".yellow(),
        _ => "Unknown".red(),
    }));
    output.push_str(&format!("{}: 0x{:x} {}: 0x{:x} {}: 0x{:x}\n", "Version".cyan(), elf.header.e_ident[6], "OS/ABI".cyan(), elf.header.e_ident[7], "ABI Version".cyan(), elf.header.e_ident[8]));
    output.push_str(&format!("{}: 0x{:x}\n", "Type".cyan(), elf.header.e_type));
    output.push_str(&format!("{}: 0x{:x}\n", "Machine".cyan(), elf.header.e_machine));
    output.push_str(&format!("{}: 0x{:x}\n", "Version".cyan(), elf.header.e_version));
    output.push_str(&format!("{}: 0x{:x}\n", "Entry point address".cyan(), elf.header.e_entry));
    output.push_str(&format!("{}: 0x{:x}\n", "Start of program headers".cyan(), elf.header.e_phoff));
    output.push_str(&format!("{}: 0x{:x}\n", "Start of section headers".cyan(), elf.header.e_shoff));
    output.push_str(&format!("{}: 0x{:x}\n", "Flags".cyan(), elf.header.e_flags));
    output.push_str(&format!("{}: {}\n", "Size of this header".cyan(), elf.header.e_ehsize));
    output.push_str(&format!("{}: {}\n", "Size of program headers".cyan(), elf.header.e_phentsize));
    output.push_str(&format!("{}: {}\n", "Number of program headers".cyan(), elf.header.e_phnum));
    output.push_str(&format!("{}: {}\n", "Size of section headers".cyan(), elf.header.e_shentsize));
    output.push_str(&format!("{}: {}\n", "Number of section headers".cyan(), elf.header.e_shnum));
    output.push_str(&format!("{}: {}\n", "Section header string table index".cyan(), elf.header.e_shstrndx));
}

fn print_pe_header_info(progname: &str, pe: &goblin::pe::PE, output: &mut String) {
    output.push_str(&format!("{} :\n", format!("{}", progname).bold().underlined().green().slow_blink().to_string()));

    // COFF Header
    output.push_str(&format!("{}: 0x{:x}\n", "Machine".cyan(), pe.header.coff_header.machine));
    output.push_str(&format!("{}: {}\n", "Number of sections".cyan(), pe.header.coff_header.number_of_sections));

    let naive_datetime = DateTime::<Utc>::from_timestamp(pe.header.coff_header.time_date_stamp as i64, 0)
        .expect("Invalid timestamp")
        .naive_utc();
    let datetime = Utc.from_utc_datetime(&naive_datetime);

    output.push_str(&format!("{}: {}\n", "Time date stamp".cyan(), datetime.to_rfc2822()));
    output.push_str(&format!("{}: {}\n", "Pointer to symbol table".cyan(), pe.header.coff_header.pointer_to_symbol_table));
    output.push_str(&format!("{}: {}\n", "Number of symbols".cyan(), pe.header.coff_header.number_of_symbol_table));
    output.push_str(&format!("{}: {}\n", "Size of optional header".cyan(), pe.header.coff_header.size_of_optional_header));
    output.push_str(&format!("{}: {}\n", "Characteristics".cyan(), pe.header.coff_header.characteristics));

    // Optional Header
    let opt_header = &pe.header.optional_header.unwrap();
    output.push_str(&format!("{}: 0x{:x}\n", "Magic".cyan(), opt_header.standard_fields.magic));
    output.push_str(&format!("{}: {}\n", "Linker version".cyan(), format!("{}.{}", opt_header.standard_fields.major_linker_version, opt_header.standard_fields.minor_linker_version)));
    output.push_str(&format!("{}: {}\n", "Size of code".cyan(), opt_header.standard_fields.size_of_code));
    output.push_str(&format!("{}: {}\n", "Size of initialized data".cyan(), opt_header.standard_fields.size_of_initialized_data));
    output.push_str(&format!("{}: {}\n", "Size of uninitialized data".cyan(), opt_header.standard_fields.size_of_uninitialized_data));
    output.push_str(&format!("{}: 0x{:x}\n", "Address of entry point".cyan(), opt_header.standard_fields.address_of_entry_point));
    output.push_str(&format!("{}: 0x{:x}\n", "Base of code".cyan(), opt_header.standard_fields.base_of_code));

    if opt_header.standard_fields.magic == goblin::pe::optional_header::IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        output.push_str(&format!("{}: 0x{:x}\n", "Image base".cyan(), opt_header.windows_fields.image_base));
    } else {
        output.push_str(&format!("{}: 0x{:x}\n", "Image base".cyan(), opt_header.windows_fields.image_base as u32));
        output.push_str(&format!("{}: 0x{:x}\n", "Base of data".cyan(), opt_header.standard_fields.base_of_data));
    }

    output.push_str(&format!("{}: {}\n", "Section alignment".cyan(), opt_header.windows_fields.section_alignment));
    output.push_str(&format!("{}: {}\n", "File alignment".cyan(), opt_header.windows_fields.file_alignment));
    output.push_str(&format!("{}: {}\n", "Operating system version".cyan(), format!("{}.{}", opt_header.windows_fields.major_operating_system_version, opt_header.windows_fields.minor_operating_system_version)));
    output.push_str(&format!("{}: {}\n", "Image version".cyan(), format!("{}.{}", opt_header.windows_fields.major_image_version, opt_header.windows_fields.minor_image_version)));
    output.push_str(&format!("{}: {}\n", "Subsystem version".cyan(), format!("{}.{}", opt_header.windows_fields.major_subsystem_version, opt_header.windows_fields.minor_subsystem_version)));
    output.push_str(&format!("{}: 0x{:x}\n", "Win32 version value".cyan(), opt_header.windows_fields.win32_version_value));
    output.push_str(&format!("{}: {}\n", "Size of image".cyan(), opt_header.windows_fields.size_of_image));
    output.push_str(&format!("{}: {}\n", "Size of headers".cyan(), opt_header.windows_fields.size_of_headers));
    output.push_str(&format!("{}: 0x{:x}\n", "Checksum".cyan(), opt_header.windows_fields.check_sum));
    output.push_str(&format!("{}: {}\n", "Subsystem".cyan(), opt_header.windows_fields.subsystem));
    output.push_str(&format!("{}: {}\n", "DLL characteristics".cyan(), opt_header.windows_fields.dll_characteristics));
    output.push_str(&format!("{}: {}\n", "Size of stack reserve".cyan(), opt_header.windows_fields.size_of_stack_reserve));
    output.push_str(&format!("{}: {}\n", "Size of stack commit".cyan(), opt_header.windows_fields.size_of_stack_commit));
    output.push_str(&format!("{}: {}\n", "Size of heap reserve".cyan(), opt_header.windows_fields.size_of_heap_reserve));
    output.push_str(&format!("{}: {}\n", "Size of heap commit".cyan(), opt_header.windows_fields.size_of_heap_commit));
    output.push_str(&format!("{}: 0x{:x}\n", "Loader flags".cyan(), opt_header.windows_fields.loader_flags));
    output.push_str(&format!("{}: {}\n", "Number of Rva and Sizes".cyan(), opt_header.windows_fields.number_of_rva_and_sizes));
}

fn write_screen<W: Write>(buffer: &Vec<&str>, screen: &mut W, scroll: usize, height: u16) {
    execute!(screen, terminal::Clear(ClearType::All), cursor::MoveTo(0, 0)).unwrap();

    let lines_to_display = (height as usize).min(buffer.len());
    let content_height = lines_to_display - 2; // Reserve space for the prompt
    let vertical_offset = (height as usize - content_height) / 2;

    for (i, line) in buffer.iter().skip(scroll).take(content_height).enumerate() {
        execute!(screen, cursor::MoveTo(0, (i + vertical_offset) as u16)).unwrap();
        writeln!(screen, "{}", line).unwrap();
    }

    execute!(
        screen,
        cursor::MoveTo(0, height - 1)
    )
    .unwrap();
    write!(screen, "{}", format!("{}", "Press 'Q' to exit.".bold().negative().on_white().black())).unwrap();
}

fn display_tui(out_buffer: &str) {
    let mut stdout = stdout();
    
    execute!(stdout, terminal::EnterAlternateScreen, cursor::Show, cursor::SetCursorStyle::BlinkingBlock).unwrap();
    terminal::enable_raw_mode().unwrap();

    let mut scroll = 0;
    let vecbuff: Vec<&str> = out_buffer.split("\n").collect();
    let height = terminal::size().unwrap().1;
    
    write_screen(&vecbuff, &mut stdout, scroll, height);
    loop {
        stdout.flush().unwrap();
    
        let height = terminal::size().unwrap().1;
    
        let event = crossterm::event::read().unwrap();
    
        if let Event::Key(KeyEvent { code, .. }) = &event {
            match code {
                KeyCode::Char('q') => break,
                KeyCode::Up => {
                    if scroll > 0 {
                        scroll -= 1;
                        write_screen(&vecbuff, &mut stdout, scroll, height);
                    }
                }
                KeyCode::Down => {
                    if scroll < vecbuff.len().saturating_sub((height as usize) - 2) {
                        scroll += 1;
                        write_screen(&vecbuff, &mut stdout, scroll, height);
                    }
                }
                _ => {}
            }
        }
    
        if let Event::Mouse(MouseEvent { kind, .. }) = &event {
            match kind {
                crossterm::event::MouseEventKind::ScrollUp => {
                    if scroll > 0 {
                        scroll -= 1;
                        write_screen(&vecbuff, &mut stdout, scroll, height);
                    }
                }
                crossterm::event::MouseEventKind::ScrollDown => {
                    if scroll < vecbuff.len().saturating_sub((height as usize) - 2) {
                        scroll += 1;
                        write_screen(&vecbuff, &mut stdout, scroll, height);
                    }
                }
                _ => {}
            }
        }
    
        stdout.flush().unwrap();
    }

    execute!(stdout, cursor::Show, terminal::LeaveAlternateScreen).unwrap();
    terminal::disable_raw_mode().unwrap();
}

fn calc_len_instructions(
    arch: u32,
    section_data: &[u8],
    section_rip: u64,
    max_bytes_width: &mut usize,
    max_instr_width: &mut usize,
    output: &mut String,
    formatter: &mut Box<dyn FormatterTrait>,
    instruction: &mut Instruction,
) {
    let mut decoder = Decoder::with_ip(arch, section_data, section_rip, DecoderOptions::NONE);

    while decoder.can_decode() {
        decoder.decode_out(instruction);

        let start_index = (instruction.ip() - section_rip) as usize;
        let instr_bytes = &section_data[start_index..start_index + instruction.len()];

        if instr_bytes.len() > *max_bytes_width {
            *max_bytes_width = instr_bytes.len();
        }
        output.clear();
        formatter.format_instruction(&instruction, output);
        if output.len() > *max_instr_width {
            *max_instr_width = output.len();
        }
    }
}

fn decode_instructions(
    arch: u32,
    section_data: &[u8],
    section_rip: u64,
    max_bytes_width: usize,
    max_instr_width: usize,
    out_buffer: &mut String,
    formatter: &mut Box<dyn FormatterTrait>,
    instruction : &mut Instruction
) {
    let mut decoder = Decoder::with_ip(arch, section_data, section_rip, DecoderOptions::NONE);

    while decoder.can_decode() {
        decoder.decode_out(instruction);

        let mut output = String::new();
        formatter.format_instruction(&instruction, &mut output);

        // Print the instruction pointer
        out_buffer.push_str(&format!("{}", format!("{:0width$x} ", instruction.ip(), width = 4)).blue().to_string());

        // Print the instruction bytes
        let start_index = (instruction.ip() - section_rip) as usize;
        let instr_bytes = &section_data[start_index..start_index + instruction.len()];

        let mnemonic = output.split_whitespace().next().unwrap_or("");
        let mnemonic_len = mnemonic.len();
        let mut byte_idx = 0;

        for (_, b) in instr_bytes.iter().enumerate() {
            if byte_idx < mnemonic_len {
                out_buffer.push_str(&format!("{}", format!("{:02x} ", b)).yellow().to_string());
            } else {
                out_buffer.push_str(&format!("{}", format!("{:02x} ", b)).magenta().to_string());
            }
            byte_idx += 1;
        }

        // Pad the instruction bytes column
        let bytes_padding = max_bytes_width - instr_bytes.len();
        for _ in 0..bytes_padding {
            out_buffer.push_str(&format!("   ")); // 2 hex digits + 1 space
        }

        // Split the formatted instruction into mnemonic and operands
        let parts: Vec<&str> = output.splitn(2, ' ').collect();

        if parts.len() == 2 {
            // Color the mnemonic
            out_buffer.push_str(&format!("{} {}", parts[0].yellow(), color_registers(parts[1])));
        } else if parts.len() == 1 && parts[0] == "(bad)" {
            // If the instruction is invalid, print it in red
            out_buffer.push_str(&format!("{}", output.clone().black().crossed_out()));
        } else if parts.len() == 1 && parts[0] == "syscall" {
            // If the instruction is a syscall, print it in green
            out_buffer.push_str(&format!("{}", output.clone().red()));
        } else {
            // If the instruction could not be split (rare), print it all in one color
            out_buffer.push_str(&format!("{}", output.clone().yellow()));
        }

        // Pad the instruction text column if needed
        let instr_padding = max_instr_width - output.len();
        for _ in 0..instr_padding {
            out_buffer.push_str(&format!(" "));
        }

        out_buffer.push_str(&format!("\n"));
    }
}

fn main() -> io::Result<()> {
    let matches = Command::new("example")
        .version("1.0")
        .about("Parses command-line arguments")
        .arg(
            Arg::new("formatter")
                .short('f')
                .long("formatter")
                .help("\"intel\" | \"masm\" | \"nasm\" | \"gas\" | \"fast\""),
        )
        .arg(
            Arg::new("filename")
                .required(true)
                .help("Specifies the filename"),
        )
        .get_matches();

    let filename = matches.get_one::<String>("filename").expect("Failed to get filename");
    let mut buffer = Vec::new();

    File::open(filename)
        .expect("Failed to open file")
        .read_to_end(&mut buffer)
        .expect("Failed to read file");

    let formatter_arg = match matches.get_one::<String>("formatter") {
        Some(formatter) => formatter,
        None => &std::string::String::from("intel")
    };

    let res_formatter: Result<Box<dyn FormatterTrait>, &'static str> = match formatter_arg.as_str() {
        "intel" => Ok(Box::new(iced_x86::IntelFormatter::new())),
        "masm" => Ok(Box::new(iced_x86::MasmFormatter::new())),
        "nasm" => Ok(Box::new(iced_x86::NasmFormatter::new())),
        "fast" => Ok(Box::new(iced_x86::FastFormatter::new())),
        "gas" => Ok(Box::new(iced_x86::GasFormatter::new())),
        _ => Err("Unsupported formatter"),
    };

    if res_formatter.is_err() {
        eprintln!("{}", res_formatter.err().unwrap());
        return Ok(());
    }

    let mut formatter = res_formatter.unwrap();
    let mut output = String::new();
    let mut instruction = Instruction::default();

    // Variables to store the maximum widths
    let mut max_bytes_width = 0;
    let mut max_instr_width = 0;
    let mut out_buffer = String::new();
    
    let binary = parse_binary(&buffer).expect("Failed to parse binary");

    match &binary {
        BinaryType::PE(ref pe) => print_pe_header_info(filename, pe, &mut out_buffer),
        BinaryType::ELF(ref elf) => print_elf_header_info(filename, elf, &mut out_buffer)
    }
    
    let arch = match &binary {
        BinaryType::ELF(ref elf) => match elf.header.e_ident[4] {
            goblin::elf::header::ELFCLASS64 => 64,
            goblin::elf::header::ELFCLASS32 => 32,
            _ => panic!("Unsupported ELF class"),
        },
        BinaryType::PE(ref pe) => match pe.header.coff_header.machine {
            goblin::pe::header::COFF_MACHINE_X86 => 32,
            goblin::pe::header::COFF_MACHINE_X86_64 => 64,
            _ => panic!("Unsupported PE machine"),
        } 
    };

    // First pass to calculate the maximum widths across all sections
    match &binary {
        BinaryType::PE(ref pe) => {
            for section in &pe.sections {
                // if section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0 {
                let section_offset = section.pointer_to_raw_data as usize;
                let section_size = section.size_of_raw_data as usize;
                let section_rip = section.virtual_address as u64;

                if section_offset + section_size <= buffer.len() {
                    calc_len_instructions(
                        arch,
                        &buffer[section_offset..section_offset + section_size],
                        section_rip,
                        &mut max_bytes_width,
                        &mut max_instr_width,
                        &mut output,
                        &mut formatter,
                        &mut instruction
                    );
                } else {
                    eprintln!("Skipped section '{}': offset {} + size {} > buffer length {}",
                        std::str::from_utf8(&section.name).unwrap_or_default(),
                        section_offset,
                        section_size,
                        buffer.len()
                    );
                }
                // }
            }
        },
        BinaryType::ELF(ref elf) => {
            for section in &elf.section_headers {
                // if section.sh_type == goblin::elf::section_header::SHT_PROGBITS && section.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64 != 0 {

                let section_offset = section.sh_offset as usize;
                let section_size = section.sh_size as usize;
                let section_rip = section.sh_addr;

                if section_offset + section_size <= buffer.len() {
                    calc_len_instructions(
                        arch,
                        &buffer[section_offset..section_offset + section_size],
                        section_rip,
                        &mut max_bytes_width,
                        &mut max_instr_width,
                        &mut output,
                        &mut formatter,
                        &mut instruction
                    );
                } else {
                    eprintln!("Skipped section '{}': offset {} + size {} > buffer length {}",
                        elf.shdr_strtab.get_at(section.sh_name).unwrap_or("unknown"),
                        section_offset, section_size, buffer.len()
                    );
                }
                // }
            }
        }
    }

    // Second pass to print the formatted instructions with section names
    match &binary {
        BinaryType::PE(ref pe) => {
            for section in &pe.sections {
                // if section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0 {
                let section_offset = section.pointer_to_raw_data as usize;
                let section_size = section.size_of_raw_data as usize;

                if section_offset + section_size <= buffer.len() {
                    let section_data = &buffer[section_offset..section_offset + section_size];
                    let section_rip = section.virtual_address as u64;

                    out_buffer.push_str(&format!("\n{}",
                        format!(
                            "{:0width$x} <{}>:\n",
                            section_rip,
                            std::str::from_utf8(&section.name).unwrap_or_default(),
                            width = if arch == 64 { 16 } else { 8 }
                        ).green()
                    ));

                    decode_instructions(
                        arch,
                        section_data,
                        section_rip,
                        max_bytes_width,
                        max_instr_width,
                        &mut out_buffer,
                        &mut formatter,
                        &mut instruction
                    );
                }
                // }
            }
        },
        BinaryType::ELF(ref elf) => {
            for section in &elf.section_headers {
                // if section.sh_type == goblin::elf::section_header::SHT_PROGBITS && section.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64 != 0 {
                let section_offset = section.sh_offset as usize;
                let section_size = section.sh_size as usize;
                let section_rip = section.sh_addr;
                let section_name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("unknown");

                if section_name.is_empty() {
                    out_buffer.push_str(&format!("\n{}",
                    format!(
                        "{:0width$x} <unknown>:\n",
                        section_rip,
                        width = if arch == 64 { 16 } else { 8 }
                    ).black().crossed_out()));
                } else {
                    out_buffer.push_str(&format!(
                        "\n{}",
                        format!(
                            "{:0width$x} <{}>:\n",
                            section_rip,
                            section_name,
                            width = if arch == 64 { 16 } else { 8 }
                        ).green()
                    ));
                }

                if section_offset + section_size <= buffer.len() {

                    let section_data = &buffer[section_offset..section_offset + section_size];
                    let section_rip = section.sh_addr;

                    decode_instructions(
                        arch,
                        section_data,
                        section_rip,
                        max_bytes_width,
                        max_instr_width,
                        &mut out_buffer,
                        &mut formatter,
                        &mut instruction
                    );
                }
                // }
            }
        }
    }

    display_tui(&out_buffer);
    Ok(())
}
