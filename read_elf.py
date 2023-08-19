# Writing a ELF parser from scratch, because why not?

ELF_FIELDS = []

ELF_32 = [
    16,  # e_ident
    2,  # e_type
    2,  # e_machine
    4,  # e_version
    4,  # e_entry *
    4,  # e_phoff *
    4,  # e_shoff *
    4,  # e_flags
    2,  # e_ehsize
    2,  # e_phentsize
    2,  # e_phnum
    2,  # e_shentsize
    2,  # e_shnum
    2,  # e_shstrndx
]

ELF_64 = [
    16,  # e_ident
    2,  # e_type
    2,  # e_machine
    4,  # e_version
    8,  # e_entry *
    8,  # e_phoff *
    8,  # e_shoff *
    4,  # e_flags
    2,  # e_ehsize
    2,  # e_phentsize
    2,  # e_phnum
    2,  # e_shentsize
    2,  # e_shnum
    2,  # e_shstrndx
]

FIELDS = {
    "e_ident": 0,
    "e_type": 1,
    "e_machine": 2,
    "e_version": 3,
    "e_entry": 4,
    "e_phoff": 5,
    "e_shoff": 6,
    "e_flags": 7,
    "e_ehsize": 8,
    "e_phentsize": 9,
    "e_phnum": 10,
    "e_shentsize": 11,
    "e_shnum": 12,
    "e_shstrndx": 13,
}

ELF_BITS = 32


def read_bytes(haystack, start, end):
    bytes_read = haystack[start:end]
    if len(bytes_read) > 0:
        while bytes_read[-1] == b"\x00":
            del bytes_read[-1]
    return bytes_read


def read_bytes_as_int(haystack, start, end, byteOrder="little"):
    return int.from_bytes(read_bytes(haystack, start, end), byteorder=byteOrder)


def read_bytes_as_str(haystack, start, end, byteOrder="little") -> str:
    nstr = ""
    for b in read_bytes(haystack, start, end):
        nstr += chr(b)
    return nstr


def get_field_offset(field_name: str) -> int:
    offset = 0
    for i in ELF_FIELDS[: FIELDS[field_name]]:
        offset += i
    return offset


def read_field(haystack, field_name: str) -> int:
    field_off = get_field_offset(field_name)
    field_size = ELF_FIELDS[FIELDS[field_name]]
    return read_bytes_as_int(haystack, field_off, field_off + field_size)


class ELFIdent:
    elf_bits = None
    elf_endianess = None


def read_ident(haystack) -> ELFIdent:
    elfIdent = ELFIdent()
    ei_class = read_bytes_as_int(haystack, 4, 5, "little")
    ei_data = read_bytes_as_int(haystack, 5, 6, "little")

    if ei_class == 1:
        elfIdent.elf_bits = 32
    elif ei_class == 2:
        elfIdent.elf_bits = 64
    else:
        elfIdent.elf_bits = 0

    if ei_data == 1:
        elfIdent.elf_endianess = "little"
    elif ei_data == 2:
        elfIdent.elf_endianess = "big"
    else:
        elfIdent.elf_endianess = "none"

    return elfIdent


SH_ENTRY = []
SH_ENTRY_32 = [
    4,  # sh_name
    4,  # sh_type
    4,  # sh_flags
    4,  # sh_addr
    4,  # sh_offset
    4,  # sh_size
    4,  # sh_link
    4,  # sh_info
    4,  # sh_addralign
    4,  # sh_entsize
]
SH_ENTRY_64 = [
    4,  # sh_name
    4,  # sh_type
    8,  # sh_flags
    8,  # sh_addr
    8,  # sh_offset
    8,  # sh_size
    4,  # sh_link
    4,  # sh_info
    8,  # sh_addralign
    8,  # sh_entsize
]


class ShTableNav:
    startIndex = 0
    uint32_t = 4
    uint64_t = 8
    sh_entry_size = -1

    def __init__(self, start, sh_entry_size):
        self.startIndex = start
        self.sh_entry_size = sh_entry_size

    def currentPOS(self):
        return self.startIndex

    def nextUINT32(self):
        self.startIndex = self.startIndex + self.uint32_t
        return self.startIndex

    def nextUINT64(self):
        self.startIndex = self.startIndex + self.uint64_t
        return self.startIndex

    def nextSHEntry(self):
        self.startIndex = self.startIndex + self.sh_entry_size
        return self.startIndex


class ShTableEntry:
    sh_name = None
    sh_name_index = None
    sh_off = None
    sh_size = None


def get_sh_entry(haystack, start, e_shentsize, byteOrder="little") -> ShTableEntry:
    shTableNav = ShTableNav(start, e_shentsize)
    sh_entry = ShTableEntry()

    sh_entry.sh_name_index = read_bytes_as_int(
        haystack, shTableNav.currentPOS(), shTableNav.nextUINT32(), byteOrder
    )

    if ELF_BITS == 32:
        shTableNav.nextUINT32()  # sh_type
        shTableNav.nextUINT32()  # sh_flags
        shTableNav.nextUINT32()  # sh_addr
        sh_entry.sh_off = read_bytes_as_int(
            haystack, shTableNav.currentPOS(), shTableNav.nextUINT32(), byteOrder
        )
        sh_entry.sh_size = read_bytes_as_int(
            haystack, shTableNav.currentPOS(), shTableNav.nextUINT32(), byteOrder
        )
    else:  # ELF_BITS->64
        shTableNav.nextUINT32()  # sh_type
        shTableNav.nextUINT64()  # sh_flags
        shTableNav.nextUINT64()  # sh_addr
        sh_entry.sh_off = read_bytes_as_int(
            haystack, shTableNav.currentPOS(), shTableNav.nextUINT64(), byteOrder
        )
        sh_entry.sh_size = read_bytes_as_int(
            haystack, shTableNav.currentPOS(), shTableNav.nextUINT64(), byteOrder
        )

    return sh_entry


def to_str(bytes: bytes) -> str:
    nstr = ""
    for b in bytes:
        nstr += chr(b)
    return nstr


def read_sh_entry_name(haystack, start) -> str:
    _null_ptr = start
    while haystack[_null_ptr] != 0:
        _null_ptr += 1
    return to_str(haystack[start:_null_ptr])


def get_sh_table_entries(haystack, byteOrder="little") -> list:
    e_shoff = read_field(haystack, "e_shoff")
    e_shentsize = read_field(haystack, "e_shentsize")
    e_shnum = read_field(haystack, "e_shnum")
    e_shstrndx = read_field(haystack, "e_shstrndx")

    sh_entries = []

    print("[+] Section Header Table is @", hex(e_shoff))

    for i in range(e_shnum):
        sh_entries.append(
            get_sh_entry(haystack, e_shoff + (i * e_shentsize), e_shentsize, byteOrder)
        )

    sh_str_entry = sh_entries[e_shstrndx]

    name_str_bytes = read_bytes(
        haystack, sh_str_entry.sh_off, sh_str_entry.sh_off + sh_str_entry.sh_size
    )
    name_bytes = name_str_bytes.split(b"\x00")
    for i in range(e_shnum):
        sh_entries[i].sh_name = read_sh_entry_name(
            name_str_bytes, sh_entries[i].sh_name_index
        )
    return sh_entries


def get_rodata_section(haystack, byteOrder="little") -> ShTableEntry:
    sh_entries = get_sh_table_entries(haystack, byteOrder)
    for entry in sh_entries:
        if entry.sh_name == ".rodata":
            return entry
    return None


def make_arch_adjustments(haystack) -> ELFIdent:
    global ELF_BITS, ELF_FIELDS, SH_ENTRY

    eli = read_ident(haystack)
    ELF_BITS = eli.elf_bits

    ELF_FIELDS = ELF_32 if eli.elf_bits == 32 else ELF_64
    SH_ENTRY = SH_ENTRY_32 if eli.elf_bits == 32 else SH_ENTRY_64

    return eli


# f = open("testbin", "rb")
# dat = f.read()

# make_arch_adjustments(dat)
# entry = get_rodata_section(dat, "little")
# print(hex(entry.sh_off), hex(entry.sh_size))

# f.close()
