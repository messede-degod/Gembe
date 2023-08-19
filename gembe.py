import read_elf
import argparse
import os
import pathlib


class EmbedEntryNav:
    startIndex = 0
    HWORD = 8
    WORD = 16
    EMBED_ENTRY_SIZE = HWORD * 6

    def __init__(self, start, bits):
        self.startIndex = start
        if bits == 32:
            self.HWORD = 4
            self.WORD = 8
            self.EMBED_ENTRY_SIZE = self.HWORD * 8

    def currentPOS(self):
        return self.startIndex

    def nextHWORD(self):
        self.startIndex = self.startIndex + self.HWORD
        return self.startIndex

    def nextWORD(self):
        self.startIndex = self.startIndex + self.WORD
        return self.startIndex

    def nextEmbedEntry(self):
        self.startIndex = self.startIndex + self.EMBED_ENTRY_SIZE
        return self.startIndex


class FileEntry:
    file_name_ptr: int = None
    file_name_len: int = None
    file_content_ptr: int = None
    file_content_len: int = None
    file_content_hash: str = None
    isDirectory: bool = False

    def getFileName(self, haystack) -> bytes:
        if self.file_name_len > 0:
            return haystack[
                self.file_name_ptr : self.file_name_ptr + self.file_name_len
            ]
        return b""

    def getFileContent(self, haystack) -> bytes:
        if self.file_content_len > 0:
            return haystack[
                self.file_content_ptr : self.file_content_ptr + self.file_content_len
            ]
        return b""


ELF64_BADDR = 0x400000
ELF32_BADDR = 0x08048000

ELF_BASE_ADDR = 0x400000


"""
Embed struct
============================
FirstENtryPtr(8)    -- 1
TotalNoofEntries(8) -- 2
TotalNoofEntries(8) -- 3

Entry-No.1--|
FilnamePtr(8) -- 4
FilenameLen(8)  -- 5
FileContentPtr(8) -- 6
FileContentLen(8) -- 7
FileContentHash(16) --8
....
...
..
.
Entry-No.N--|
...
..
.
============================
"""


def read_bytes(haystack, start, end):
    bytes_read = haystack[start:end]
    if len(bytes_read) > 0:
        while bytes_read[-1] == b"\x00":
            del bytes_read[-1]
    return bytes_read


def read_bytes_as_int(haystack, start, end, byteOrder="little"):
    return int.from_bytes(read_bytes(haystack, start, end), byteorder=byteOrder)


def get_entry(haystack, start, bits, byteOrder="little") -> FileEntry:
    bys = EmbedEntryNav(start, bits)
    entry = FileEntry()

    entry.file_name_ptr = (
        read_bytes_as_int(haystack, bys.currentPOS(), bys.nextHWORD(), byteOrder)
        - ELF_BASE_ADDR
    )
    entry.file_name_len = read_bytes_as_int(
        haystack, bys.currentPOS(), bys.nextHWORD(), byteOrder
    )

    file_content_ptr = (
        read_bytes_as_int(haystack, bys.currentPOS(), bys.nextHWORD(), byteOrder)
        - ELF_BASE_ADDR
    )

    entry.file_content_ptr = file_content_ptr if file_content_ptr > 0 else 0

    entry.file_content_len = read_bytes_as_int(
        haystack, bys.currentPOS(), bys.nextHWORD(), byteOrder
    )
    entry.file_content_hash = read_bytes(
        haystack, bys.currentPOS(), bys.nextWORD()
    ).hex()

    entry.isDirectory = entry.file_content_len == 0

    return entry


# =============================================================
# arg (1) -> Binary Name
# arg (2) -> Hex Addr of the embed struct

parser = argparse.ArgumentParser(description="Extract Embedded Files From Go Binaries.")
parser.add_argument(
    "bin_name", metavar="bin_name", type=str, help="Name of the binary to inspect"
)
parser.add_argument(
    "s_addr", metavar="struct_addr", type=str, help="Address of the embed struct"
)
parser.add_argument(
    "--extract",
    metavar="e",
    required=False,
    type=bool,
    help="Whether to extract the contents",
    default=False,
    action=argparse.BooleanOptionalAction,
)
parser.add_argument(
    "--output",
    metavar="o",
    required=False,
    type=str,
    help="Where to store the extracted contents",
    default=".",
)
args = parser.parse_args()

file_name = args.bin_name
e_struct_pos = args.s_addr

f = open(file_name, "rb")
dat = f.read()

# Get ELF Information
elf_ident = read_elf.read_ident(dat)
emebed_struct_pos = int(e_struct_pos, 16)
print("[+] Embed Struct @ ", hex(emebed_struct_pos))

# Adjust Base Address if ELF32
if elf_ident.elf_bits == 32:
    ELF_BASE_ADDR = ELF32_BADDR

embed_struct_start = emebed_struct_pos - ELF_BASE_ADDR

print(
    "[+] File:",
    file_name,
    " Endianess:",
    elf_ident.elf_endianess,
    " Bits:",
    elf_ident.elf_bits,
)

ebys = EmbedEntryNav(embed_struct_start, elf_ident.elf_bits)

first_entry_ptr = (
    read_bytes_as_int(
        dat, ebys.currentPOS(), ebys.nextHWORD(), elf_ident.elf_endianess
    )  # --1
    - ELF_BASE_ADDR
)

print("[+] First Entry @ ", hex(first_entry_ptr))

# no of entries(files+dir) in struct
no_of_entries = read_bytes_as_int(
    dat, ebys.currentPOS(), ebys.nextHWORD(), elf_ident.elf_endianess  # --2
)

ebys.nextHWORD()  # --3

fileEnts = []
totalFileSize = 0
for i in range(no_of_entries):
    # print("Current Pos", hex(ebys.currentPOS()), end=" ")
    fileEnt = get_entry(
        dat, ebys.currentPOS(), elf_ident.elf_bits, elf_ident.elf_endianess
    )
    # print(fileEnt.getFileName(dat), " isDirectory: ", fileEnt.isDirectory," Size : ",fileEnt.file_content_len)
    totalFileSize += fileEnt.file_content_len
    ebys.nextEmbedEntry()
    fileEnts.append(fileEnt)

f.close()

print("[+] Found ", no_of_entries, " files, Total Size : ", totalFileSize, " bytes")

outputPath = args.output
if args.extract:
    if outputPath==".":
        outputPath = "./output/"+file_name

    print("[+] Extracting Files to ", outputPath)

    for fileEnt in fileEnts:
        filePath = outputPath+"/"+fileEnt.getFileName(dat).decode("utf-8")
        if fileEnt.isDirectory:
            pathlib.Path(filePath).mkdir(parents=True,exist_ok=True)
        else:
            pathlib.Path(filePath).write_bytes(fileEnt.getFileContent(dat))