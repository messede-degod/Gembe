## Gembe
Extract Files Embedded Within Go Binaries ( [Go Embeds](https://pkg.go.dev/embed).)<br>
Read this [post](https://web.archive.org/web/20230606135339/https://0x00sec.org/t/extracting-go-embeds/34885)  for more information.

## Requirements
  -  Python 3.10

## Support
|          |  |
|--------------|:-----:|
| Binary Format |  ELF |
| Endianess      |  LE, BE |

## In the Wild
  - Extracting files from the gorgon stresser: https://rt-solar.ru/solar-4rays/blog/4690/

## Usage
  - Please obtain the address of the embed structure by using a appropriate debugger first! (read [this](https://web.archive.org/web/20230606135339/https://0x00sec.org/t/extracting-go-embeds/34885) for more information)
```
usage: gembe.py [-h] [--extract | --no-extract] [--output o] bin_name struct_addr

Extract Embedded Files From Go Binaries.

positional arguments:
  bin_name              Name of the binary to inspect
  struct_addr           Address of the embed struct

options:
  -h, --help            show this help message and exit
  --extract, --no-extract
                        Whether to extract the contents (default: False)
  --output o            Where to store the extracted contents
```
