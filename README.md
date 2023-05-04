## Gembe
Extract Files Embedded Within Go Binaries (Go Embeds)["https://pkg.go.dev/embed"].

## Requirements
  -  Python 3.10

## Usage
```
usage: gembe.py [-h] [--extract | --no-extract] [--output o] bin_name struct_addr

Extract Embed File From Go Binaries.

positional arguments:
  bin_name              Name of the binary to inspect
  struct_addr           Address of the embed struct

options:
  -h, --help            show this help message and exit
  --extract, --no-extract
                        Whether to extract the contents (default: False)
  --output o            Where to store the extracted contents
```


