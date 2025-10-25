# Notes for CTF Challenges

A comprehensive collection of tools, commands, and techniques for Capture The Flag (CTF) competitions.

## Table of Contents
- [Linux Commands](#linux-commands)
  - [Grep](#grep)
  - [Find](#find)
  - [Strings](#strings)
  - [File Analysis](#file-analysis)
- [Web Exploitation](#web-exploitation)
- [Cryptography](#cryptography)
- [Binary Exploitation](#binary-exploitation)
- [Forensics](#forensics)
- [Network Analysis](#network-analysis)
- [Steganography](#steganography)
- [Reverse Engineering](#reverse-engineering)
- [Resources](#resources)

---

## Linux Commands

### Grep
Search for patterns in files and command output.

**Basic Usage:**
```bash
# Search for a pattern in a file
grep "pattern" filename

# Case-insensitive search
grep -i "pattern" filename

# Recursive search in directories
grep -r "pattern" /path/to/directory

# Show line numbers
grep -n "pattern" filename

# Invert match (show lines that don't match)
grep -v "pattern" filename

# Search for whole words only
grep -w "word" filename

# Show context (lines before and after)
grep -C 3 "pattern" filename
grep -A 3 "pattern" filename  # 3 lines after
grep -B 3 "pattern" filename  # 3 lines before

# Count matching lines
grep -c "pattern" filename

# Multiple patterns
grep -E "pattern1|pattern2" filename
```

**CTF Examples:**
```bash
# Find flag format
grep -r "flag{" ./

# Search for base64 encoded data
grep -E "[A-Za-z0-9+/]{20,}={0,2}" file.txt

# Find hidden data in binary files
grep -a "flag" binary_file

# Search for specific keywords in web responses
curl http://target.com | grep -i "password"
```

### Find
Locate files and directories based on various criteria.

**Basic Usage:**
```bash
# Find files by name
find /path -name "filename"

# Find files by extension
find /path -name "*.txt"

# Find files by size
find /path -size +10M  # Larger than 10MB
find /path -size -1k   # Smaller than 1KB

# Find recently modified files
find /path -mtime -1   # Modified in last 24 hours

# Find and execute commands
find /path -name "*.log" -exec grep "error" {} \;

# Find files with specific permissions
find /path -perm 777
```

**CTF Examples:**
```bash
# Find all hidden files
find / -name ".*" 2>/dev/null

# Find SUID binaries (privilege escalation)
find / -perm -4000 2>/dev/null

# Find writable directories
find / -writable -type d 2>/dev/null

# Find files owned by specific user
find / -user root 2>/dev/null
```

### Strings
Extract printable strings from binary files.

**Basic Usage:**
```bash
# Extract strings from a binary
strings binary_file

# Minimum string length (default is 4)
strings -n 10 binary_file

# Search for specific patterns in strings
strings binary_file | grep "flag"

# Show file offset of strings
strings -t x binary_file
```

**CTF Examples:**
```bash
# Look for flags in executables
strings challenge_binary | grep -i "flag{"

# Extract URLs or emails
strings file | grep -E "http|www|@"

# Find encoded data
strings file | grep -E "[A-Za-z0-9+/]{20,}={0,2}"
```

### File Analysis
Identify and analyze file types and contents.

**Commands:**
```bash
# Identify file type
file filename

# Display file in hexadecimal
xxd filename
hexdump -C filename

# Show file metadata
exiftool filename

# Calculate file hash
md5sum filename
sha256sum filename

# Compare two files
diff file1 file2
cmp file1 file2
```

---

## Web Exploitation

### Common Tools
```bash
# Directory/file enumeration
gobuster dir -u http://target.com -w /path/to/wordlist

# SQL Injection
sqlmap -u "http://target.com/page?id=1" --dbs

# Web request manipulation
curl -X POST http://target.com/api -d "param=value"

# Check for common vulnerabilities
nikto -h http://target.com
```

### Useful Techniques
- Check robots.txt and sitemap.xml
- Inspect HTML source code for comments
- Test for SQL injection: `' OR 1=1--`
- Look for Local/Remote File Inclusion (LFI/RFI)
- Test for Cross-Site Scripting (XSS): `<script>alert(1)</script>`

---

## Cryptography

### Common Encodings
```bash
# Base64
echo "text" | base64          # Encode
echo "dGV4dA==" | base64 -d   # Decode

# Hex
echo "text" | xxd -p           # Encode
echo "74657874" | xxd -r -p    # Decode

# ROT13
echo "text" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# URL encoding/decoding
python3 -c "import urllib.parse; print(urllib.parse.unquote('encoded_string'))"
```

### Hash Identification
```bash
# Identify hash type
hashid hash_value
hash-identifier

# Crack hashes
john --format=raw-md5 hash.txt
hashcat -m 0 hash.txt wordlist.txt
```

---

## Binary Exploitation

### Analysis Tools
```bash
# Check binary properties
file binary
checksec binary

# Disassemble
objdump -d binary
gdb binary

# Debug with GDB
gdb ./binary
> break main
> run
> disassemble
> x/20x $rsp
```

### Common Techniques
- Buffer overflow
- Return-oriented programming (ROP)
- Format string vulnerabilities
- Use-after-free

---

## Forensics

### Memory Analysis
```bash
# Volatility framework
volatility -f memory.dump imageinfo
volatility -f memory.dump pslist

# Analyze disk images
autopsy disk.img
```

### File Carving
```bash
# Recover deleted files
foremost -i disk.img

# Binwalk for embedded files
binwalk -e firmware.bin
```

---

## Network Analysis

### Packet Analysis
```bash
# Wireshark for GUI analysis
wireshark capture.pcap

# TShark for CLI analysis
tshark -r capture.pcap

# Filter specific protocols
tshark -r capture.pcap -Y "http"

# Extract HTTP objects
tshark -r capture.pcap --export-objects http,output_dir
```

### Network Scanning
```bash
# Nmap port scanning
nmap -sV -sC target.com
nmap -p- target.com  # All ports
```

---

## Steganography

### Image Analysis
```bash
# Check for hidden data in images
steghide extract -sf image.jpg

# Analyze LSB (Least Significant Bit)
stegsolve image.png

# Zsteg for PNG/BMP
zsteg image.png

# ExifTool for metadata
exiftool image.jpg
```

### Audio Analysis
```bash
# Analyze audio spectrograms
sonic-visualiser audio.wav

# Extract data from audio
steghide extract -sf audio.wav
```

---

## Reverse Engineering

### Tools
```bash
# Ghidra - Decompiler
ghidra

# Radare2 - Reverse engineering framework
r2 binary
> aaa  # Analyze
> pdf @main  # Print disassembly of main

# IDA Pro alternative
# Binary Ninja
```

### Techniques
- Static analysis (reading code without running)
- Dynamic analysis (debugging while running)
- Decompiling to higher-level code
- Understanding assembly language

---

## Resources

### Practice Platforms
- [HackTheBox](https://www.hackthebox.eu/)
- [TryHackMe](https://tryhackme.com/)
- [PicoCTF](https://picoctf.org/)
- [OverTheWire](https://overthewire.org/)
- [CTFtime](https://ctftime.org/) - CTF event calendar

### Learning Resources
- [CTF101](https://ctf101.org/)
- [LiveOverflow YouTube Channel](https://www.youtube.com/c/LiveOverflow)
- [IppSec YouTube Channel](https://www.youtube.com/c/ippsec)

### Wordlists
- SecLists: `/usr/share/seclists/` (Kali Linux)
- [SecLists GitHub](https://github.com/danielmiessler/SecLists)

---

## Contributing

This is a personal collection of CTF notes. Feel free to organize and expand as you learn new techniques!

## Note Organization

You can create separate markdown files for detailed notes on specific topics:
- `linux-commands.md` - Detailed Linux command reference
- `web-exploitation.md` - Web security techniques
- `crypto-tools.md` - Cryptography tools and methods
- And more...

Link them back to this README for easy navigation!
# Notes for CTF

A compact collection of command-line notes and quick references I use while solving CTF challenges. This file focuses on searching text in files — primarily `grep` (Linux/macOS) and `findstr` (Windows).

Table of contents
- [Grep (Linux / macOS)](#grep-linux--macos)
  - [Common options](#common-options)
  - [Examples](#examples)
- [findstr (Windows)](#findstr-windows)
  - [Common options](#common-options-1)
  - [Examples](#examples-1)
- [Tips & alternatives](#tips--alternatives)
- [Contributing](#contributing)
- [License](#license)

---

## Grep (Linux / macOS)

Basic syntax:
```bash
grep [OPTIONS] PATTERN [FILE...]
```

Common options
- `-o`, `--only-matching` : print only the matched part of the line (one match per line).
- `-E`, `--extended-regexp` : treat PATTERN as an extended regular expression (ERE).
- `-i` : ignore case.
- `-r` or `-R` : recursively search directories.
- `-n` : show line numbers.
- `-H` : show filename for each match.
- `-v` : invert match (show lines that do NOT match).
- `--color=auto` : highlight matches in color.
- `-P` : use Perl-compatible regular expressions (PCRE) — not supported in all grep builds.

Examples
- Search for the string `picoCTF` in a file:
```bash
grep 'picoCTF' /path/to/file.txt
```
- Print only the matched text (useful for extracting flags):
```bash
grep -oE 'picoCTF\{[^}]+\}' /path/to/file.txt
```
- Search recursively from the current directory, show filenames and line numbers:
```bash
grep -Rni --color=auto 'password' .
```
- Show files that contain a match (filenames only):
```bash
grep -Rlm1 'TODO' .
```

Notes
- By default, `grep` prints the entire line containing the match; use `-o` to extract only the match.
- When using regular expressions, test your pattern on sample text (or use `grep -oP` for PCRE if available).

---

## findstr (Windows)

Basic syntax:
```
findstr [OPTIONS] PATTERN [FILES]
```

Common options
- `/R` : treat pattern as a regular expression.
- `/S` : search the current directory and all subdirectories.
- `/I` : case-insensitive search.
- `/N` : print line numbers.
- `/M` : print only the filename if a file contains a match.
- `/C:"string"` : use the specified string as a literal search phrase (useful when pattern contains spaces).
- `/P` : skip files with non-printable characters (binary files).

Examples
- Search for `picoCTF` in a file:
```
findstr "picoCTF" C:\path\to\file.txt
```
- Recursive search for `password`, case-insensitive, with line numbers:
```
findstr /S /I /N "password" *
```
- Print filenames only for files that contain the literal phrase `secret key`:
```
findstr /S /M /C:"secret key" *
```

Notes
- `findstr` regex syntax differs from `grep` and is more limited; for complex regex support on Windows consider using PowerShell (`Select-String`) or installing GNU tools (e.g. via WSL, Cygwin, or GnuWin32).

---

## Tips & alternatives
- ripgrep (`rg`) is a fast, user-friendly alternative: `rg 'pattern'`.
- Use `-o` with `grep` to extract flags or tokens (e.g. `picoCTF{...}`).
- When searching code repositories, combine search with `git` or limit by file extension:
```bash
grep -R --include='*.py' 's3cr3t' .
```
- If you’re unsure about escaping in regex, enclose patterns in single quotes on Unix shells to avoid shell interpolation.


