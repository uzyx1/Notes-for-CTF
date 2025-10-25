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

---

## Contributing
Open an issue or submit a PR with corrections, additions, or other commands you find useful.

---

## License
This repository is for personal notes. Feel free to reuse or adapt these snippets for personal learning or CTF practice.
