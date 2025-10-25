# Notes-for-CTF
This will be my notes for CTF challenges


#Grep
grep [OPTIONS] PATTERN [FILE...]
example: grep -oE picoCTF C:/file/path
-o (or --only-matching): This option changes the default behavior of grep, which is to print the entire line containing a match. With -o, grep will only print the matched portion of the line, and each match will be printed on a new line.
-E (or --extended-regexp): This option instructs grep to interpret the provided pattern as an extended regular expression (ERE). Extended regular expressions offer more features and a slightly different syntax compared to basic regular expressions (BREs), which are the default for grep

for windows
findstr [string/pattern] [filepath]
