__progcalls: Parse and Extract System Call Descriptions
from Syzkaller's .syz files__

(Currently only extracts File Paths  from
__open()__  and __openat()__ calls but it is a  __WIP__)

# Compilation
Enter and Run
```
make progcalls
```
In the repository base directory. Binary will be output to bin/


# Usage 
To parse a directory of syz files and output syscall descriptions to
__json__ format in current the directory use e.g:
```
cd bin 
./progcalls -dir kasan/ -json kasan.json 
```

To parse a single file and output json try e.g
```
./progcalls -p kfree_skb_7.syz -json kfree.json
```
To only print call info to stdout use e.g

```
./progcalls -debug -p kfree_skb_7.syz 
```

#JSON Format

Currently the json format is as such
```
{
"File: "filename.syz", (__Filename String__)
"Calls:"  [] (__List of calls inside filename.syz__)
}
```
A __Call__ is structured as such:
```
{
 "SyscallName": "syscallname", (__string__)
 "SyscallNR":  syscall number, (__int__)
 "Arguments": [] (__List of arguments inside call__)
}
```
Arguments contain:
```
{
"ArgName": "(e.g) file", (__String description of argument__),
"ArgType":  "(e.g) flags, (__String description of the argument type__)
 "HasVal": true/false, (__Bool to indicate if call has a constant file path value associated (currently__)
 "ArgVal": "/path/to/file" (__Currently only contains an argument file path if one exists__)
}

```




