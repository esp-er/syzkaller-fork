__progcalls: Parse and Extract System Call Descriptions
from Syzkaller's .syz files__

(Currently only extracts file paths  from
__open()__ calls but it is a  __WIP__)

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

