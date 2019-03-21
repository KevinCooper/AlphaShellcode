# AlphaShellcode 

This repo contains two different tools for working with alphanumeric shellcode.  
1. EncodeVariable takes two different addresses, then produces a sequence of three sub encoded commands to produce the desired ending address.  These sub commands are restricted to an alpanumeric character set
2. EncodeInstructions takes shellcode, then produces the minimum possible length of sub commands to create the desired shellcode on the stack.  
Inspired from [Slink](https://github.com/ihack4falafel/Slink) and [This Blog](https://marcosvalle.github.io/re/exploit/2018/10/05/sub-encoding.html).
