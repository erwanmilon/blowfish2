# Implementation of BLOWFISH II Cipher in C language

Blowfish II was released in 2005. It has exactly the same design but has twice as many S tables and uses 64-bit integers instead of 32-bit integers. It no longer works on 64-bit blocks but on 128-bit blocks like AES.
128-bit block, 64 rounds, key up to 4224 bits.

Blowfish II is included in FreePascal : 
https://gitlab.com/freepascal.org/fpc/source/-/blob/main/packages/fcl-base/src/blowfish2.pp

Use GCC to compile BLOWFISH II :
`gcc blowfish2.c -o blowfish2`

 * Code free for all, even for commercial software 
 * No restriction to use. Public Domain
   
