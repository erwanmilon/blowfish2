/* BLOWFISH II : 128-bit block (like AES) 64 rounds */
/* by Alexander PUKALL 2005 */
/* Code free for all, even for commercial software */
/* key up to 4224 bits */
 
/* compile with gcc : gcc blowfish2.c -o blowfish2 */
 
 
/*
 
   BLOWFISH II : 128-bit block (like AES) 64 rounds
 
blowfish2.c:  C implementation of the Blowfish II algorithm.
 
Blowfish 1 Copyright (C) 1997 by Paul Kocher.
Blowfish II 128-bit block 2005 by Alexander Pukall
 
  
COMMENTS ON USING THIS CODE:
 
Normal usage is as follows:
   [1] Allocate a BLOWFISH_CTX.  (It may be too big for the stack.)
   [2] Call Blowfish_Init with a pointer to your BLOWFISH_CTX, a pointer to
       the key, and the number of bytes in the key.
   [3] To encrypt a 128-bit block, call Blowfish_Encrypt with a pointer to
       BLOWFISH_CTX, a pointer to the 64-bit left half of the plaintext
       and a pointer to the 64-bit right half.  The plaintext will be
       overwritten with the ciphertext.
   [4] Decryption is the same as encryption except that the plaintext and
       ciphertext are reversed.
 
Warning #1:  The code does not check key lengths. (Caveat encryptor.) 
Warning #2:  Beware that Blowfish keys repeat such that "ab" = "abab".
Warning #3:  It is normally a good idea to zeroize the BLOWFISH_CTX before
  freeing it.
Warning #4:  Endianness conversions are the responsibility of the caller.
  (To encrypt bytes on a little-endian platforms, you'll probably want
  to swap bytes around instead of just casting.)
Warning #5:  Make sure to use a reasonable mode of operation for your
  application.  (If you don't know what CBC mode is, see Warning #7.)
Warning #6:  This code is susceptible to timing attacks.
Warning #7:  Security engineering is risky and non-intuitive.  Have someone 
  check your work.  If you don't know what you are doing, get help.
 
This is code is fast enough for most applications, but is not optimized for
speed.
 
 
  Modifications by Alexander Pukall:
 
  N = 64 rounds
  ORIG_P[64+2] = generated from Pi
  ORIG_S[8][256] = generated from Pi
 
  Modifications to use uint64_t for L and R
 
  The original Blowfish algorithm supports key sizes up to 576 bits because 
  the ORIG_P[16+2] is 576 bits long (18*32 bits = 576)
  Blowfish II supports key sizes up to 4224 bits because ORIG_P[64+2]
  is 4224 bits long (66*64 bits = 4224).
 
*/
 
#include <stdint.h>
#include <stdio.h>
 
 
typedef struct {
  uint64_t P[64 + 2];
  uint64_t S[8][256];
} BLOWFISH_CTX;
 
void Blowfish_Init(BLOWFISH_CTX *ctx, unsigned char *key, int keyLen);
void Blowfish_Encrypt(BLOWFISH_CTX *ctx, uint64_t *xl, uint64_t *xr);
void Blowfish_Decrypt(BLOWFISH_CTX *ctx, uint64_t *xl, uint64_t *xr);
 
 
 
#define N 64/* Exchange Xl and Xr */
    temp = Xl;
    Xl = Xr;
    Xr = temp;
  }
 
  /* Exchange Xl and Xr */
  temp = Xl;
  Xl = Xr;
  Xr = temp;
 
  Xr = Xr ^ ctx->P[1];
  Xl = Xl ^ ctx->P[0];
 
  *xl = Xl;
  *xr = Xr;
}
 
 
void Blowfish_Init(BLOWFISH_CTX *ctx, unsigned char *key, int keyLen) {
  int i, j, k;
  uint64_t data, datal, datar;
 
 
  for (i = 0; i < 8; i++) {
    for (j = 0; j < 256; j++)
      ctx->S[i][j] = ORIG_S[i][j];
  }
 
  j = 0;
  for (i = 0; i < N + 2; ++i) {
    data = 0x0000000000000000;
    for (k = 0; k < 8; ++k) {
      data = (data << 8) | key[j];
      j = j + 1;
      if (j >= keyLen)
        j = 0;
    }
    ctx->P[i] = ORIG_P[i] ^ data;
  }
 
  datal = 0x0000000000000000;
  datar = 0x0000000000000000;
 
  for (i = 0; i < N + 2; i += 2) {
    Blowfish_Encrypt(ctx, &datal, &datar);
    ctx->P[i] = datal;
    ctx->P[i + 1] = datar;
  }
 
  for (i = 0; i < 8; ++i) {
    for (j = 0; j < 256; j += 2) {
      Blowfish_Encrypt(ctx, &datal, &datar);
      ctx->S[i][j] = datal;
      ctx->S[i][j + 1] = datar;
    }
  }
}
 
 
void main(void) {
 
  
  printf("BLOWFISH II by Alexander PUKALL 2005\n 128-bit block 64 rounds\n key up to 4224 bits\n");
  printf("Code can be freely use even for commercial software\n");
  printf("Based on Blowfish 1997 by Paul Kocher\n");
 
  uint64_t L,R;
  
 
  BLOWFISH_CTX ctx;
  
  
  /* Plaintext 128-bit block :0x00000000000000010000000000000002 */
  
  L = 0x0000000000000001, R = 0x0000000000000002; // 64 bits L + 64 bits R = 128-bit block
    
 
  printf("Plaintext 128-bit block: %0.16llX %0.16llX\n",L, R);
  printf("Key: TESTKEY\n");
      
  Blowfish_Init (&ctx, (unsigned char*)"TESTKEY", 7);
  Blowfish_Encrypt(&ctx, &L, &R);
  
  printf("Ciphertext 128-bit block: ");
  printf("%0.16llX %0.16llX\n",L, R);
  
  if (L == 0x7B2B9DE71D1B1C62 && R == 0x91C230351177BEE8)
      printf("Test encryption OK.\n");
  else
      printf("Test encryption failed.\n");
  Blowfish_Decrypt(&ctx, &L, &R);
  if (L == 1 && R == 2)
      printf("Test decryption OK.\n");
  else
      printf("Test decryption failed.\n");
 
 
  /* Plaintext 128-bit block :0x01020304050607080910111213141516 */
  
  L=0x0102030405060708;
  R=0x0910111213141516;
  
  
  printf("\nPlaintext 128-bit block : %0.16llX %0.16llX\n",L, R);
  
  printf("Key: A\n");
   
  Blowfish_Init (&ctx, (unsigned char*)"A", 1);
  Blowfish_Encrypt(&ctx, &L, &R);
  
  printf("Ciphertext 128-bit block: ");
  printf("%0.16llX %0.16llX\n", L, R);
  
  if (L == 0xCA38165603F9915C && R == 0x61F0776A0F55E807)
      printf("Test encryption OK.\n");
  else
      printf("Test encryption failed.\n");
  Blowfish_Decrypt(&ctx, &L, &R);
  if (L == 0x0102030405060708 && R == 0x0910111213141516)
      printf("Test decryption OK.\n");
  else
      printf("Test decryption failed.\n");
          
  
  /* Plaintext 128-bit block :0x01020304050607080910111213141516 */
  
  L=0x0102030405060708;
  R=0x0910111213141516;
  
  
  printf("\nPlaintext 128-bit block: %0.16llX %0.16llX\n",L, R);
  
  printf("Key: B\n");
   
  Blowfish_Init (&ctx, (unsigned char*)"B", 1);
  Blowfish_Encrypt(&ctx, &L, &R);
  
  printf("Ciphertext 128-bit block: ");
  printf("%0.16llX %0.16llX\n", L, R);
  
  if (L == 0xD07690A78B109983 && R == 0x8DDF85826F2366C2)
      printf("Test encryption OK.\n");
  else
      printf("Test encryption failed.\n");
  Blowfish_Decrypt(&ctx, &L, &R);
  if (L == 0x0102030405060708 && R == 0x0910111213141516)
      printf("Test decryption OK.\n");
  else
      printf("Test decryption failed.\n");
   
}