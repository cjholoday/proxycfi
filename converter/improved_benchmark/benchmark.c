#include "printf.h"

/**********************hanoi.c*********************************/

#define other(i,j) (6-(i+j))

static int num[4];
static long count;

static int
mov(int n, int f, int t)
{ int o;

  if (n == 1)
    {
      num[f]--;
      num[t]++;
      count++;
      return 0;
    }
  o = other(f, t);
  mov(n-1, f, o);
  mov(1, f, t);
  mov(n-1, o, t);
  return 0;
}

int
hanoi_main(void)
{
  int disk, Loops = 0;

  printf("Towers of Hanoi Puzzle Test Program\n");
  printf("Disks     Moves\n");

  disk = 0;

  while (1)
    {
      disk++;
      num[0] = 0;
      num[1] = disk;
      num[2] = 0;
      num[3] = 0;
      count  = 0;

      mov(disk,1,3);

      Loops = Loops + 1;
      printf("%3d  %04X%04X\n",disk,count >> 16, count & 0xffff);

      if ( disk == 30 ) break;
    }
  return 0;
}

/**********************cipher.c*********************************/

void
encipher(unsigned int *const in,
	 unsigned int *const out,
	 const unsigned int *const key)
{
  unsigned int y=in[0], z=in[1], sum=0, delta=0x9E3779B9;
  unsigned int a=key[0], b=key[1], c=key[2], d=key[3], n=32;

  while (n-->0)
    {
      sum += delta;
      y += ((z << 4)+a) ^ (z+sum) ^ ((z >> 5)+b);
      z += ((y << 4)+c) ^ (y+sum) ^ ((y >> 5)+d);
    }
  out[0]=y; out[1]=z;
}

void
decipher(unsigned int *const in,
	 unsigned int *const out,
	 const unsigned int *const key)
{
  unsigned int y=in[0], z=in[1], sum=0xC6EF3720, delta=0x9E3779B9;
  unsigned int a=key[0], b=key[1], c=key[2], d=key[3], n=32;

  /* sum = delta<<5, in general sum = delta * n */
  while (n-->0)
    {
      z -= ((y << 4)+c) ^ (y+sum) ^ ((y >> 5)+d);
      y -= ((z << 4)+a) ^ (z+sum) ^ ((z >> 5)+b);
      sum -= delta;
    }
  out[0]=y; out[1]=z;
}

unsigned int keytext[4] = { 358852050,	311606025, 739108171, 861449956 };
unsigned int plaintext[2] = { 765625614, 14247501 };
unsigned int cipherref[2] = { 0x9fe2c864, 0xd7da4da4 };
unsigned int ciphertext[2];
unsigned int newplain[2];


int
cipher_main(void)
{
  void (*cipher_type) (unsigned int *const in,
   unsigned int *const out,
   const unsigned int *const key);
  cipher_type = &encipher;
  cipher_type(plaintext, ciphertext, keytext);
  if (ciphertext[0] != cipherref[0] || ciphertext[1] != cipherref[1])
      return 1;
  cipher_type = &decipher;
  cipher_type(ciphertext, newplain, keytext);
  if (newplain[0] != plaintext[0] || newplain[1] != plaintext[1])
      return 1;
  
  printf("TEA Cipher results:\n");
  printf("  plaintext:  0x%04X%04X 0x%04X%04X\n",
	       plaintext[0] >> 16, plaintext[0] & 0xffff,
               plaintext[1] >> 16, plaintext[1] & 0xffff);
  printf("  ciphertext: 0x%04X%04X 0x%04X%04X\n",
	       ciphertext[0] >> 16, ciphertext[0] & 0xffff,
               ciphertext[1] >> 16, ciphertext[1] & 0xffff);
  printf("  newplain:   0x%04X%04X 0x%04X%04X\n",
	       newplain[0] >> 16, newplain[0] & 0xffff,
               newplain[1] >> 16, newplain[1] & 0xffff);

  return 0;
}

/***********************CDI benchmark*********************************/

int main() {
    hanoi_main();
    cipher_main();
}

