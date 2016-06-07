// #include "libcosim.h"
#include "printf.h"

#define other(i,j) (6-(i+j))

static int num[4];
static long count;

static int
mov(int n, int f, int t)
{
  int o;

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
main(void)
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
      printf("%3d  %5d%5d\n",disk,count>>20 , count & 0xfffff);

      if ( disk == 5 ) break;
    }
  return 0;
}
