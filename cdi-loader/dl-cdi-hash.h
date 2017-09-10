#ifndef _DL_CDI_HASH
#define _DL_CDI_HASH

#include <errno.h>                                                              
#include <dlfcn.h>                                                              
#include <fcntl.h>                                                              
#include <stdbool.h>                                                            
#include <stdlib.h>                                                             
#include <string.h>                                                             
#include <unistd.h>                                                             
#include <sys/mman.h>                                                           
#include <sys/param.h>                                                          
#include <sys/stat.h>                                                           
#include <ldsodefs.h>                                                           
#include <_itoa.h>                                                              
#include <entry.h>                                                              
#include <fpu_control.h>                                                        
#include <hp-timing.h>                                                          
#include <libc-lock.h>                                                          
#include <dl-librecon.h>                                                        
#include <dl-procinfo.h>                                                        
#include <tls.h>                                                                
#include <stap-probe.h>                                                         
#include <stackinfo.h>                                                          

#include <assert.h>              

#include <link.h>



/* hash table interface */
#define ht_size 4096

/* hash table interface */
typedef struct {
	ElfW(Addr) plt_addr;
	struct plt_entry* next;
}plt_entry;

typedef struct {
	ElfW(Addr) f_addr;
	plt_entry* first;
	struct hash_entry* next;
}hash_entry;

typedef struct {
	hash_entry* table[ht_size];
}hash_table;

hash_entry* _ht_get_entry(hash_table *ht, ElfW(Addr) key);
void _ht_put (hash_table *ht, ElfW(Addr) key, ElfW(Addr) value);
void _ht_init (hash_table *ht);
void _ht_print (hash_table * ht);
void _he_print (int index, hash_entry *he); /* Prints all the plt addresses for a fp*/
hash_entry* _ht_get_entry(hash_table *ht, ElfW(Addr) key);
#endif
