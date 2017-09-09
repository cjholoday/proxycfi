#ifndef _DL_CDI_HASH
#define _DL_CDI_HASH

#define ht_size 1024;

/* hash table interface */
#define ht_size 1024

/* hash table interface */
typedef struct {
	Elfw(Addr) plt_addr;
	struct plt_entry* next;
}plt_entry;

typedef struct {
	Elfw(Addr) fp_addr;
	plt_entry* first;
	struct hash_entry* next;
}hash_entry;

typedef struct {
	hash_entry* table[ht_size];
}hash_table;

void _he_insert_value(hash_entry *he, Elfw(Addr) value);
// Elfw(Addr) remove_last(hash_entry *he);
hash_entry* _ht_get_entry(hash_table *ht, Elfw(Addr) key);
void _ht_put (hash_table *ht, Elfw(Addr) key, Elfw(Addr) value);
void _ht_init (hash_table *ht);
void _ht_print (hash_table * ht);
#endif
