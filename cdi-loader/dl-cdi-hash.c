#include <dl-cdi-hash.h>
// #include <elf/link.h>
// #include <elf/elf.h>




/* hash table implementation */
/* hash table implementation */
// #define hashAddr(addr)       ( (ElfW(Addr))(addr) * 14695981039346656037 ) /*http://isthe.com/chongo/tech/comp/fnv/*/
#define H_BITS          12   // Hashtable size = 2 ^ 12 = 1024
#define H_SHIFT_64      ( 64 - H_BITS )
const ElfW(Xword) var = 2166136261;//14695981039346656037; /*2166136261*/

ElfW(Addr) getHashKey( ElfW(Addr) addr)
{
  return (addr * 2166136261)  >> H_SHIFT_64;
}
void _he_insert_value(hash_entry *he, ElfW(Addr) value){
	plt_entry *tmp = he->first;
	if(!tmp){
		
		he->first = malloc(sizeof(plt_entry));
		he->first->plt_addr = value;
		he->first->next = NULL;
		
		return;
	}
	while(tmp->next){
		tmp = (plt_entry*)tmp->next; 
	}
	tmp->next = malloc(sizeof(plt_entry));
	tmp = (plt_entry *)tmp->next;
	tmp->plt_addr = value;
	tmp->next = NULL;
}

hash_entry* _ht_get_insertion_he (hash_table *ht, ElfW(Addr) key){
	int index = getHashKey(key) % ht_size;
	hash_entry *tmp = ht->table[index];
	if(!tmp){
		ht->table[index] = malloc(sizeof(hash_entry));
		ht->table[index]->f_addr = key;
		ht->table[index]->first = NULL;
		ht->table[index]->next = NULL;
		return ht->table[index];
	}
	while(tmp->next || tmp->f_addr == key){
		if(tmp->f_addr == key){
			return tmp;
		}
		tmp = (hash_entry *)tmp->next;
	}

	tmp->next = malloc(sizeof(hash_entry));
	tmp = (hash_entry *)tmp->next;
	tmp->f_addr = key;
	tmp->first = NULL;
	tmp->next = NULL;
	return tmp;
}

void _ht_put (hash_table *ht, ElfW(Addr) key, ElfW(Addr) value){
	hash_entry *he = _ht_get_insertion_he (ht, key);
	_he_insert_value(he, value);
}

void _ht_init (hash_table *ht){
	for (int i = 0; i < ht_size; i++){
		ht->table[i] = NULL;
	}
}

hash_entry* _ht_get_entry(hash_table *ht, ElfW(Addr) key){
	int index = getHashKey(key) % ht_size;
	hash_entry *tmp = ht->table[index];
	if(!tmp){
		return NULL;
	}
	while(tmp->next || tmp->f_addr == key){
		if(tmp->f_addr == key){
			return tmp;
		}
		tmp = (hash_entry *)tmp->next;
	}
	return NULL;
}

/****** print hash table *****/
void _he_print (int index, hash_entry *he){
	if(he){
		_dl_debug_printf_c("%u: fp_ptr = 0x%lx's plt addresses:\n", (unsigned)index, he->f_addr);
		plt_entry *tmp_plt = he->first;
		while (tmp_plt){
			_dl_debug_printf_c("\t\t0x%lx\n", tmp_plt->plt_addr);
			tmp_plt = (plt_entry*)tmp_plt->next;
		}
	}	
}


void _ht_print (hash_table *ht){
	_dl_debug_printf_c("Printing hash table:\n");
	for (int i = 0; i < ht_size; i++){
		hash_entry *tmp_he = ht->table[i];
		while (tmp_he){
			_he_print(i, tmp_he);
			tmp_he = (hash_entry*)tmp_he->next;
		}
	}
}
