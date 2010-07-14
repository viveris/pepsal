/*
 * PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyleft Daniele Lacamera 2005
 * See AUTHORS and COPYING before using this software.
 *
 *
 *
 */

#include <sys/ipc.h>
#include <sys/shm.h>
#include <string.h> //for memset()
#include "pepsal.h"


int e_match(struct t_endpoint e1, struct t_endpoint e2)
{
	if ((e1.addr==e2.addr) && (e1.p==e2.p)){
		return 1;
	}
	else
		return 0;
}

int t_find(struct t_endpoint src, struct syn_table *st)
{
	int i; 
	for (i=0; i<BUFSIZE; i++) {
		if (e_match (src, st->item[i].proxy.s))
			return i;
	}
	if (st->nextpage)
		return t_find(src,get_syn_table(0,st->page+1));
	
	return -1;
}
void set_bit(unsigned pos, struct syn_table *st)
{
        unsigned byte = pos>>3;
        unsigned bit = pos%8;
        unsigned char setbit = 1<<bit;
        st->bitmap[byte]=st->bitmap[byte]|setbit;
}

void unset_bit(unsigned pos, struct syn_table *st)
{
        unsigned byte = pos>>3;
        unsigned bit = pos%8;
        unsigned char setbit = 0xFF - (1<<bit);
        st->bitmap[byte]=st->bitmap[byte]&setbit;
}

int is_setbit(unsigned pos, struct syn_table *st)
{
        unsigned byte = pos>>3;
        unsigned bit = pos%8;
        unsigned char setbit = 1<<bit;
        return (st->bitmap[byte] & setbit);
}

int t_add(struct p_descr p, struct syn_table *st)
{
	int i, must_spawn_page=0;
	for (i=0; i<BUFSIZE; i++) {
                if (!is_setbit(i,st)){
                        set_bit(i,st);
			st->item[i]=p;
			return i;
		}
	}
	if (!st->nextpage)
		must_spawn_page=1;
	return t_add(p,get_syn_table(must_spawn_page, st->page+1));
		
}


struct syn_table *get_syn_table(int flags, int page)
{
	int pagenum, shmid;
	struct syn_table *st;
	
	pagenum=SHM_POS+page;
	if (flags){
		shmid = shmget (pagenum,sizeof(struct syn_table),IPC_CREAT|0660);
	}else{
		shmid = shmget (pagenum,sizeof(struct syn_table),0660);
	}

	st=(struct syn_table *)shmat(shmid,0,0);
		
	if (flags)
		memset(st,0,sizeof(struct syn_table));
		st->page=page;
		st->nextpage=0;

	return st;
}	

