/*
 * PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyleft Daniele Lacamera 2005-2007
 * See AUTHORS and COPYING before using this software.
 *
 *
 *
 */

#ifndef __PEPSAL_H
#define __PEPSAL_H

#include <sys/shm.h>
#include <sys/time.h>


#define DIM_BUFF 1500
#define max(a,b) ((a) > (b) ? (a) : (b))
#ifdef __FAVOR_BSD
#undef __FAVOR_BSD
#endif
#define BUFSIZE 100
//#define BSIZE	8192
#define BSIZE 16348
#define SHM_POS 1280
				     

struct p_buffer{
	char data[BSIZE];
	int pr;
	int pw;
	int tx_attempt;
};

struct t_endpoint{
	int addr;
	unsigned short p;
};

struct t_proxy{
	struct t_endpoint s;
	struct t_endpoint d;
};

struct p_descr{
	int fd_in;
	int fd_out;
	unsigned char  status;
	struct timeval last_tx;
	struct t_proxy proxy;
	struct p_buffer *buf_in;
	struct p_buffer *buf_out;
};
#define PST_CLOSED 0
#define PST_OPEN 1
#define PST_CONNECT 2
#define PST_PRE	3


struct syn_table{
	struct p_descr item[BUFSIZE];
	unsigned int page;
	unsigned char nextpage;
	unsigned char bitmap[(BUFSIZE/8)+1];
};

#define ST_ACCESS 0
#define ST_CREATE 1


/*
 * From shmanage.c :
 */

#ifndef __I_AM_SHMANAGE_C
extern int e_match(struct t_endpoint e1, struct t_endpoint e2);
extern int t_find(struct t_endpoint src, struct syn_table *st);
extern void set_bit(unsigned pos, struct syn_table *st);
extern void unset_bit(unsigned pos, struct syn_table *st);
extern int is_setbit(unsigned pos, struct syn_table *st);
extern int t_add(struct p_descr p, struct syn_table *st);
extern struct syn_table *get_syn_table(int flags, int page);
#endif 	

#endif
