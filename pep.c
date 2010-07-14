/*
 * PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyleft Daniele Lacamera 2005
 * See AUTHORS and COPYING before using this software.
 *
 *
 *
 */

#include "pepsal.h"
#include "config.h"
#define IPQUEUE_OLD 0

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#define __USE_XOPEN_EXTENDED
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netdb.h>
#include <getopt.h>
#include <linux/netfilter.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <sys/poll.h>

#if (IPQUEUE_OLD)
#include <libipq/libipq.h>
#else
#include <libnetfilter_queue/libnetfilter_queue.h>
#endif

#define TRANSMIT_RETRIES 200
#define SOCKET_TIMEOUT 60 //seconds


#define DIM_BUFF 1500
#define max(a,b) ((a) > (b) ? (a) : (b))

#ifdef __FAVOR_BSD
#undef __FAVOR_BSD
#endif
#define PORTSCAN 0

struct syn_table *tab;

static int DEBUG=0;
static int background=0;
static int queuenum=0;
static int qpid;
static int conn_pipe[2];
static char address[20]="0.0.0.0";


static int portnum=5000;


/*
 * Data structure to fill with packet headers when we
 * get a new syn:
 *
 * struct ipv4_packet
 *		iph : ip header for the packet
 *		tcph: tcp header for the segment
 *
 */
struct ipv4_packet{
	struct iphdr iph;
	struct tcphdr tcph;
};

/*
 * Secure routine to translate a hex address in a
 * readable ip number:
 */
void toip(char *ret, int address){
	int a,b,c,d;
	a=(0xFF000000&address)>>24;
	b=(0x00FF0000&address)>>16;
	c=(0x0000FF00&address)>>8;
	d=0x000000FF&address;
	snprintf(ret,16,"%d.%d.%d.%d",a,b,c,d);
}

int check_endpoint(struct t_proxy tp){
	struct sockaddr_in servaddr_r;
	int sd;
	unsigned short tcpport_r;
	struct hostent *host;
	char remotehost[17];
	toip(remotehost,tp.d.addr);
	//printf("OK\n%s,%u\n",remotehost,tp.d.p);
	tcpport_r=tp.d.p;
	memset((char *)&servaddr_r, 0, sizeof(struct sockaddr_in));
	servaddr_r.sin_family = AF_INET;
	host = gethostbyname(remotehost);
	if (host == NULL)
	{
		 perror("Unable to reach endpoint ");
		exit(2);
	}

	servaddr_r.sin_addr.s_addr=((struct in_addr*) (host->h_addr))->s_addr;
	servaddr_r.sin_port = htons(tcpport_r);
	sd=socket(AF_INET, SOCK_STREAM, 0);
	if (sd <0)
	{
		perror("Opening socket "); exit(3);
	}
	if (connect(sd,(struct sockaddr *)&servaddr_r, sizeof(struct sockaddr))<0)
	{
		return 0;
	}
	close(sd);
	return 1;
}

/* NFQUEUE callback function for incoming TCP syn */
static int nfqueue_get_syn(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	char *buffer;
	int ret;
	struct ipv4_packet *ip4;
	struct p_descr pd;
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	
	if(DEBUG)
		printf("Enter callback... \n");

	ph = nfq_get_msg_packet_hdr(nfa);
	if(!ph){
		fprintf(stderr,"Unable to get packet header.\n");
		return -1;
	}
	id = ntohl(ph->packet_id);

	ret = nfq_get_payload(nfa, &buffer);

	if(DEBUG)
		printf("payload_len=%d ", ret);
	
	ip4=(struct ipv4_packet *)buffer;
	pd.proxy.s.addr=ntohl(ip4->iph.saddr);
	pd.proxy.d.addr=ntohl(ip4->iph.daddr);
	pd.proxy.s.p=ntohs(ip4->tcph.source);
	pd.proxy.d.p=ntohs(ip4->tcph.dest);
	if (DEBUG)
		printf("Syn from %x\n",ntohl(ip4->iph.saddr));
	/* This checks if the other endpoint exists. */
	if(PORTSCAN){
		if(!check_endpoint(pd.proxy)){
			fprintf(stderr,"Unable to reach endpoint.\n");
			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		}
	}

	/* Check for duplicate syn, and drop it.
	 * This happens when RTT is too long and we
	 * still didn't establish the connection.
	 */
	if((t_find(pd.proxy.s,tab)>0)){
			printf("Duplicate syn! DROPping.\n");
			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
//			return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	/* add to the table... */
	pd.status=PST_PRE;
	t_add(pd,tab);

	if (DEBUG)
		printf("Syn Registered.\n");
	
	/* let it pass through */
	ret = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	return ret;
}


/*
 * This is the queuer thread.
 * It reads a packet from the ip_queue and fill
 * connection array with the ipquad.
 */

void p_queuer(void *obj){
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096];
	int i;
	
	tab=(struct syn_table*)get_syn_table(ST_CREATE,0);

	/* Initialize the array bitmap*/
	for (i=0;i<BUFSIZE;i++)
		unset_bit(i,tab);
	
	/* Create handle for the nf_queue */
	if(DEBUG)
		printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	
	if(DEBUG)
		printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	(void) nfq_unbind_pf(h, AF_INET);
	
	if(DEBUG)
		printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
		int ttt = nfq_bind_pf(h, AF_INET);
	if (ttt < 0) {
		fprintf(stderr, "error during nfq_bind_pf() value=%d \n",ttt);
		exit(1);
	}

	if(DEBUG)
		printf("binding this socket to queue '%d'\n",queuenum);
	qh = nfq_create_queue(h,  queuenum, &nfqueue_get_syn, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}
	
	if(DEBUG)
		printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	nh = nfq_nfnlh(h);
	fd = nfnl_fd(nh);

	// Blocking call to read packet from nf_queue
	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		if(DEBUG)
			printf("pkt received\n");
		nfq_handle_packet(h, buf, rv);
	}

	if(DEBUG)
		printf("Exiting queuer. Closing library handle.\n");
	nfq_close(h);
	
}





/********************************************************/
void sigchld_handler(int signo)
{
 int stato;
 //printf("Signals collector started\n");
 wait(&stato);
 //printf("queuer process killed, terminating...\n");
 //exit(0);
}

void goodbye(int signo)
{
	int stato;
	wait(&stato);
	printf("Received signal %d. Exiting...\n",signo);
	kill(qpid,SIGINT);
	sleep(1);
	exit(0);
}


int getpos(int fd)
{
	int i;
	for (i=0;i<BUFSIZE*2+1;i++){
		if(is_setbit(i,tab)){
			if((tab->item[i].fd_in==fd)||(tab->item[i].fd_out==fd)){
				return i;
			}
		}
	}
	if(DEBUG)
		printf("Not Found\n",i);
	return -1;
}

static void close_proxy(struct p_descr *pd){
	int pos=getpos(pd->fd_in);
	if(pos>=0){
		close(pd->fd_in);
		close(pd->fd_out);
		pd->status=PST_CLOSED;
		unset_bit(pos, tab);
		//free(pd);
	}
}


static void check_timeout(void){
	struct timeval expire;
	int i;
	gettimeofday(&expire,NULL);
	expire.tv_sec-=SOCKET_TIMEOUT;
	for(i=0; i<(2*BUFSIZE+1); i++){
		if(tab->item[i].status==PST_OPEN && tab->item[i].last_tx.tv_sec < expire.tv_sec ||  
		(tab->item[i].last_tx.tv_sec ==  expire.tv_sec &&
		tab->item[i].last_tx.tv_usec <  expire.tv_usec) ){
			printf("Timeout on sockets\n");
			close_proxy(&(tab->item[i]));
		}
	}		
	
}

struct pollfd *arrange_poll_write(int *clients){
	int i, k=0, s=0;
	struct pollfd *pfd;
	int filedesc[2*BUFSIZE+1];
	
	check_timeout();
	
	for(i=0; i<(2*BUFSIZE+1); i++){
		if(is_setbit(i,tab) && tab->item[i].status==PST_OPEN){
			//printf("FD: %d, pw:%d, pr:%d\n",tab->item[i].fd_in,tab->item[i].buf_out->pw,tab->item[i].buf_out->pr);
			if(tab->item[i].buf_out->pw > BSIZE || tab->item[i].buf_out->pw < 0)
				tab->item[i].buf_out->pr=tab->item[i].buf_out->pw=0;
			if(tab->item[i].buf_out->pr > tab->item[i].buf_out->pw){
				filedesc[k++]=tab->item[i].fd_in;
			}
			//printf("FD: %d, pw:%d, pr:%d\n",tab->item[i].fd_out,tab->item[i].buf_in->pw,tab->item[i].buf_in->pr);
			if(tab->item[i].buf_in->pw > BSIZE || tab->item[i].buf_in->pw < 0)
				tab->item[i].buf_in->pr=tab->item[i].buf_in->pw=0;
			if(tab->item[i].buf_in->pr > tab->item[i].buf_in->pw){
				filedesc[k++]=tab->item[i].fd_out;
			}
		}				
	}
	
	pfd=(struct pollfd *)calloc(sizeof(struct pollfd),k);
	for(i=0;i<k;i++){
			pfd[i].fd=filedesc[i];
			pfd[i].events=POLLOUT;
			//printf("Adding %d:\n",filedesc[i]);
	}
	//printf("Writing to %d sockets:\n",k);
	memcpy(clients,&k,sizeof(int));
	return pfd;
}
	
struct pollfd *arrange_poll(int *clients, int listenfd){
	int i, s=0, k=1;
	struct pollfd *pfd, filedes[2*BUFSIZE+1];
	
	check_timeout();
	
	for(i=0; i<(2*BUFSIZE+1); i++){
		if(is_setbit(i,tab)){
			if(tab->item[i].status == PST_OPEN){
				filedes[k].events=POLLIN|POLLNVAL|POLLHUP|POLLERR;
				filedes[k++].fd=tab->item[i].fd_in;
				filedes[k].events=POLLIN|POLLNVAL|POLLHUP|POLLERR;
				filedes[k++].fd=tab->item[i].fd_out;
			}else if( tab->item[i].status == PST_CONNECT){
				filedes[k].events=POLLOUT;
				filedes[k++].fd=tab->item[i].fd_out;
			}
		}
	}
				
	pfd=(struct pollfd *)calloc(sizeof(struct pollfd),k);
	pfd[0].fd=listenfd;
	pfd[0].events=POLLIN;
	for(i=1;i<k;i++){
			pfd[i].fd=filedes[i].fd;
			pfd[i].events=filedes[i].events;
	}
	memcpy(clients,&k,sizeof(int));
	return pfd;
}

void usage(char *name){
	fprintf(stderr,"Usage: %s [-v] [-d] [-q QUEUENUM] [-a address] [-h]\n", name);
	exit(0);
}

void setup_socket(int fd){
	struct timeval t={0,10000};
	fcntl(fd, F_SETFL, O_SYNC);
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(struct timeval));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &t, sizeof(struct timeval));
	if(DEBUG)
		printf("Socket %d: Setting up timeouts and syncronous mode.\n",fd);


}

/******* Main ********/

int main(int argc, char **argv)
{
	int  listenfd, connfd;
	int len;
	int  sd=-1;
	struct hostent *host;
	struct sockaddr_in servaddr_r;
	const int on = 1;
	int i,k=1;
	struct sockaddr_in cliaddr, servaddr;
	struct pollfd *pfd=NULL, *wpfd=NULL; 
	int poll_clients=1;
	struct sigaction sa1,sa2;
	int rr_pointer=1;
	int pos;
	int connerr,errlen;
	int io, o, n;
	struct p_descr *pd;
	struct p_buffer *mybuf, *other, *inbuf, *outbuf;


	//printf("Starting PEPsal\n");
	
	sigemptyset(&sa1.sa_mask);
	sigemptyset(&sa2.sa_mask);
	sa1.sa_flags = sa2.sa_flags = 0;
	
	sa1.sa_handler = sigchld_handler;
	sa2.sa_handler = goodbye;
	sigaction(SIGCHLD, &sa1, NULL);
	sigaction(SIGTERM, &sa2, NULL);
	sigaction(SIGSEGV, &sa2, NULL);
	
	/* Initialize pipe for new connections */
	if(pipe(conn_pipe) != 0){
		perror("pipe");
		exit(5);
	}
			
		

	/* option parsing */
	{
		int c;
		while (1) {
			int option_index = 0;

			static struct option long_options[] = {
				{"daemon", 1, 0, 'd'},
				{"verbose", 1, 0, 'v'},
				{"help",0,0,'h'},
				{"queue",1,0,'q'},
				{"port",1,0,'p'},
				{"version",0,0,'V'},
				{"address",1,0,'a'},
				{0, 0, 0, 0}
			};
			c = getopt_long (argc, argv, "dvVhq:p:a:",
					long_options, &option_index);
			if (c == -1)
				break;

			switch (c) {
				case 'd':
					background=1;
					break;
				case 'v':
					DEBUG=1;
					break;

				case 'h':
					usage(argv[0]); //implies exit
					break;

				case 'q':
					queuenum=atoi(optarg);
					break;
				case 'p':
					portnum=atoi(optarg);
					break;
				case 'a':
					strncpy(address,optarg,19);
					break;	
				case 'V':
					printf("PEPSal ver. %s\n",VERSION);
					exit(0);
			}
		}
	}
	
	if(background && fork()!=0)
		exit(0);
	

	/* Start queuer */
	qpid=fork();
	if (qpid==0){
		p_queuer(NULL);
		exit(0);
	}
	

	printf("Server is up\n");
	if(DEBUG){
		printf("Queuer process= %d\n",qpid);
	}
	

	/* Tcp socket creation and listen */
	listenfd=socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd <0)
	{
		perror("Open listen socket...ERROR"); exit(1);
	}

	if(DEBUG)
		printf ("Listening on %d:\n", listenfd);
	memset ((char *)&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(portnum);

	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))<0)
	{
		perror("set sockoptions TCP...ERROR"); exit(2);
	}
	if(DEBUG)
		printf ("setsockopt: Ok.\n");

	if (bind(listenfd,(struct sockaddr *) &servaddr, sizeof(servaddr))<0)
	{
		perror("bind socket TCP"); exit(3);
	}
	if(DEBUG)
		printf ("bind: Ok.\n");

// CLOSE - REBIND
#if 1
	close(listenfd);
	sleep(1);
	listenfd=socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd <0)
	{
		perror("Open listen socket...ERROR"); exit(1);
	}

	if(DEBUG)
		printf ("Listening on %d:\n", listenfd);
	memset ((char *)&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(portnum);

	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))<0)
	{
		perror("set sockoptions TCP...ERROR"); exit(2);
	}
	if(DEBUG)
		printf ("setsockopt: Ok.\n");

	if (bind(listenfd,(struct sockaddr *) &servaddr, sizeof(servaddr))<0)
	{
		perror("bind socket TCP"); exit(3);
	}
	if(DEBUG)
		printf ("bind: Ok.\n");

	//CLOSE-REBIND
#endif

	if (listen(listenfd, 60000)<0)
	{
		perror("listen"); exit(4);
	}
	if(DEBUG)
		printf ("listen: Ok.\n");




	
	
	tab=(struct syn_table *)get_syn_table(ST_ACCESS,0);
/*	for(i=0;i<BUFSIZE*2+1;i++){
		unset_bit(i,tab);
		tab->item[i].status=PST_CLOSED;
	}
	*/
	i=1;
	for(;;)
	{
		int pollret=-1;

startpoll:
		// READ 
		pfd=arrange_poll(&poll_clients,listenfd);
		pollret=poll(pfd,poll_clients,500);
		if(pollret<0){
			perror("poll");
			exit(19);
		}
		
		if(pollret==0){
			goto writer;
		}
		
		for(i=1;i<poll_clients;i++){			
			errlen=sizeof(int);
			pos=getpos(pfd[i].fd);
			pd=&(tab->item[pos]);
			switch (pd->status){
				case PST_CONNECT:
				{
					getsockopt(pd->fd_out,SOL_SOCKET,SO_ERROR,&connerr,&errlen);
					if(connerr!=0){
						perror ("getsockopt");
						goto startpoll;
					}
					
					if(DEBUG)
						printf("Socket %d connected:",pd->fd_out);
					pd->buf_in=(struct p_buffer*)malloc(sizeof (struct p_buffer));
					pd->buf_out=(struct p_buffer*)malloc(sizeof (struct p_buffer));
					pd->buf_in->pr = 0;
					pd->buf_in->pw = 0;
					pd->buf_out->pr = 0;
					pd->buf_out->pw = 0;
					pd->buf_in->tx_attempt=0;
					pd->buf_out->tx_attempt=0;
					gettimeofday(&(pd->last_tx),NULL);
					pd->status=PST_OPEN;
					if(DEBUG)
						printf("Transferring data.\n");
					if(DEBUG)
						printf("Adding 2 clients, fd=[%d,%d], numclients=%d\n",pd->fd_in, pd->fd_out, poll_clients+1);
					setup_socket(pd->fd_in);
					setup_socket(pd->fd_out);
					goto startpoll;
				}
				break;

				case PST_OPEN:
				{
					if((pfd[i].revents&POLLHUP)||(pfd[i].revents&POLLERR)||
						(pfd[i].revents&POLLNVAL)){
						
						if(DEBUG)
							printf("Connection closed: FD [%d,%d], numclients=%d\n",pd->fd_in, pd->fd_out, poll_clients);
						close_proxy(pd);
						goto startpoll;
						
					}
					inbuf=pd->buf_in;
					outbuf=pd->buf_out;
					if(pfd[i].fd == pd->fd_in) {
						mybuf = inbuf;
						other = outbuf;
					}
					else {
						mybuf = outbuf;
						other = inbuf;
					}
					

					// READ
					if ((pfd[i].revents&POLLIN)) {
					
						n=read(pfd[i].fd, mybuf->data - mybuf->pr, BSIZE - mybuf->pr);
						if (n<0 && errno != EAGAIN && errno != EWOULDBLOCK){
							if(DEBUG)
								perror("read");
							close_proxy(pd);
							goto startpoll;
						}
						else if (n==0){
							if(DEBUG)
								//printf("zero read\n");
							sync();
							if(mybuf->pr > mybuf->pw){
								goto writer;
							} else{
								close_proxy(pd);
								goto writer;
							}
						}
						else{
							mybuf->pr+=n;
							gettimeofday(&(pd->last_tx),NULL);
						}
					
					}
				}//CASE OPEN
			}//SWITCH
		}//FOR POLLCLIENTS
		
		
		
		/*** New Connection ***
		 * 
		 */
		if (pfd[0].revents==POLLIN){
		struct p_descr *pd;
		int pos,r;
		struct t_endpoint e_pattern;
		unsigned short tcpport_r;
		char remotehost[17];
		struct sockaddr_in my_name;
		int status;
		
		//rr_pointer++;			
		len = sizeof(struct sockaddr_in);
		connfd = accept(listenfd,(struct sockaddr *)&cliaddr,&len);
		if(connfd==-1){
			if(DEBUG)
				printf("ERESTSYS?\n");
			continue;
		}
			
		/* Create a fingerprint for the incoming connection */
		e_pattern.addr=ntohl(cliaddr.sin_addr.s_addr);
		e_pattern.p=ntohs(cliaddr.sin_port);
		/* Find a match in the ipquad array */
		pos=t_find(e_pattern,tab);
			if(pos>=0){
			pd=&(tab->item[pos]);
			set_bit(pos,tab);
			toip(remotehost,pd->proxy.d.addr);
			tcpport_r=pd->proxy.d.p;
			pd->status=PST_CONNECT;
			if(DEBUG)
				printf("Contacting host %s..\n",remotehost);
			}else{
				perror("Connection Abnormal Termination. Can't find your connection registration.\n");
			goto startpoll;
			}

			memset((char *)&servaddr_r, 0, sizeof(struct sockaddr_in));
			servaddr_r.sin_family = AF_INET;

			host = gethostbyname(remotehost);
			if (host == NULL)
			{
				perror("Failed gethostbyname  ");
				exit(2);
			}

			servaddr_r.sin_addr.s_addr=((struct in_addr*) (host->h_addr))->s_addr;
			servaddr_r.sin_port = htons(tcpport_r);


			pd->fd_out=socket(AF_INET, SOCK_STREAM, 0);
			if (pd->fd_out <0)
			{
				perror("Unable to open socket  "); exit(3);
			}
			
			if(poll_clients>2*BUFSIZE)
			{
				perror("Error. Cannot allocate more clients.");
			}

			fcntl(pd->fd_out, F_SETFL, O_NONBLOCK);
			
	    my_name.sin_family = AF_INET;
	    my_name.sin_addr.s_addr = inet_addr(address);
	    
	    my_name.sin_port = htons(0);
	        
	 status = bind(pd->fd_out, (struct sockaddr*)&my_name, sizeof(my_name));
	 if (status == -1)
	     {
	         perror("Binding error");
	         exit(1);
	             }
			
			
			
			r=connect(pd->fd_out,(struct sockaddr *)&servaddr_r, sizeof(struct sockaddr));

			pd->status=PST_CONNECT;
			pd->fd_in=connfd;
			if(DEBUG)
				printf("Restarting poll..\n");
			goto startpoll;		
		}
		//free(pfd);
		
		writer:
		// Write 
		wpfd=arrange_poll_write(&poll_clients);
		if (poll_clients > 0){
			pollret=poll(wpfd,poll_clients,500);
			if(pollret<0){
				perror("poll");
				exit(19);
			}
		
			for (i=0;i<poll_clients;i++){
				//printf("loop\n");
				errlen = sizeof(int);
				//printf("Getting position for %d\n",wpfd[i].fd);
				pos = getpos(wpfd[i].fd);
				pd = &(tab->item[pos]);
			//	if (pfd[i].revents&POLLOUT){
				//printf("loop core 1\n");
				inbuf=pd->buf_in;
				outbuf=pd->buf_out;
				if (wpfd[i].fd == pd->fd_in) {
					mybuf = inbuf;
					other = outbuf;
				} else {
					mybuf = outbuf;
					other = inbuf;
				}	
				// actual write()
				if ((other->pw <= BSIZE) && (other->pr > other->pw)){
					o=write(wpfd[i].fd, other->data+other->pw, other->pr - other->pw);
					if (o<0 && errno != EAGAIN && errno != EWOULDBLOCK){
						if (DEBUG)
							perror("write");
						close_proxy(pd);
						goto startpoll;
					}
					if (o>=0){
						//printf("Wrote %d bytes.\n",o);
						other->pw+=o;
						if(other->pw==other->pr){
							//printf("Reset to 0.\n");
							other->pw=0;
							other->pr=0;
						}
						other->tx_attempt=0;
						gettimeofday(&(pd->last_tx),NULL);
					}
					if (o<0 && errno == EAGAIN || errno == EWOULDBLOCK){
						other->tx_attempt++;
						if(other->tx_attempt >= TRANSMIT_RETRIES){
							//close 
							close_proxy(pd);
							goto startpoll;
						}
					}
				}
			}
		}// WRITE
//		if(DEBUG)
//				printf("Free wfd\n");
		free(wpfd);
		
//		if(DEBUG)
//				printf("Free pfd\n");
		free(pfd);
		 			
	}//INFINITE FOR
}// MAIN()
