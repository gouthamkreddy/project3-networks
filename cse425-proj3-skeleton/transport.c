/*
 * transport.c 
 *
 *	Project 3		
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"

// Page 20 of RFC
enum { CSTATE_ESTABLISHED, FIN_RCVD, FIN_SENT, CLOSE};    /* you should have more states */


/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;

	tcp_seq current_ack; 
	tcp_seq last_acked;
	tcp_seq fin_seq;
    /* any other connection-wide global variables go here */
} context_t;


static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);


/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);
	ctx->fin_seq = 0;
    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */

	if(is_active) {
		//send SYN packet
		tcphdr* syn1 = (tcphdr*)malloc(sizeof(tcphdr));
		syn1->th_seq = ctx->initial_sequence_num++;
		syn1->th_ack = 0;
		syn1->th_off = 5;
		syn1->th_flags = TH_SYN;
		syn1->th_win = 3072;
		int err = stcp_network_send(sd, syn1, sizeof(tcphdr), NULL);
		if(err==-1){
			errno = ECONNREFUSED;
			printf("nw send error-1");}
		tcphdr *syn_ack = (tcphdr*)malloc(sizeof(tcphdr));
		int len = stcp_network_recv(sd, syn_ack, sizeof(tcphdr));
		if(len==-1 || syn_ack->th_flags!=(TH_SYN|TH_ACK) || syn_ack->th_ack!=ctx->initial_sequence_num) {
			errno = ECONNREFUSED;
			printf("nw rcv error-1");
		}
		
		tcphdr* ack = (tcphdr*)malloc(sizeof(tcphdr));
		ack->th_seq = ctx->initial_sequence_num++;
		ack->th_ack = syn_ack->th_seq+1;
		ack->th_off = 5;
		ack->th_flags = TH_ACK;
		ack->th_win = 3072;
		err= stcp_network_send(sd, ack, sizeof(tcphdr), NULL);
		if(err==-1) {
			errno = ECONNREFUSED;
			printf("nw send error-2");}	
		ctx->current_ack = ack->th_ack;
		ctx->last_acked = syn_ack->th_ack;
	
	}
	else {
		tcphdr *recv_syn = (tcphdr*)malloc(sizeof(tcphdr));
		tcphdr* recv_ack = (tcphdr*)malloc(sizeof(tcphdr));
		int len1, len2;
		len1 = stcp_network_recv(sd, recv_syn, sizeof(tcphdr));
		if(len1==-1 || recv_syn->th_flags!=TH_SYN) {
			errno = ECONNREFUSED;
			printf("nw rcv error-2");
		}
		tcphdr* syn2 = (tcphdr*)malloc(sizeof(tcphdr));
		syn2->th_seq = ctx->initial_sequence_num++;
		syn2->th_ack = recv_syn->th_seq+1;
		syn2->th_off = 5;
		syn2->th_flags = TH_SYN | TH_ACK;
		syn2->th_win = 3072;
		int err = stcp_network_send(sd, syn2, sizeof(tcphdr), NULL);
		if(err==-1) {
			errno = ECONNREFUSED;
			printf("nw send error-3");}
	
		len2 = stcp_network_recv(sd, recv_ack, sizeof(tcphdr));
		if(len2==-1 || recv_ack->th_flags!=TH_ACK || recv_ack->th_seq!=syn2->th_ack || recv_ack->th_ack!=ctx->initial_sequence_num) {
			errno = ECONNREFUSED;
			printf("nw rcv error-3");
		}
		ctx->last_acked = recv_ack->th_ack;
		ctx->current_ack = syn2->th_ack;
	}

    ctx->connection_state = CSTATE_ESTABLISHED;
    stcp_unblock_application(sd);

    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* you have to fill this up */
    ctx->initial_sequence_num = rand()%256;
#endif
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);
    assert(!ctx->done);

    while (!ctx->done)
    {
        unsigned int event;
	
        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, 1|2|4, NULL);
	printf("event: %d\n", event);
        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
        {
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
		int len_appdata, len_network;
		int sender_win = 3072-(ctx->initial_sequence_num - ctx->last_acked);
		//printf("sender wind: %d\n", sender_win);
		//printf("new seq no: %d\n", ctx->initial_sequence_num);
		//printf("last acked: %d\n", ctx->last_acked);
		char* recv_appdata = (char*)malloc(sender_win*sizeof(char));
		len_appdata = stcp_app_recv(sd, recv_appdata, sender_win);
		printf("len appdata: %d\n", len_appdata);
		
		if(sender_win > 0) {
			while(len_appdata!=0) {
				tcphdr* data = (tcphdr*)malloc(sizeof(tcphdr));
				data->th_seq = ctx->initial_sequence_num;
				if(len_appdata>536) {
					len_network = 536;
					len_appdata = len_appdata-536;
				}	
				else {
					len_network = len_appdata;
					len_appdata = 0;
				}
				ctx->initial_sequence_num += len_network;
				data->th_ack = ctx->current_ack;
				data->th_off = 5;
				data->th_flags = TH_ACK;
				data->th_win = 3072;
				char send_network[538];
				strncpy(send_network, recv_appdata, len_network);
				recv_appdata = recv_appdata + len_network;
				int err = stcp_network_send(sd, data, sizeof(tcphdr), send_network , len_network, NULL);
				if(err==-1)
					printf("Cannot send data to network layer");
			}
		}
        }
	if(event & NETWORK_DATA) {
		char *net_data = (char*)malloc(sizeof(tcphdr) + 536*sizeof(char));
		tcphdr* hdr = (tcphdr*)malloc(sizeof(tcphdr));	
		int len_net, len_data, bytes_to_buffer;
		len_net = stcp_network_recv(sd, net_data, sizeof(tcphdr)+536);
		
		hdr = (tcphdr*) net_data;
		char *data = (char*)malloc(538*sizeof(char));
		len_data = len_net-sizeof(tcphdr);               ////does it ensure 0<=len_data<=536 ??
		if(len_data==-20) {
			ctx->connection_state=CLOSE;
		}		
		printf("len data: %d\n", len_data);
		printf("current ack: %d\n", ctx->current_ack);
		if(len_data>0) {
		//send data to app
			data = net_data+hdr->th_off*sizeof(uint32_t);
			/*if((net_data->th_seq>=ctx->current_ack && net_data->th_seq<=ctx->current_ack+3072-1) {
				bytes_to_buffer = MIN(ctx->current_ack+3072-net_data->th_seq,len_data);
				if(net_data->th_seq==ctx->current_ack)
					ctx->current_ack += len_data;		
			else if ( net_data->th_seq<=ctx->current_ack && net_data->th_seq + len_data-1 >= ctx->current_ack)) {
				bytes_to_buffer = net_data->th_seq - ctx->current_ack+len_data;
				data = data + ctx->current_ack-net_data->th_seq;
				ctx->current_ack = 
			}*/
			ctx->current_ack += len_data;
			stcp_app_send(sd, data, len_data);
			tcphdr* data_ack = (tcphdr*)malloc(sizeof(tcphdr));          //do we need to send ack to network here??
			data_ack->th_seq = ctx->initial_sequence_num++;
			data_ack->th_ack = ctx->current_ack;
			data_ack->th_off = 5;
			data_ack->th_flags = TH_ACK;
			data_ack->th_win = 3072;
			stcp_network_send(sd, data_ack, sizeof(tcphdr), NULL);
		}
		if(hdr->th_flags==TH_ACK) {
			if(len_data==0)
				ctx->current_ack ++;
			ctx->last_acked = hdr->th_ack;
			printf("inside ack.....hdr seq: %d, hdr acked:%d\n", hdr->th_seq, hdr->th_ack);
			
			if(hdr->th_ack==ctx->fin_seq) {
				if(ctx->connection_state == FIN_RCVD)
					ctx->connection_state = CLOSE;
				else
					ctx->connection_state = FIN_SENT;
			}
		}
		if(hdr->th_flags==TH_FIN) {                            //what if it also contains ack flag??
			stcp_fin_received(sd);	
			if(len_data==0)
				ctx->current_ack ++;	
			if(ctx->connection_state == FIN_SENT)
				ctx->connection_state = CLOSE;
			else 
				ctx->connection_state = FIN_RCVD;
			tcphdr* fin_ack = (tcphdr*)malloc(sizeof(tcphdr));          //do we need to send ack to network here??
			fin_ack->th_seq = ctx->initial_sequence_num++;
			fin_ack->th_ack = ctx->current_ack;
			fin_ack->th_off = 5;
			fin_ack->th_flags = TH_ACK;
			fin_ack->th_win = 3072;
			stcp_network_send(sd, fin_ack, sizeof(tcphdr), NULL);
				
		}
		
		printf("connection_state: %d\n", ctx->connection_state);
	}
	if(event & APP_CLOSE_REQUESTED) {
		tcphdr* fin = (tcphdr*)malloc(sizeof(tcphdr));          //do we need to send ack to network here??
		fin->th_seq = ctx->initial_sequence_num++;
		fin->th_ack = ctx->current_ack;
		fin->th_off = 5;
		fin->th_flags = TH_FIN;
		fin->th_win = 3072;
		ctx->fin_seq = fin->th_seq;
		printf("fin seq: %d\n", ctx->fin_seq);
		stcp_network_send(sd, fin, sizeof(tcphdr), NULL);
	}

        /* etc. */
	if(ctx->connection_state == CLOSE)
		ctx->done = 1;
    }
}


/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}



