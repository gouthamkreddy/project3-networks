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

#define RECEIVER_WINDOW 3072

enum { CSTATE_ESTABLISHED };    /* you should have more states */


/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;
    tcp_seq server_sequence_num;
    tcp_seq client_sequence_num;
    int server_window_size;
    int client_window_size;
    tcp_seq current_sequence_num;

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
    tcphdr *tcp_hdr;
    int send_pkt, recv_pkt;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    tcp_hdr = (tcphdr *) calloc(1, sizeof(tcphdr));
    
    assert(ctx);
    assert(tcp_hdr);

    generate_initial_seq_num(ctx);

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */

    if(is_active)
    {
        /*--- SYN Packet ---*/
        tcp_hdr->th_seq = ctx->initial_sequence_num;
        tcp_hdr->th_off = 5;
        tcp_hdr->th_flags |= TH_SYN;
        tcp_hdr->th_win = RECEIVER_WINDOW;
        ctx->current_sequence_num++;
        
        send_pkt = stcp_network_send(sd, tcp_hdr, sizeof(tcphdr), NULL);
        printf("SYN Packet send");

        /*--- SYN-ACK Packet ---*/
        // unsigned int ret_pkt = stcp_wait_for_event(sd, stcp_event_type_t NETWORK_DATA, NULL);
        bzero((tcphdr *)tcp_hdr, sizeof(tcphdr));
        recv_pkt = stcp_network_recv(sd, tcp_hdr, sizeof(tcphdr));
        printf("SYN-ACK Packet received");
        if ((tcp_hdr->th_flags & TH_ACK) && (tcp_hdr->th_ack == ctx->current_sequence_number))
        {
            ctx->server_sequence_num = tcp_hdr->th_seq;
            ctx->server_window_size = tcp_hdr->th_win;
            
            /*--- ACK Packet ---*/
            bzero((tcphdr *)tcp_hdr, sizeof(tcphdr));
            tcp_hdr->th_seq = ctx->current_sequence_num;
            tcp_hdr->th_ack = ctx->server_sequence_num + 1;
            tcp_hdr->th_off = 5;
            tcp_hdr->th_flags |= TH_ACK;
            // tcp_hdr->th_win = RECEIVER_WINDOW + ;
            ctx->current_sequence_num++;
            send_pkt = stcp_network_send(sd, tcp_hdr, sizeof(tcphdr), NULL);
        }


    }
    else
    {
        recv_pkt = stcp_network_recv(sd, tcp_hdr, sizeof(tcphdr));
        ctx->client_sequence_num = tcp_hdr->th_seq;
        ctx->client_window_size = tcp_hdr->th_win;
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
    int r = rand() % 256;
    ctx->initial_sequence_num = r;
    ctx->current_sequence_number = ctx->initial_sequence_num;
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
        event = stcp_wait_for_event(sd, 0, NULL);

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
        {
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
        }

        /* etc. */
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



