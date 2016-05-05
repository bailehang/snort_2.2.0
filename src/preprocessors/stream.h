#ifndef __STREAM_H__
#define __STREAM_H__

#include "snort_packet_header.h"
#include "ubi_SplayTree.h"

/* Session flags for stream4 data */
#define SSNFLAG_SEEN_CLIENT         0x00000001
#define SSNFLAG_SEEN_SERVER         0x00000002
#define SSNFLAG_ESTABLISHED         0x00000004
#define SSNFLAG_NMAP                0x00000008
#define SSNFLAG_ECN_CLIENT_QUERY    0x00000010
#define SSNFLAG_ECN_SERVER_REPLY    0x00000020
#define SSNFLAG_HTTP_1_1            0x00000040 /* has this stream seen HTTP 1.1? */
#define SSNFLAG_SEEN_PMATCH         0x00000080 /* has this stream seen
						                          pattern match? */
#define SSNFLAG_MIDSTREAM           0x00000100 /* picked up midstream */
#define SSNFLAG_CLIENT_FIN          0x00000200 /* server sent fin */
#define SSNFLAG_SERVER_FIN          0x00000400 /* client sent fin */
#define SSNFLAG_ALL                 0xFFFFFFFF /* all that and a bag of chips */

typedef struct _Stream
{
    u_int32_t ip;          /* IP addr */
    u_int16_t port;        /* port number */
    u_int8_t  state;       /* stream state */
    u_int32_t isn;         /* initial sequence number */
    u_int32_t base_seq;    /* base seq num for this packet set */
    u_int32_t last_ack;    /* last segment ack'd */
    u_int16_t win_size;    /* window size */
    u_int32_t next_seq;    /* next sequence we expect to see -- used on reassemble */
    u_int32_t pkts_sent;   /* track the number of packets in this stream */
    u_int32_t bytes_sent;  /* track the number of bytes in this stream */
    u_int32_t bytes_tracked; /* track the total number of bytes on this side */
    u_int8_t  state_queue;    /* queued state transition */
    u_int8_t  expected_flags; /* tcp flag needed to accept transition */
    u_int32_t trans_seq;      /* sequence number of transition packet */
    u_int8_t  stq_chk_seq;    /* flag to see if we need to check the seq 
                                 num of the state transition packet */
    ubi_trRoot data;
} Stream;

typedef struct _Session
{
    ubi_trNode Node;   /* Record keeper for the ubx stuff */

    Stream server;
    Stream client;
    
    u_int32_t start_time;   /* unix second the session started */
    u_int32_t last_session_time; /* last time this session got a packet */
    
    u_int32_t session_flags; /* special little flags we keep */
    u_int32_t http_alert_flags;

    u_int8_t flush_point;
    u_int8_t ttl; /* track the ttl of this current session ( only done on client side ) */
} Session;

/* used for the StreamPacketData chuck field */
#define SEG_UNASSEMBLED 0x00
#define SEG_FULL        0x01
#define SEG_PARTIAL     0x02

typedef struct _StreamPacketData
{
    ubi_trNode Node;
    u_int8_t *pkt;
    u_int8_t *payload;
    SnortPktHeader pkth;
    u_int32_t seq_num;
    u_int16_t payload_size;
    u_int16_t pkt_size;
    u_int32_t cksum;
    u_int8_t  chuck;   /* mark the spd for chucking if it's 
                        * been reassembled 
                        */
} StreamPacketData;


#endif  // __STREAM_H__
