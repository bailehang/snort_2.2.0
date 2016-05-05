/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**           (C) 2002 Sourcefire, Inc.
**
** Author(s):   Martin Roesch <roesch@sourcefire.com>
**              Andrew R. Baker <andrewb@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/
/* $Id: spo_log_ascii.c,v 1.14 2003/10/20 15:03:35 chrisgreen Exp $ */

/* spo_log_ascii
 * 
 * Purpose:
 *
 * This output module provides the default packet logging funtionality
 *
 * Arguments:
 *   
 * None.
 *
 * Effect:
 *
 * None.
 *
 * Comments:
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* ! WIN32 */

#include "plugbase.h"
#include "spo_plugbase.h"
#include "parser.h"
#include "debug.h"
#include "decode.h"
#include "event.h"
#include "log.h"
#include "util.h"

#include "snort.h"

/* external globals from rules.c */
extern OptTreeNode *otn_tmp;

/* internal functions */
void LogAsciiInit(u_char *args);
void LogAscii(Packet *p, char *msg, void *arg, Event *event);
void LogAsciiCleanExit(int signal, void *arg);
void LogAsciiRestart(int signal, void *arg);
char *IcmpFileName(Packet * p);
static FILE *OpenLogFile(int mode, Packet * p);


#define DUMP              1
#define BOGUS             2
#define NON_IP            3
#define ARP               4
#define GENERIC_LOG   5

void LogAsciiSetup()
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterOutputPlugin("log_ascii", NT_OUTPUT_LOG, LogAsciiInit);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Output: LogAscii is setup\n"););
}

void LogAsciiInit(u_char *args)
{
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Output: Ascii logging initialized\n"););

    pv.log_plugin_active = 1;

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(LogAscii, NT_OUTPUT_LOG, NULL);
    AddFuncToCleanExitList(LogAsciiCleanExit, NULL);
    AddFuncToRestartList(LogAsciiRestart, NULL);
}



void LogAscii(Packet *p, char *msg, void *arg, Event *event)
{
    FILE *log_ptr = NULL;
    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "LogPkt started\n"););
    if(p)
    { 
        if(p->iph)
            log_ptr = OpenLogFile(0, p);
        else if(p->ah)
            log_ptr = OpenLogFile(ARP, p);
        else
            log_ptr = OpenLogFile(NON_IP, p);
    }
    else
        log_ptr = OpenLogFile(GENERIC_LOG, p);

    if(!log_ptr)
        FatalError("Unable to open packet log file\n");
    
    if(msg)
    {
        fwrite("[**] ", 5, 1, log_ptr);
        fwrite(msg, strlen(msg), 1, log_ptr);
        fwrite(" [**]\n", 6, 1, log_ptr);
    }
    if(p)
    {
        if(p->iph)
            PrintIPPkt(log_ptr, p->iph->ip_proto, p);
        else if(p->ah)
            PrintArpHeader(log_ptr, p);
    }
    if(log_ptr)
        fclose(log_ptr);
}


void LogAsciiCleanExit(int signal, void *arg)
{
    return;
}

void LogAsciiRestart(int signal, void *arg)
{
    return;
}

static char *logfile[] =
        { "", "PACKET_FRAG", "PACKET_BOGUS", "PACKET_NONIP", "ARP", "log" };

/*
 * Function: OpenLogFile()
 *
 * Purpose: Create the log directory and file to put the packet log into.
 *          This function sucks, I've got to find a better way to do this
 *          this stuff.
 *
 * Arguments: None.
 *
 * Returns: FILE pointer on success, else NULL
 */
FILE *OpenLogFile(int mode, Packet * p)
{
    char log_path[STD_BUF+1]; /* path to log file */
    char log_file[STD_BUF+1]; /* name of log file */
    char proto[5];      /* logged packet protocol */
    char suffix[5];     /* filename suffix */
    FILE *log_ptr = NULL;
#ifdef WIN32
    strcpy(suffix,".ids");
#else
    suffix[0] = '\0';
#endif

    /* zero out our buffers */
    bzero((char *) log_path, STD_BUF + 1);
    bzero((char *) log_file, STD_BUF + 1);
    bzero((char *) proto, 5);

    if(mode == GENERIC_LOG || mode == DUMP || mode == BOGUS ||
            mode == NON_IP || mode == ARP)
    {
        snprintf(log_file, STD_BUF, "%s/%s", pv.log_dir, logfile[mode]);

        if(!(log_ptr = fopen(log_file, "a")))
        {
            FatalError("OpenLogFile() => fopen(%s) log file: %s\n",
                       log_file, strerror(errno));
        }
        return log_ptr;
    }

    if(otn_tmp != NULL)
    {
        if(otn_tmp->logto != NULL)
        {
            snprintf(log_file, STD_BUF, "%s/%s", pv.log_dir, otn_tmp->logto);

            if(!(log_ptr = fopen(log_file, "a")))
            {
                FatalError("OpenLogFile() => fopen(%s) log file: %s\n", 
                           log_file, strerror(errno));
            }
            return log_ptr;
        }
    }
    /* figure out which way this packet is headed in relation to the homenet */
    if((p->iph->ip_dst.s_addr & pv.netmask) == pv.homenet)
    {
        if((p->iph->ip_src.s_addr & pv.netmask) != pv.homenet)
        {
            snprintf(log_path, STD_BUF, "%s/%s", pv.log_dir, 
                    inet_ntoa(p->iph->ip_src));
        }
        else
        {
            if(p->sp >= p->dp)
            {
                snprintf(log_path, STD_BUF, "%s/%s", pv.log_dir, 
                        inet_ntoa(p->iph->ip_src));
            }
            else
            {
                snprintf(log_path, STD_BUF, "%s/%s", pv.log_dir, 
                        inet_ntoa(p->iph->ip_dst));
            }
        }
    }
    else
    {
        if((p->iph->ip_src.s_addr & pv.netmask) == pv.homenet)
        {
            snprintf(log_path, STD_BUF, "%s/%s", pv.log_dir, 
                    inet_ntoa(p->iph->ip_dst));
        }
        else
        {
            if(p->sp >= p->dp)
            {
                snprintf(log_path, STD_BUF, "%s/%s", pv.log_dir, 
                        inet_ntoa(p->iph->ip_src));
            }
            else
            {
                snprintf(log_path, STD_BUF, "%s/%s", pv.log_dir, 
                        inet_ntoa(p->iph->ip_dst));
            }
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_FLOW, "Creating directory: %s\n", log_path););

    /* build the log directory */
    if(mkdir(log_path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH))
    {

        if(errno != EEXIST)
        {
            FatalError("OpenLogFile() => mkdir(%s) log directory: %s\n",
                       log_path, strerror(errno));
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_FLOW, "Directory Created!\n"););

    /* build the log filename */
    if(p->iph->ip_proto == IPPROTO_TCP ||
            p->iph->ip_proto == IPPROTO_UDP)
    {
        if(p->frag_flag)
        {
            snprintf(log_file, STD_BUF, "%s/IP_FRAG%s", log_path, suffix);
        }
        else
        {
            if(p->sp >= p->dp)
            {
#ifdef WIN32
                snprintf(log_file, STD_BUF, "%s/%s_%d-%d%s", log_path,
                        protocol_names[p->iph->ip_proto], p->sp, p->dp, suffix);
#else
                snprintf(log_file, STD_BUF, "%s/%s:%d-%d%s", log_path,
                        protocol_names[p->iph->ip_proto], p->sp, p->dp, suffix);
#endif
            }
            else
            {
#ifdef WIN32
                snprintf(log_file, STD_BUF, "%s/%s_%d-%d%s", log_path,
                        protocol_names[p->iph->ip_proto], p->dp, p->sp, suffix);
#else
                snprintf(log_file, STD_BUF, "%s/%s:%d-%d%s", log_path,
                        protocol_names[p->iph->ip_proto], p->dp, p->sp, suffix);
#endif
            }
        }
    }
    else
    {
        if(p->frag_flag)
        {
            snprintf(log_file, STD_BUF, "%s/IP_FRAG%s", log_path, suffix);
        }
        else
        {
            if(p->iph->ip_proto == IPPROTO_ICMP)
            {
                snprintf(log_file, STD_BUF, "%s/%s_%s%s", log_path, "ICMP",
                         IcmpFileName(p), suffix);
            }
            else
            {
                snprintf(log_file, STD_BUF, "%s/PROTO%d%s", log_path,
                         p->iph->ip_proto, suffix);
            }
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_FLOW, "Opening file: %s\n", log_file););

    /* finally open the log file */
    if(!(log_ptr = fopen(log_file, "a")))
    {
        FatalError("OpenLogFile() => fopen(%s) log file: %s\n",
                   log_file, strerror(errno));
    }

    DEBUG_WRAP(DebugMessage(DEBUG_FLOW, "File opened...\n"););
    return log_ptr;
}



/****************************************************************************
 *
 * Function: IcmpFileName(Packet *p)
 *
 * Purpose: Set the filename of an ICMP output log according to its type
 *
 * Arguments: p => Packet data struct
 *
 * Returns: the name of the file to set
 *
 ***************************************************************************/
char *IcmpFileName(Packet * p)
{
    if(p->icmph == NULL)
    {
        return "ICMP_TRUNC";
    }

    switch(p->icmph->type)
    {
        case ICMP_ECHOREPLY:
            return "ECHO_REPLY";

        case ICMP_DEST_UNREACH:
            switch(p->icmph->code)
            {
                case ICMP_NET_UNREACH:
                    return "NET_UNRCH";

                case ICMP_HOST_UNREACH:
                    return "HST_UNRCH";

                case ICMP_PROT_UNREACH:
                    return "PROTO_UNRCH";

                case ICMP_PORT_UNREACH:
                    return "PORT_UNRCH";

                case ICMP_FRAG_NEEDED:
                    return "UNRCH_FRAG_NEEDED";

                case ICMP_SR_FAILED:
                    return "UNRCH_SOURCE_ROUTE_FAILED";

                case ICMP_NET_UNKNOWN:
                    return "UNRCH_NETWORK_UNKNOWN";

                case ICMP_HOST_UNKNOWN:
                    return "UNRCH_HOST_UNKNOWN";

                case ICMP_HOST_ISOLATED:
                    return "UNRCH_HOST_ISOLATED";

                case ICMP_PKT_FILTERED_NET:
                    return "UNRCH_PKT_FILTERED_NET";

                case ICMP_PKT_FILTERED_HOST:
                    return "UNRCH_PKT_FILTERED_HOST";

                case ICMP_NET_UNR_TOS:
                    return "UNRCH_NET_UNR_TOS";

                case ICMP_HOST_UNR_TOS:
                    return "UNRCH_HOST_UNR_TOS";

                case ICMP_PKT_FILTERED:
                    return "UNRCH_PACKET_FILT";

                case ICMP_PREC_VIOLATION:
                    return "UNRCH_PREC_VIOL";

                case ICMP_PREC_CUTOFF:
                    return "UNRCH_PREC_CUTOFF";

                default:
                    return "UNKNOWN";

            }

        case ICMP_SOURCE_QUENCH:
            return "SRC_QUENCH";

        case ICMP_REDIRECT:
            return "REDIRECT";

        case ICMP_ECHO:
            return "ECHO";

        case ICMP_TIME_EXCEEDED:
            return "TTL_EXCEED";

        case ICMP_PARAMETERPROB:
            return "PARAM_PROB";

        case ICMP_TIMESTAMP:
            return "TIMESTAMP";

        case ICMP_TIMESTAMPREPLY:
            return "TIMESTAMP_RPL";

        case ICMP_INFO_REQUEST:
            return "INFO_REQ";

        case ICMP_INFO_REPLY:
            return "INFO_RPL";

        case ICMP_ADDRESS:
            return "ADDR";

        case ICMP_ADDRESSREPLY:
            return "ADDR_RPL";

        default:
            return "UNKNOWN";
    }
}


