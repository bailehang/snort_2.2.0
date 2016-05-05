/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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
/* $Id: spo_alert_syslog.c,v 1.38 2003/12/03 15:22:22 chris_reid Exp $ */

/* spo_alert_syslog 
 * 
 * Purpose:
 *
 * This module sends alerts to the syslog service.
 *
 * Arguments:
 *   
 * Logging mechanism?
 *
 * Effect:
 *
 * Alerts are written to the syslog service with in the facility indicated by
 * the module arguments.
 *
 * Comments:
 *
 * First try
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <syslog.h>
#include <stdlib.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* !WIN32 */

#include "decode.h"
#include "event.h"
#include "rules.h"
#include "plugbase.h"
#include "spo_plugbase.h"
#include "debug.h"
#include "parser.h"
#include "mstring.h"
#include "util.h"

#include "snort.h"

typedef struct _SyslogData
{
    int facility;
    int priority;
    int options;
} SyslogData;

void AlertSyslogInit(u_char *);
SyslogData *ParseSyslogArgs(char *);
void AlertSyslog(Packet *, char *, void *, Event *);
void AlertSyslogCleanExit(int, void *);
void AlertSyslogRestart(int, void *);



/*
 * Function: SetupSyslog()
 *
 * Purpose: Registers the output plugin keyword and initialization 
 *          function into the output plugin list.  This is the function that
 *          gets called from InitOutputPlugins() in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void AlertSyslogSetup(void)
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterOutputPlugin("alert_syslog", NT_OUTPUT_ALERT, AlertSyslogInit);
    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Output plugin: Alert-Syslog is setup...\n"););
}


/*
 * Function: AlertSyslogInit(u_char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
void AlertSyslogInit(u_char *args)
{
    SyslogData *data;
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output: Alert-Syslog Initialized\n"););

    pv.alert_plugin_active = 1;

    /* parse the argument list from the rules file */
    data = ParseSyslogArgs(args);

    openlog("snort", data->options, data->facility);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Linking syslog alert function to call list...\n"););

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(AlertSyslog, NT_OUTPUT_ALERT, data);
    AddFuncToCleanExitList(AlertSyslogCleanExit, data);
    AddFuncToRestartList(AlertSyslogRestart, data);
}



/*
 * Function: ParseSyslogArgs(char *)
 *
 * Purpose: Process the preprocessor arguements from the rules file and 
 *          initialize the preprocessor's data struct.  This function doesn't
 *          have to exist if it makes sense to parse the args in the init 
 *          function.
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 *
 */
SyslogData *ParseSyslogArgs(char *args)
{
#ifdef WIN32
    char *DEFAULT_SYSLOG_HOST = "127.0.0.1";
    int   DEFAULT_SYSLOG_PORT = 514;
    char **config_toks;
    char **host_toks;
    char  *host_string = args;
    int num_config_toks, num_host_toks;
#endif
    char **facility_toks;
    char  *facility_string = args;
    int num_facility_toks = 0;
    int i = 0;
    SyslogData *data;
    char *tmp;

    data = (SyslogData *)SnortAlloc(sizeof(SyslogData));

    /* default values for syslog output */
    data->options = 0;
    data->facility = LOG_AUTH;
    data->priority = LOG_INFO;

    if(args == NULL)
    {
        /* horrible kludge to catch default initialization */
        if(file_name != NULL)
        {            
            LogMessage("%s(%d) => No arguments to alert_syslog preprocessor!\n",
                    file_name, file_line);
        }

        return data;

    }

    /*
     * NON-WIN32:  Config should be in the format:
     *   output alert_syslog: LOG_AUTH LOG_ALERT
     * 
     * WIN32:  Config can be in any of these formats:
     *   output alert_syslog: LOG_AUTH LOG_ALERT
     *   output alert_syslog: host=hostname, LOG_AUTH LOG_ALERT
     *   output alert_syslog: host=hostname:port, LOG_AUTH LOG_ALERT
     */

#ifdef WIN32
    /* split the host/port part from the facilities/priorities part */
    config_toks = mSplit(args, ",", 2, &num_config_toks, '\\');
    switch( num_config_toks )
    {
        case 1:  /* config consists of only facility/priority info */
            LogMessage("alert_syslog output processor is defaulting to syslog "
                    "server on %s port %d!\n",
                    DEFAULT_SYSLOG_HOST, DEFAULT_SYSLOG_PORT);
            strncpy(pv.syslog_server, DEFAULT_SYSLOG_HOST, STD_BUF-1);
            pv.syslog_server_port = DEFAULT_SYSLOG_PORT;
            facility_string = config_toks[0];
            break;

        case 2:  /* config consists of host info, and facility/priority info */
            host_string     = config_toks[0];
            facility_string = config_toks[1];
            /* split host_string into "host" vs. "server" vs. "port" */
            host_toks = mSplit(host_string, "=:", 3, &num_host_toks, 0);
            if(num_host_toks > 0 && strcmp(host_toks[0], "host") != 0 )
            {
                FatalError("%s(%d) => Badly formed alert_syslog 'host' "
                        "argument ('%s')\n", 
                        file_name, file_line, host_string);
            }
            /* check for empty strings */
            if((num_host_toks >= 1 && strlen(host_toks[0]) == 0) ||
                    (num_host_toks >= 2 && strlen(host_toks[1]) == 0) ||
                    (num_host_toks >= 3 && strlen(host_toks[2]) == 0))
            {
                FatalError("%s(%d) => Badly formed alert_syslog 'host' "
                        "argument ('%s')\n", 
                        file_name, file_line, host_string);
            }
            switch(num_host_toks)
            {
                case 2:  /* ie,  host=localhost (defaults to port 514) */
                    strncpy(pv.syslog_server, host_toks[1], STD_BUF-1);
                    pv.syslog_server_port = DEFAULT_SYSLOG_PORT;  /* default */
                    break;

                case 3:  /* ie.  host=localhost:514 */
                    strncpy(pv.syslog_server, host_toks[1], STD_BUF-1);
                    pv.syslog_server_port = atoi(host_toks[2]);
                    if( pv.syslog_server_port == 0 )
                    {
                        pv.syslog_server_port = DEFAULT_SYSLOG_PORT; /*default*/
                        LogMessage("WARNING %s(%d) => alert_syslog port "
                                "appears to be non-numeric ('%s').  Defaulting " 
                                "to port %d!\n", file_name, file_line, 
                                host_toks[2], DEFAULT_SYSLOG_PORT);
                                
                    }
                    break;

                default:  /* badly formed, should never occur */
                    FatalError("%s(%d) => Badly formed alert_syslog 'host' "
                            "argument ('%s')\n", 
                            file_name, file_line, host_string);
            }
            mSplitFree(&host_toks, num_host_toks);
            break;

        default:
            FatalError("%s(%d) => Badly formed alert_syslog arguments ('%s')\n",
                    file_name, file_line, args);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Logging alerts to syslog "
                "server %s on port %d\n", pv.syslog_server, 
                pv.syslog_server_port););
    mSplitFree(&config_toks, num_facility_toks);
#endif /* WIN32 */



    /* tokenize the facility/priority argument list */
    facility_toks = mSplit(facility_string, " |", 31, &num_facility_toks, '\\');

    for(i = 0; i < num_facility_toks; i++)
    {
        if(*facility_toks[i] == '$')
        {
            if((tmp = VarGet(facility_toks[i]+1)) == NULL)
            {
                FatalError("%s(%d) => Undefined variable %s\n", 
                        file_name, file_line, facility_toks[i]);
            }
        }
        else
        {
            tmp = facility_toks[i];
        }

        /* possible openlog options */

#ifdef LOG_CONS 
        if(!strcasecmp("LOG_CONS", tmp))
        {
            data->options |= LOG_CONS;
        }
        else
#endif
#ifdef LOG_NDELAY 
        if(!strcasecmp("LOG_NDELAY", tmp))
        {
            data->options |= LOG_NDELAY;
        }
        else
#endif
#ifdef LOG_PERROR 
        if(!strcasecmp("LOG_PERROR", tmp))
        {
            data->options |= LOG_PERROR;
        }
        else
#endif
#ifdef LOG_PID 
        if(!strcasecmp("LOG_PID", tmp))
        {
            data->options |= LOG_PID;
        }
        else
#endif
#ifdef LOG_NOWAIT
        if(!strcasecmp("LOG_NOWAIT", tmp))
        {
            data->options |= LOG_NOWAIT;
        }
        else
#endif
        /* possible openlog facilities */

#ifdef LOG_AUTHPRIV 
        if(!strcasecmp("LOG_AUTHPRIV", tmp))
        {
            data->facility = LOG_AUTHPRIV;
        }
        else
#endif
#ifdef LOG_AUTH 
        if(!strcasecmp("LOG_AUTH", tmp))
        {
            data->facility = LOG_AUTH;
        }
        else
#endif
#ifdef LOG_DAEMON 
        if(!strcasecmp("LOG_DAEMON", tmp))
        {
            data->facility = LOG_DAEMON;
        }
        else
#endif
#ifdef LOG_LOCAL0 
        if(!strcasecmp("LOG_LOCAL0", tmp))
        {
            data->facility = LOG_LOCAL0;
        }
        else
#endif
#ifdef LOG_LOCAL1 
        if(!strcasecmp("LOG_LOCAL1", tmp))
        {
            data->facility = LOG_LOCAL1;
        }
        else
#endif
#ifdef LOG_LOCAL2 
        if(!strcasecmp("LOG_LOCAL2", tmp))
        {
            data->facility = LOG_LOCAL2;
        }
        else
#endif
#ifdef LOG_LOCAL3 
        if(!strcasecmp("LOG_LOCAL3", tmp))
        {
            data->facility = LOG_LOCAL3;
        }
        else
#endif
#ifdef LOG_LOCAL4 
        if(!strcasecmp("LOG_LOCAL4", tmp))
        {
            data->facility = LOG_LOCAL4;
        }
        else
#endif
#ifdef LOG_LOCAL5 
        if(!strcasecmp("LOG_LOCAL5", tmp))
        {
            data->facility = LOG_LOCAL5;
        }
        else
#endif
#ifdef LOG_LOCAL6 
        if(!strcasecmp("LOG_LOCAL6", tmp))
        {
            data->facility = LOG_LOCAL6;
        }
        else
#endif
#ifdef LOG_LOCAL7 
        if(!strcasecmp("LOG_LOCAL7", tmp))
        {
            data->facility = LOG_LOCAL7;
        }
        else
#endif
#ifdef LOG_USER 
        if(!strcasecmp("LOG_USER", tmp))
        {
            data->facility = LOG_USER;
        }
        else
#endif

        /* possible syslog priorities */

#ifdef LOG_EMERG 
        if(!strcasecmp("LOG_EMERG", tmp))
        {
            data->priority = LOG_EMERG;
        }
        else
#endif
#ifdef LOG_ALERT 
        if(!strcasecmp("LOG_ALERT", tmp))
        {
            data->priority = LOG_ALERT;
        }
        else
#endif
#ifdef LOG_CRIT 
        if(!strcasecmp("LOG_CRIT", tmp))
        {
            data->priority = LOG_CRIT;
        }
        else
#endif
#ifdef LOG_ERR 
        if(!strcasecmp("LOG_ERR", tmp))
        {
            data->priority = LOG_ERR;
        }
        else
#endif
#ifdef LOG_WARNING 
        if(!strcasecmp("LOG_WARNING", tmp))
        {
            data->priority = LOG_WARNING;
        }
        else
#endif
#ifdef LOG_NOTICE 
        if(!strcasecmp("LOG_NOTICE", tmp))
        {
            data->priority = LOG_NOTICE;
        }
        else
#endif
#ifdef LOG_INFO 
        if(!strcasecmp("LOG_INFO", tmp))
        {
            data->priority = LOG_INFO;
        }
        else
#endif
#ifdef LOG_DEBUG 
        if(!strcasecmp("LOG_DEBUG", tmp))
        {
            data->priority = LOG_DEBUG;
        }
        else
#endif
        {
            LogMessage("WARNING %s (%d) => Unrecognized syslog "
                    "facility/priority: %s\n",
                    file_name, file_line, tmp);
        }
    }
    mSplitFree(&facility_toks, num_facility_toks);

    return data;
}


/*
 * Function: PreprocFunction(Packet *)
 *
 * Purpose: Perform the preprocessor's intended function.  This can be
 *          simple (statistics collection) or complex (IP defragmentation)
 *          as you like.  Try not to destroy the performance of the whole
 *          system by trying to do too much....
 *
 * Arguments: p => pointer to the current packet data struct 
 *
 * Returns: void function
 *
 */
extern OptTreeNode *otn_tmp;
void AlertSyslog(Packet *p, char *msg, void *arg, Event *event)
{
    char sip[16];
    char dip[16];
    char pri_data[STD_BUF];
    char ip_data[STD_BUF];
    char event_data[STD_BUF];
#define SYSLOG_BUF  1024
    char event_string[SYSLOG_BUF];
    SyslogData *data = (SyslogData *)arg;


    bzero(event_string, SYSLOG_BUF);

    if(p && p->iph)
    {
        /*
         * have to do this since inet_ntoa is fucked up and writes to a static
         * memory location
         */
        strlcpy(sip, inet_ntoa(p->iph->ip_src), 16);
        strlcpy(dip, inet_ntoa(p->iph->ip_dst), 16);

        if(event != NULL)
        {
            snprintf(event_data, STD_BUF-1, "[%lu:%lu:%lu] ", 
                    (unsigned long) event->sig_generator,
                    (unsigned long) event->sig_id, 
                    (unsigned long) event->sig_rev);
            strlcat(event_string, event_data, SYSLOG_BUF);
        }

        if(msg != NULL)
        {
            strlcat(event_string, msg, SYSLOG_BUF);
        }
        else
        {
            strlcat(event_string, "ALERT", SYSLOG_BUF);
        }

        if(otn_tmp != NULL)
        {
            if(otn_tmp->sigInfo.classType)
            {
                snprintf(pri_data, STD_BUF-1, " [Classification: %s] "
                        "[Priority: %d]:", otn_tmp->sigInfo.classType->name,
                        otn_tmp->sigInfo.priority); 
                strlcat(event_string, pri_data, SYSLOG_BUF);
            }
            else if(otn_tmp->sigInfo.priority != 0)
            {
                snprintf(pri_data, STD_BUF-1, "[Priority: %d]:", 
                        otn_tmp->sigInfo.priority); 
                strlcat(event_string, pri_data, SYSLOG_BUF);
            }
        }

        if((p->iph->ip_proto != IPPROTO_TCP &&
                    p->iph->ip_proto != IPPROTO_UDP) || 
                p->frag_flag)
        {
            if(!pv.alert_interface_flag)
            {
                snprintf(ip_data, STD_BUF-1, " {%s} %s -> %s",  
                        protocol_names[p->iph->ip_proto], sip, dip);
            }
            else
            {
                snprintf(ip_data, STD_BUF-1, " <%s> {%s} %s -> %s",  
                        PRINT_INTERFACE(pv.interface), 
                        protocol_names[p->iph->ip_proto], 
                        sip, dip);
            }
        }
        else
        {
            if(pv.alert_interface_flag)
            {
                snprintf(ip_data, STD_BUF-1, " <%s> {%s} %s:%i -> %s:%i",
                        PRINT_INTERFACE(pv.interface), 
                        protocol_names[p->iph->ip_proto], sip,
                        p->sp, dip, p->dp);
            }
            else
            {
                snprintf(ip_data, STD_BUF-1, " {%s} %s:%i -> %s:%i",
                        protocol_names[p->iph->ip_proto], sip, p->sp, 
                        dip, p->dp);
            }
        }

        strlcat(event_string, ip_data, SYSLOG_BUF);

        syslog(data->priority, "%s", event_string);

    }
    else  
    {
        syslog(data->priority, "%s", msg == NULL ? "ALERT!" : msg);
    }

    return;

}


void AlertSyslogCleanExit(int signal, void *arg)
{
    SyslogData *data = (SyslogData *)arg;
    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "AlertSyslogCleanExit\n"););
    /* free memory from SyslogData */
    free(data);
}

void AlertSyslogRestart(int signal, void *arg)
{
    SyslogData *data = (SyslogData *)arg;
    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "AlertSyslogRestartFunc\n"););
    /* free memory from SyslogData */
    free(data);
}
