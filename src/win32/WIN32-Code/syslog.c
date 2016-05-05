/* $Id: syslog.c,v 1.9 2004/01/23 08:04:24 chris_reid Exp $ */
/* -/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/
 . Copyright (c) 2001 Michael Davis <mike@datanerds.net>
 . All rights reserved.
 .
 . Redistribution and use in source and binary forms, with or without
 . modification, are permitted provided that the following conditions
 . are met:
 .
 . 1. Redistributions of source code must retain the above copyright
 .    notice, this list of conditions and the following disclaimer.
 .
 . 2. Redistributions in binary form must reproduce the above copyright
 .    notice, this list of conditions and the following disclaimer in the
 .    documentation and/or other materials provided with the distribution.
 .
 . 3. The name of author may not be used to endorse or promote products
 .    derived from this software without specific prior written permission.
 .
 . THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 . INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 . AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 . THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 . EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 . PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 . OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 . WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 . OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 . ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 . -\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\ */

#define _WINSOCKAPI_   /* Prevent inclusion of winsock.h in windows.h */
#include <windows.h>
#include <stdio.h>
#include <time.h>
#include "name.h"
#include "syslog.h"

#include "snort.h"
#include "util.h"

#define TBUF_LEN        2048
#define FMT_LEN         1024
#define INTERNALLOG     LOG_ERR|LOG_CONS|LOG_PERROR|LOG_PID

static int      LogFile = -1;           /* fd for log */
static int      opened;                 /* have done openlog() */
static int      LogStat = 0;            /* status bits, set by openlog() */
static char *LogTag = NULL;       /* string to tag the entry with */
static int      LogFacility = LOG_USER; /* default facility code */
static int      LogMask = 0xff;         /* mask of priorities to be logged */

void syslog(int pri, char *fmt, ...)
{
        va_list ap;
        va_start(ap, fmt);
        vsyslog(pri, fmt, ap);
        va_end(ap);
}

void vsyslog(int pri, char *fmt, va_list ap){
	char ch, *p, *t;
	register int cnt;
	int tbuf_left, fmt_left, prlen, saved_errno;
	char *stdp, tbuf[TBUF_LEN], fmt_cpy[FMT_LEN];
    time_t now;
	SOCKET sockfd;
	struct sockaddr_in sin;
	HANDLE	hEventLog;				/* handle to the Event Log. */

	if(!pv.syslog_remote_flag) { /* Log to Event Log. */
	    p = tbuf;
	    tbuf_left = TBUF_LEN;

	    saved_errno = errno;

            /*
             * We wouldn't need this mess if printf handled %m, or if
             * strerror() had been invented before syslog().
             */
            for (t = fmt_cpy, fmt_left = FMT_LEN;
                 (ch = *fmt);
                 ++fmt)
            {
                    if (ch == '%' && fmt[1] == 'm') {
                            ++fmt;
                            prlen = _snprintf(t, fmt_left, "%s",
                                strerror(saved_errno));
                            if (prlen >= fmt_left)
                                    prlen = fmt_left - 1;
                            t += prlen;
                            fmt_left -= prlen;
                    } else {
                            if (fmt_left > 1) {
                                    *t++ = ch;
                                    fmt_left--;
                            }
                    }
            }
            *t = '\0';

	    _vsnprintf(p, tbuf_left, fmt_cpy, ap);
	    
	    /* Get connected, output the message to the local logger. */
	    if (!opened)
		    openlog(LogTag, LogStat, 0);

	
		hEventLog = RegisterEventSource(NULL, LogTag);
		if (hEventLog == NULL)
			return;

		/* Now, actually report it. */
		ReportEvent( hEventLog
                   , EVENTLOG_INFORMATION_TYPE
                   , 0
                   , EVMSG_SIMPLE
                   , NULL
                   , 1
                   , 0
                   , (char **)&p
                   , NULL);
		DeregisterEventSource(hEventLog);

		return;
	}
	
    /* Check for invalid bits. */
    if (pri & ~(LOG_PRIMASK|LOG_FACMASK)) {
            syslog(INTERNALLOG,
                "syslog: unknown facility/priority: %x", pri);
            pri &= LOG_PRIMASK|LOG_FACMASK;
    }

    /* Check priority against setlogmask values. */
    if (!(LOG_MASK(LOG_PRI(pri)) & LogMask))
            return;

    saved_errno = errno;

    /* Set default facility if none specified. */
    if ((pri & LOG_FACMASK) == 0)
            pri |= LogFacility;

    /* Build the message. */

    /*
     * Although it's tempting, we can't ignore the possibility of
     * overflowing the buffer when assembling the "fixed" portion
     * of the message.  Strftime's "%h" directive expands to the
     * locale's abbreviated month name, but if the user has the
     * ability to construct to his own locale files, it may be
     * arbitrarily long.
     */
    (void)time(&now);

    p = tbuf;
    tbuf_left = TBUF_LEN;

#define DEC()   \
        do {                                    \
                if (prlen >= tbuf_left)         \
                        prlen = tbuf_left - 1;  \
                p += prlen;                     \
                tbuf_left -= prlen;             \
        } while (0)

    prlen = snprintf(p, tbuf_left, "<%d>", pri);
    DEC();

    prlen = strftime(p, tbuf_left, "%h %e %T ", localtime(&now));
    DEC();

    if (LogStat & LOG_PERROR)
            stdp = p;
    if (LogTag == NULL)
            LogTag = VERSION;
    if (LogTag != NULL) {
            prlen = snprintf(p, tbuf_left, "%s", LogTag);
            DEC();
    }
    if (LogStat & LOG_PID) {
            prlen = snprintf(p, tbuf_left, "[%d]", getpid());
            DEC();
    }
    if (LogTag != NULL) {
            if (tbuf_left > 1) {
                    *p++ = ':';
                    tbuf_left--;
            }
            if (tbuf_left > 1) {
                    *p++ = ' ';
                    tbuf_left--;
            }
    }

    /*
     * We wouldn't need this mess if printf handled %m, or if
     * strerror() had been invented before syslog().
     */
    for (t = fmt_cpy, fmt_left = FMT_LEN; (ch = *fmt); ++fmt) {
            if (ch == '%' && fmt[1] == 'm') {
                    ++fmt;
                    prlen = snprintf(t, fmt_left, "%s",
                        strerror(saved_errno));
                    if (prlen >= fmt_left)
                            prlen = fmt_left - 1;
                    t += prlen;
                    fmt_left -= prlen;
            } else {
                    if (fmt_left > 1) {
                            *t++ = ch;
                            fmt_left--;
                    }
            }
    }
    *t = '\0';

    prlen = vsnprintf(p, tbuf_left, fmt_cpy, ap);
    DEC();
    cnt = p - tbuf;

	/* Connect to Target server. */
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == SOCKET_ERROR){
		ErrorMessage("[!] ERROR: Could not create the socket to send the syslog alert. Error Number: %d.\n", WSAGetLastError());	
		return;
	}

	sin.sin_port = htons((u_short)pv.syslog_server_port);
	sin.sin_family = AF_INET;

	if (!(sin.sin_addr.s_addr = resolve_host(pv.syslog_server))){
		ErrorMessage("[!] ERROR: Could not resolve syslog server's hostname. Error Number: %d.\n", WSAGetLastError());		
		closesocket(sockfd);
		return;
	}

	if(sendto(sockfd,tbuf,cnt,(int)NULL, (SOCKADDR *)&sin, sizeof(SOCKADDR_IN)) == SOCKET_ERROR) {
		ErrorMessage("[!] ERROR: Could not send the alert to the syslog server. Error Number: %d.\n", WSAGetLastError());		
		closesocket(sockfd);
		return;
	}

	closesocket(sockfd);
}

void openlog(char *ident, int logstat, int logfac){

	if(ident != NULL){
		LogTag = ident;
        LogStat = logstat;
		if (logfac != 0 && (logfac &~ LOG_FACMASK) == 0)
                LogFacility = logfac;

	    /* Add the registry key each time openlog is called. */
	    AddEventSource(ident);
	}
	opened = 1;
}

/* Taken from MSDN. */
void AddEventSource(char *ident)
{
    HKEY hk; 
    DWORD dwData; 
    char szFilePath[_MAX_PATH];
	char key[_MAX_PATH];
	
    // Add your source name as a subkey under the Application 
    // key in the EventLog registry key. 
    _snprintf(key, sizeof(key), "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\%s", ident);

    if (RegCreateKey(HKEY_LOCAL_MACHINE, key, &hk)) {
		printf("Could not create the registry key."); 
		exit(-1);
	}
 
    // Set the name of the message file. 
	GetModuleFileName(NULL, szFilePath, sizeof(szFilePath));
    // Add the name to the EventMessageFile subkey. 
 
    if (RegSetValueEx(hk,             // subkey handle 
            "EventMessageFile",       // value name 
            0,                        // must be zero 
            REG_EXPAND_SZ,            // value type 
            (LPBYTE) szFilePath,           // pointer to value data 
            strlen(szFilePath) + 1)) {       // length of value data 
        printf("Could not set the event message file."); 
		exit(-1);
	}
 
    // Set the supported event types in the TypesSupported subkey. 
 
    dwData = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | 
        EVENTLOG_INFORMATION_TYPE | EVENTLOG_AUDIT_SUCCESS | EVENTLOG_AUDIT_FAILURE; 
 
    if (RegSetValueEx(hk,      // subkey handle 
            "TypesSupported",  // value name 
            0,                 // must be zero 
            REG_DWORD,         // value type 
            (LPBYTE) &dwData,  // pointer to value data 
            sizeof(DWORD))){    // length of value data 
        printf("Could not set the supported types."); 
		exit(-1);
	}
 
    RegCloseKey(hk); 
} 

unsigned long resolve_host(char *host) {
    struct hostent *he;
    unsigned long ip;
    
    if (inet_addr(host) == INADDR_NONE)
    {
        he = gethostbyname(host);
        if (!he)
        {
            printf("Unable to resolve address: %s", host);
            return 0;
        }
        else
        {
            /* protecting against malicious DNS servers */
            if(he->h_length <= sizeof(unsigned long))
            {
                memcpy((char FAR *)&(ip), he->h_addr, he->h_length);
            }
            else
            {
                memcpy((char FAR *)&(ip), he->h_addr, sizeof(unsigned long));
            }
        }
    } else {
        ip = inet_addr(host);
    }
    
    return ip;
}
