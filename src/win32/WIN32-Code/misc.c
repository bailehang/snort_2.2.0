/* $Id: misc.c,v 1.6 2003/10/20 15:03:42 chrisgreen Exp $ */
/*
** Copyright (C) 2002 Martin Roesch <roesch@sourcefire.com>
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


#include "snort.h"
#include "util.h"


/****************************************************************************
 *
 * Function: gettimeofday(struct timeval *, struct timezone *)
 *
 * Purpose:  Get current time of day.
 *
 * Arguments: tv => Place to store the curent time of day.
 *            tz => Ignored.
 *
 * Returns: 0 => Success.
 *
 ****************************************************************************/

int gettimeofday(struct timeval *tv, struct timezone *tz)
{
    struct _timeb tb;

	if(tv==NULL)
    {
        return -1;
    }
	_ftime(&tb);
	tv->tv_sec = tb.time;
	tv->tv_usec = ((int) tb.millitm) * 1000;
	return 0;
}

/****************************************************************************
 *
 * Function: GetAdapterFromList(void *,int)
 *
 * Purpose:  Get a specific adapter from the list of adapters on the system.
 *
 * Arguments: device => Device to look for.
 *            index => Adapter number.
 *
 * Returns: Adapter if device was valid.
 *
 * Comments: Shamelessly ripped from WinDump.
 *
 ****************************************************************************/

void *GetAdapterFromList(void *device,int index)
{
    DWORD dwVersion;
    DWORD dwWindowsMajorVersion;
    char *Adapter95;
    WCHAR *Adapter;
    int i;

    dwVersion = GetVersion();
    dwWindowsMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));

    /* Windows 95. */
    if (dwVersion >= 0x80000000 && dwWindowsMajorVersion >= 4)
    {
        Adapter95 = device;
        for( i=0; i<index-1; i++ )
        {
            while(*Adapter95++ != 0)
            {
            }
            if( *Adapter95 == 0 )
            {
				return NULL;
            }
        }
        return  Adapter95;
    }
    else
    {
		/* NT. */
        Adapter = (WCHAR *) device;
        for( i=0; i<index-1; i++ )
        {
            while( *Adapter++ != 0 )
            {
            }
            if( *Adapter == 0 )
            {
                return NULL;
            }
        }
        return Adapter;
    }
}

/****************************************************************************
 *
 * Function: print_interface(char *)
 *
 * Purpose:  Print the interface number. Platform Independent.
 *
 * Arguments: interface => Name of Interface to print.
 *
 * Returns: Correct character format of Interface for the current platform.
 *
 * Comments: Shamelessly ripped from WinDump.
 *
 ****************************************************************************/

char *print_interface(char *szInterface)
{
    static char device[128];

    /* Device always ends with a double \0, so this way to
       determine its length should be always valid */
    if(IsTextUnicode(szInterface, wcslen((short*)szInterface), NULL))
        sprintf(device, "%ws", szInterface);
    else
        sprintf(device, "%s", szInterface);

    return(device);
}

/****************************************************************************
 *
 * Function: PrintDeviceList(const char *)
 *
 * Purpose:  Print all interfaces forund on the system that we can listen on.
 *
 * Arguments: device => List of all devices to listen on.
 *
 * Returns: void function.
 *
 * Comments: Shamelessly ripped from WinDump.
 *
 ****************************************************************************/

void PrintDeviceList(const char *device)
{
    DWORD dwVersion;
    DWORD dwWindowsMajorVersion;
    const WCHAR* t;
    const char* t95;
    int i=0;
    int DescPos=0;
    char *Desc;
    int n=1;

    dwVersion=GetVersion();
    dwWindowsMajorVersion =  (DWORD)(LOBYTE(LOWORD(dwVersion)));

    /* Windows 95. */
    if (dwVersion >= 0x80000000 && dwWindowsMajorVersion >= 4)
    {
        t95 = (char*)device;

        while(*(t95+DescPos)!=0 || *(t95+DescPos-1)!=0)
        {
            DescPos++;
        }

        Desc=(char*)t95+DescPos+1;
        printf("\nInterface\tDevice\t\tDescription\n-------------------------------------------\n");
        printf("%d  ",n++);

        while ( ! (t95[i]==0 && t95[i-1]==0) )
        {
            if ( t95[i] == 0 )
            {
                putchar(' ');
                putchar('(');
                while( *Desc !=0 )
                {
                    putchar(*Desc);
                    Desc++;
                }
                Desc++;
                putchar(')');
                putchar('\n');
            }
            else
            {
                putchar(t95[i]);
            }

            if( (t95[i]==0) && (t95[i+1]!=0) )
            {
                printf("%d ",n++);
            }

            i++;
        }
        putchar('\n');
    }
    else
    {
        /* WinNT. */
        t = (WCHAR*) device;
        while( *(t+DescPos)!=0 || *(t+DescPos-1)!=0 )
        {
                DescPos++;
        }
        DescPos <<= 1;
        Desc = (char*)t+DescPos+2;
        printf("\nInterface\tDevice\t\tDescription\n-------------------------------------------\n");
        printf("%d  ",n++);

        while ( ! ( t[i]==0 && t[i-1]==0 ) )
        {
            if ( t[i] == 0 )
            {
                putchar(' ');
                putchar('(');
                while( *Desc != 0 )
                {
                    putchar(*Desc);
                    Desc++;
                }
                Desc++;
                putchar(')');
                putchar('\n');
            }
            else
            {
                putchar(t[i]);
            }

            if( t[i]==0 && t[i+1]!=0 )
            {
                printf("%d ",n++);
            }

            i++;
        }
        putchar('\n');
    }
}

/****************************************************************************
 *
 * Function: init_winsock(void)
 *
 * Purpose:  Initialize winsock.
 *
 * Arguments: None.
 *
 * Returns: 0 => Initilization failed.
 *          1 => Initilization succeeded.
 *
 ****************************************************************************/

int init_winsock(void)
{
    WORD wVersionRequested = MAKEWORD(1, 1);
    WSADATA wsaData;

    if (WSAStartup(wVersionRequested, &wsaData))
    {
        FatalError("[!] ERROR: Unable to find a usable Winsock.\n");
        return 0;
    }

    if (LOBYTE(wsaData.wVersion) < 1 || HIBYTE(wsaData.wVersion) < 1)
    {
        FatalError("[!] ERROR: Unable to find Winsock version 1.1 or greater. You have version %d.%d.\n",
	               LOBYTE(wsaData.wVersion), HIBYTE(wsaData.wVersion));
        WSACleanup();
        return 0;
    }

    return 1;
}	

int geteuid(void)
{
	return 0;
}
