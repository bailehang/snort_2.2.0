/* $Id: sp_ip_fragbits.h,v 1.7 2003/10/20 15:03:29 chrisgreen Exp $ */

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
/* Snort Detection Plugin Header for IP Fragment Bits plugin*/

#ifndef __SP_IP_FRAGBITS_H__
#define __SP_IP_FRAGBITS_H__

void SetupFragBits(void);
void SetupFragOffset(void);

#endif  /* __SP_IP_FRAGBITS_H__ */
