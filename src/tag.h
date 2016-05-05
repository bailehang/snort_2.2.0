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

/* $Id: tag.h,v 1.11 2003/10/20 15:03:27 chrisgreen Exp $ */
#ifndef __TAG_H__
#define __TAG_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rules.h"
#include "event.h"
#include "decode.h"

void InitTag();
void ParseTag(char *, OptTreeNode *);
int CheckTagList(Packet *, Event *);
void SetTags(Packet *, OptTreeNode *, u_int32_t);

#endif /* __TAG_H__ */
