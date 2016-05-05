/* $Id: snortpp.c,v 1.1 2001/08/11 05:12:27 dragosr Exp $ */
/*
** Copyright (C) 2001 Dragos Ruiu <dr@kyx.net>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "splay.c"

#ifndef NULL
#define NULL	0
#endif
#ifndef TRUE
#define TRUE	1
#endif
#ifndef FALSE
#define FALSE 0
#endif


char *validproto[] = { "ip", "arp", "tcp", "udp", "icmp", "" };

	
typedef struct ruleip RuleIP;
struct ruleip
{
	char * ipstr;
	char any;
	char not;
	int byte[4];
	int cidr;
	char var;
	char *varname;
 	struct ruleip *next;	
};


struct ruleport
{
	char *portstr;
	char any;
	char not;
	char var;
	char * varname;
	int min, max;
	struct ruleport *next;
};

typedef struct ruleport RulePort;

struct strlist
{
	char *str;
	struct strlist *next;
};

typedef struct strlist RuleParm;
typedef struct strlist StrList;

struct rulekey
{
	char *keystr;
	char *key;
	RuleParm *parms;
	struct rulekey *next;
};

typedef struct rulekey RuleKey;

#define DIRFORW 1
#define DIRREV  2	
#define DIRBOTH 3

struct ruletext
{
	char *rulestr;
	char *type;
	char *proto;
	char *saddrstr;
	char *daddrstr;
	char *sportstr;
	char *dportstr;
	char *dirstr;
	char *keystr;
 	RuleIP *saddr, *daddr;
	RulePort *sport, *dport;	
	RuleKey *keys;
	int dir;
	char *comment;
	int sid, rev;
	struct ruletext *next;
};

typedef struct ruletext Rule;

char errorstr[32767];

struct varlist
{
	char *name;
	char *val;
	struct varlist *next;
};

typedef struct varlist SnortVar;

SnortVar *variables;
SplayTree *vars, *ruletree, *types;
FILE *outf;
int localsid;

/**********************End of Global Declaration:Start of Code***********************/

int varcmp(SnortVar *x, SnortVar *y)
{
	return(strcmp(x->name, y->name));
}

inline void errormsg(char *str)
{
	if(strlen(errorstr) < 32700)
		strcat(errorstr,str);
}

inline char *strquotchr(char *str, char c)
{
	if(!str)
		return NULL;
again:
	if(strchr(str,(int)'\"') && strchr(str,(int)'\"') < strchr(str,(int)c))
	{
		str = strchr(str,(int)'\"');
		if(*(str-1) == '\\')
		{
			str++;
			goto again;
		}
		if(!str || !*str)
			return NULL;
		while((*str != '\"' || (*str == '\"' && *((char*)str-1) != '\\')) && *str != c)
		{
			str++;
			if(!str || !*str)
				return NULL;
		}
		if(*str == c)
			return str;
		return(strquotchr(str,c));
	}
	else return(strchr(str,(int)c));
}


inline void splitstr(char *main[], char **split)
{
	if(*split)
	{
		*((*split)++) = '\0';
		while(isspace(**split))
			(*split)++;
	}
	if(*main)
		while(isspace((*main)[strlen(*main)-1]))
			(*main)[strlen(*main)-1] = '\0';
}

inline void trim(char *str[])
{
	if(*str)
	{
		while(isspace(**str))
			(*str)++;
		while(isspace((*str)[strlen(*str)-1]))
			(*str)[strlen(*str)-1] = '\0';
	}
}

int isproto(char *test)
{
	char *p;
	int i;
	for(i = 0; *(validproto[i]); i++)
		if(strcmp(test,validproto[i]) == 0)
			return TRUE;
	return FALSE;
}

void parseport(Rule *raw, char *tmp, RulePort **portptr)
{
	char *x, *y;
	const char any[] = "any";
	x = tmp;
	*portptr = calloc(1,sizeof(RulePort)+1);
	if(x && *x)
	{
		(*portptr)->portstr = calloc(1,strlen(x)+1);
		strcpy((*portptr)->portstr, x);
		if(strncasecmp(x,any,3) == 0)
			(*portptr)->any = TRUE;
		else
		{
			if(*x == '!')
			{
				(*portptr)->not = TRUE;
				splitstr(&tmp,&x);
			}
			if(*x == '$')
			{
				(*portptr)->var = TRUE;
				splitstr(&tmp,&x);
				if(!*x)
				{
					errormsg("Empty port after \'$\' ignoring and using any.\n");
					(*portptr)->any = TRUE;
					(*portptr)->portstr = calloc(4,1);
					strcpy((*portptr)->portstr,any);
				}
				else
				{
					if(!vars)
					{
						errormsg("No variables defined, using port = \"any\".\n");
						(*portptr)->any = TRUE;
						free((*portptr)->portstr);
						(*portptr)->portstr = calloc(4,1);
						strcpy((*portptr)->portstr,any);
					}
					else
					{
						SnortVar *n;
						(*portptr)->var = TRUE;
						(*portptr)->varname = calloc(1,strlen(x)+1);
						strcpy((*portptr)->varname,x);
						n = calloc(sizeof(SnortVar),1);
						n->name = (*portptr)->varname;
						vars = splay(n,vars,varcmp);
						if(vars && varcmp(vars->key,n) != 0)
						{
							errormsg("Undefined variable, using port = \"any\".\n");
							(*portptr)->any = TRUE;
							free((*portptr)->portstr);
							(*portptr)->portstr = calloc(4,1);
							strcpy((*portptr)->portstr,any);
						}
						free(n);
					}
				}
			}
			else if(y = strchr(x, ':'))
			{
				splitstr(&x, &y);
				if(!*x)
				{
					errormsg("Empty destination port before \':\' assuming 1 minimum.\n");
					(*portptr)->min = 1;
				}
				else
					sscanf(x,"%d",&((*portptr)->min));
				if(!*y)
				{
					errormsg("Empty destination port after \':\' assuming 65535 maximum.\n");
					(*portptr)->max = 65535;
				}
				else
					sscanf(y,"%d",&((*portptr)->max));
			}
			else
			{
				if(!*x)
				{
					errormsg("Empty destination port, ignoring and using any.\n");
					(*portptr)->any = TRUE;
					(*portptr)->portstr = calloc(4,1);
					strcpy((*portptr)->portstr,any);
				}
				else 
				{
					sscanf(x,"%d",&((*portptr)->min));
					(*portptr)->max = (*portptr)->min;
				}
			}
		}
	}
	else if(!x || !*x)
	{
		errormsg("Missing destination field assuming port = any.\n");
		(*portptr)->any = TRUE;
		(*portptr)->portstr = calloc(4,1);
		strcpy((*portptr)->portstr,any);
	}
}

void parseaddr(Rule *raw, char *tmp, RuleIP **addrptr)
{
	RuleIP *lastaddr, *newaddr;
	char *x, *y, *z;
	const char any[] = "Any";
	lastaddr = *addrptr;
	if(tmp)
		while(isspace(tmp[strlen(tmp)-1]))
			tmp[strlen(tmp)-1] = '\0';
	if(!tmp || !*tmp)
	{
		errormsg("No address found, assuming any.\n");
		*addrptr = calloc(sizeof(RuleIP),1);
		(*addrptr)->any = TRUE;
		(*addrptr)->ipstr = calloc(4,1);
		strcpy((*addrptr)->ipstr,any);
	}
	else while(tmp && *tmp)
	{
		trim(&tmp);
		x = strchr(tmp,',');
		splitstr(&tmp,&x);
		if(tmp && !*tmp)
			errormsg("No address found before \',\', ignoring.\n");
		else
		{
			if(lastaddr)
				while(newaddr = lastaddr->next)
					lastaddr = newaddr;
			newaddr = calloc(sizeof(RuleIP),1);
			if(lastaddr)
				lastaddr->next = newaddr;
			else
			{
				(*addrptr) = newaddr;
				lastaddr = newaddr;
			}
			newaddr->byte[0] = 0;
			newaddr->byte[1] = 0;
			newaddr->byte[2] = 0;
			newaddr->byte[3] = 0;
			newaddr->cidr = 0;
			newaddr->next = NULL;
			newaddr->ipstr = calloc(1,strlen(tmp)+1);
			strcpy(newaddr->ipstr,tmp);
			if(strncasecmp(tmp,any,3) == 0)
			{
				newaddr->any = TRUE;
			}
			else
			{
				if(*tmp == '!')
				{
					newaddr->not = TRUE;
					splitstr(&tmp,&tmp);
				}
				if(*tmp == '$')
				{
					SnortVar n;
					splitstr(&tmp,&tmp);
					if(tmp && !*tmp)
					{
						strcat(errorstr,"Empty variable name after \'$\' ignoring.");
						free(newaddr->ipstr);
						free(newaddr);
					}
					else
					{
						if(!vars)
						{
							errormsg("No variables defined, assuming address = \"Any\".\n");
							newaddr->any = TRUE;
							free(newaddr->ipstr);
							newaddr->ipstr = calloc(4,1);
							strcpy(newaddr->ipstr,any);
						}
						else
						{
							SnortVar *n;
							newaddr->var = TRUE;
							newaddr->varname = calloc(1,strlen(tmp)+1);
							strcpy(newaddr->varname,tmp);
							n = calloc(sizeof(SnortVar),1);
							n->name = newaddr->varname;
							vars = splay(n,vars,varcmp);
							if(vars && varcmp(vars->key,n) != 0)
							{
								errormsg("No address found, assuming any.\n");
								newaddr->any = TRUE;
								free(newaddr->ipstr);
								newaddr->ipstr = calloc(4,1);
								strcpy(newaddr->ipstr,any);
							}
							free(n);
						}
					}
				}
				else
				{
					if(y = strchr(tmp,'/'))
					{
						splitstr(&tmp,&y);
						if(!y || !*y)
						{
							if(strlen(errorstr) < 32700)
								strcat(errorstr,"Empty CIDR ignoring.\n");
						}
						else
							sscanf(y,"%d",&(newaddr->cidr));
					}
					if(tmp && !*tmp)
					{
						errormsg("Empty address following \'!\', or before \'/\' ignoring.\n");
						free(newaddr->ipstr);
						free(newaddr);
					}
					else if(y = strchr(tmp,'.'))
					{
						splitstr(&tmp, &y);
						if(!*tmp)
							errormsg("Empty first address octet, using 0.\n");
						else
							sscanf(tmp,"%d",&(newaddr->byte[0]));
						tmp = y;
						if(y = strchr(tmp,'.'))
						{
							splitstr(&tmp,&y);
							if(!*tmp)
								errormsg("Empty second address octet, using 0.\n");
							else
								sscanf(tmp,"%d",&(newaddr->byte[1]));
							tmp = y;
							if(y = strchr(tmp,'.'))
							{
								splitstr(&tmp,&y);
								if(!*tmp)
									errormsg("Empty third address octet, using 0.\n");
								else
									sscanf(tmp,"%d",&(newaddr->byte[2]));
								tmp = y;
								if(!tmp || !*tmp)
									errormsg("Address missing last octet after \'.\', using 0.\n");
								else
									sscanf(tmp,"%d",&(newaddr->byte[3]));
									
							}
							else
								errormsg("Address missing missing two octets and \'.\' ignoring, using 0.\n");
						}
						else
							errormsg("Address missing three octets following \'.\' ignoring, using 0.\n");
					}
					else
					{
						errormsg("Address missing dots... ignoring, using \'Any\'.\n");
						newaddr->any = TRUE;
						newaddr->ipstr = calloc(4,1);
						strcpy(newaddr->ipstr,any);
					}
				}
			}
		}
		if(x && !*x)
			errormsg("No address found after \',\', ignoring.\n");
		tmp = x;
	}
	if(!*addrptr)
	{
		errormsg("Empty address assuming \"Any\".\n");
		*addrptr = calloc(sizeof(RuleIP),1);
		(*addrptr)->any = TRUE;
		(*addrptr)->ipstr = calloc(4,1);
		strcpy((*addrptr)->ipstr,any);
	}
}

void parsekey(Rule *raw, char *tmp)
{
	RuleKey **tkey;
	RuleKey *lastkey, *newkey;
	char *x, *y, *z;
	char sid[] = "sid";
	char rev[] = "rev";
	lastkey = raw->keys;
	if(tmp && *tmp)
	{
		if(isspace(*tmp) || *tmp == ';' || *tmp == '(')
			*tmp++ = NULL;
		trim(&tmp);
		raw->keystr = calloc(1,strlen(tmp)+1);
		strcpy(raw->keystr, tmp);
	}
	else
		errormsg("Keywords not found, assuming none... weird!\n");
//keywords
	while(tmp && *tmp)
	{
		x = strquotchr(tmp,';');
		splitstr(&tmp, &x);
		if(tmp && !*tmp)
			errormsg("Empty keyword before \';\', ignoring.\n");
		else
		{
			if(lastkey)
				while(newkey = lastkey->next)
					lastkey = newkey;
			newkey = calloc(sizeof(RuleKey),1);
			if(lastkey)
				lastkey->next = newkey;
			else
			{
				raw->keys = newkey;
				lastkey = newkey;
			}
			newkey->next = NULL;
			newkey->keystr = calloc(1,strlen(tmp)+1);
			strcpy(newkey->keystr, tmp);
//parameters
			if(y = strquotchr(tmp,':'))
			{
				splitstr(&tmp, &y);
				if(tmp && !*tmp)
					errormsg("Empty keyword before \':\'. \n");
				else
				{
					newkey->key = calloc(1,strlen(tmp)+1);
					strcpy(newkey->key, tmp);
				}
// parameter lists
				if(y && !*y)
				{
					strcat(errorstr,"Empty parameter after \':\'.\n");
				}
				else
				{
					while(y && *y)
					{
						RuleParm *lastparm, *newparm;
						z = strquotchr(y, ',');
						splitstr(&y, &z);
						if(y && !*y)
							errormsg("Empty parameter before \',\'.\n");
						else
						{
							lastparm = newkey->parms;
							if(lastparm)
								while(newparm = lastparm->next)
									lastparm = newparm;
							newparm = calloc(sizeof(struct strlist),1);
							if(lastparm)
								lastparm->next = newparm;
							else
							{
								newkey->parms = newparm;
								lastparm = newparm;
							}
							newparm->next = NULL;
							newparm->str = calloc(1,strlen(y)+1);
							bcopy(y, newparm->str, strlen(y));
						}
						if(z && !*z)
							errormsg("Empty parameter after \',\'.\n");
						y = z;
					}
				}
			}
			else
			{
				newkey->key = calloc(1,strlen(tmp)+1);
				strcpy(newkey->key, tmp);
			}
			if(newkey && newkey->key && strncmp(newkey->key,sid,3) == 0)
			{
				if(newkey->parms && newkey->parms->str)
					sscanf(newkey->parms->str,"%d",&(raw->sid));
				else
					errormsg("No parameter for sid keyword!\n");
			}
			if(newkey && newkey->key && strncmp(newkey->key,rev,3) == 0)
			{
				if(newkey->parms && newkey->parms->str)
					sscanf(newkey->parms->str,"%d",&(raw->rev));
				else
					errormsg("No parameter for rev keyword!\n");
			}
		}
		tmp = x;
	}
}



int parserule(Rule *raw)
{
// assumes multi-line rules have been glued
// 
char *rulecopy;
char *tmp, *dest, *x, *y, *z;
char preproc[] = "preprocessor";
char var[] = "var";
	if(!raw->rulestr || !*(raw->rulestr))
		return -2;
	rulecopy = (char *)calloc(1,strlen(raw->rulestr)+1);
	strcpy(rulecopy, raw->rulestr);
	if(tmp = strchr(rulecopy, '#'))
	{
		splitstr(&rulecopy,&tmp);
		if(tmp && *tmp )
		{
			raw->comment = calloc(1,strlen(tmp)+1);
			bcopy(tmp,raw->comment, strlen(tmp));
		}
		if(!*rulecopy)
			return 1;
	}
	else
		raw->comment = NULL;
	if(strncasecmp(rulecopy,preproc,12) == 0)
	{
		errormsg("Preprocessor Statement.\n");
		return(0);
	}
		
	if(tmp = strchr(rulecopy, '('))
	{
		while(isspace(*tmp))
			tmp++;
		while(isspace(tmp[strlen(tmp)-1]))
			tmp[strlen(tmp)-1] = '\0';
		for(y = tmp; x = strchr(y+1,')'); y = x)
				;
		splitstr(&tmp,&y);
		if(y && *y)
			errormsg("Junk after keyword end \')\' ignored.\n");
		parsekey(raw,tmp);
	}
	else //try to salvage
	{
		if(!raw->comment)
			errormsg("Beginning of keywords not found, trying to salvage....\n");
		if(tmp = strchr(rulecopy,';'))
		{
			while(!isspace(*tmp))
				tmp--;
			splitstr(&rulecopy, &tmp);
			while(isspace(tmp[strlen(tmp)-1]))
				tmp[strlen(tmp)-1] = '\0';
			if(tmp[strlen(tmp)-1] = ')')
				tmp[strlen(tmp)-1] = '\0';
			while(isspace(tmp[strlen(tmp)-1]))
				tmp[strlen(tmp)-1] = '\0';
			parsekey(raw,tmp);
		}
		else
			if(!raw->comment)
				errormsg("Keywords not found, assuming none... strange rule there!\n");
	}
//direction
	if(!rulecopy || !*rulecopy)
	{
		if(!raw->comment)
			errormsg("Ok... I give up... where is the rule in all this?\n");
		return -2;
	}
	dest = NULL;
	if(strchr(rulecopy,'<'))
	{
		tmp = strchr(rulecopy,'<');
		for(x = tmp-1; isspace(*x); x--)
			*x = '\0';	// eat spaces before direction
		tmp++;
		if(*tmp == '-')
		{
			tmp++;
			raw->dir = DIRREV;
		}
		else if(*tmp == '>')
		{
			tmp++;
			raw->dir = DIRBOTH;
		}
		else
		{
			errormsg("Only \'<\' for rule direction found assuming \'<-\'.\n");
			tmp--;
			raw->dir = DIRREV;
		}
		*tmp++ = '\0';
		dest = tmp;
	}
	else if(strchr(rulecopy,'-'))
	{
		tmp = strchr(rulecopy,'-');
		for(x = tmp-1; isspace(*x); x--)
			*x = '\0';	// eat spaces before direction
		*tmp++ = '\0';
		if(*tmp != '>')
			errormsg("Only \'-\' for rule direction found assuming \'->\'.\n");
		*tmp++ = '\0';
		raw->dir = DIRFORW;
		dest = tmp;
	}
	else if(strchr(rulecopy,'>'))
	{
		tmp = strchr(rulecopy,'>');
		for(x = tmp-1; isspace(*x); x--)
			*x = '\0';	// eat spaces before direction
		*tmp++ = '\0';
		errormsg("Only \'>\' for rule direction found assuming \'->\'.\n");
		raw->dir = DIRFORW;
		dest = tmp;
	}
	else
	{
		errormsg("No rule direction found. Assuming ->...\n");
		raw->dir = DIRFORW;
	}
	if(tmp && *tmp)
	{
		while(isspace(*tmp))
			tmp++;
		while(isspace(tmp[strlen(tmp)-1]))
			tmp[strlen(tmp)-1] = '\0';
	}
	if(rulecopy && *rulecopy)
	{
		while(isspace(*rulecopy))
			rulecopy++;
		while(isspace(rulecopy[strlen(rulecopy)-1]))
			rulecopy[strlen(rulecopy)-1] = '\0';
	}
	else
	{
		errormsg("Ok... I give up... where is the rule?\n");
		return -2;
	}
//type
	if(tmp = strpbrk(rulecopy, " \t"))
	{
		trim(&rulecopy);
		x = strpbrk(rulecopy, "!./$:");
		if(x && x < tmp)
		{
			char alert[] = "alert";
			errormsg("Hmmm... missing fields trying to salvage, using type = \"alert\"\n");
			raw->type = calloc(1,strlen(alert)+1);
			bcopy(alert, raw->type, strlen(alert));
		}
		else
		{
			splitstr(&rulecopy, &tmp);
			if(!rulecopy || !*rulecopy)
			{
				errormsg("Missing fields before source port.\n");
				return -2;
			}
			types = splay(rulecopy,types,strcmp);
			if(types && strcmp(types->key,rulecopy) != 0)
			{
			char alert[] = "alert";
				errormsg("Messed up rule type, using type = \"alert\"\n");
				raw->proto = raw->type;
				raw->type = calloc(1,strlen(alert)+1);
				bcopy(alert, raw->type, strlen(alert));
				if(isproto(rulecopy))
				{
					errormsg("Looks like the ruletype was missing because a protocol was found, compensating.\n");
					while(*(--tmp))
						;
					while(!*(--tmp))
						*tmp = ' ';
				}
				else
					rulecopy = tmp;
			}
			else
			{
				raw->type = calloc(1,strlen(rulecopy)+1);
				bcopy(rulecopy, raw->type, strlen(rulecopy));
				rulecopy = tmp;
			}
		}
	}
	else
	{
		errormsg("Ok... I really don't think this is a much of a rule, I give up.\n");
		return -2;
	}
// proto
	if(tmp = strpbrk(rulecopy, " \t"))
	{
	char tcp[] = "tcp";
		x = strpbrk(rulecopy, "!./$:");
		if(x && x < tmp)
		{
			errormsg("Uh... missing fields trying to salvage, using proto = \"tcp\"\n");
			raw->proto = calloc(1,strlen(tcp)+1);
			strcpy(raw->proto, tcp);
		}
		else
		{
			splitstr(&rulecopy, &tmp);
			if(!rulecopy || !*rulecopy)
			{
				errormsg("Missing fields before source port.\n");
				return -2;
			}
			if(!isproto(rulecopy))
			{
				errormsg("Protocol field trashed, assumming \"tcp\".\n");
				raw->proto = calloc(1,strlen(tcp)+1);
				strcpy(raw->proto, tcp);
			}
			else
			{
				raw->proto = calloc(1,strlen(rulecopy)+1);
				strcpy(raw->proto, rulecopy);
				rulecopy = tmp;
			}
		}
	}

// source address and port
	if(tmp = strpbrk(rulecopy, " \t"))
	{
		while(isspace(tmp[strlen(tmp)-1]))
			tmp[strlen(tmp)-1] = '\0';
		if(!dest)
			dest = strpbrk(tmp+1," \t");
		else
			while(strpbrk(tmp+1, " \t"))
				tmp = strpbrk(tmp+1, " \t");   // find last space in field if luser put spaces in IP addr
		splitstr(&rulecopy,&tmp);
	}
	parseport(raw, tmp, &(raw->sport));
	if(rulecopy)
	{
		raw->daddrstr = calloc(1,strlen(rulecopy)+1);
		strcpy(raw->daddrstr,rulecopy);
	}
	parseaddr(raw, rulecopy, &(raw->saddr));

// on to destination address and port fields

	if(!dest && tmp)
		dest = strpbrk(tmp," \t");
	if(dest && (x = strpbrk(dest, " \t")))
	{
		while(isspace(x[strlen(x)-1]))
			x[strlen(x)-1] = '\0';
		while(strpbrk(x+1, " \t"))
			x = strpbrk(x+1, " \t");   // find last space in field if luser put spaces in IP addr
		splitstr(&dest,&x);
	}
	parseport(raw, x, &(raw->dport));
	if(dest)
	{
		raw->daddrstr = calloc(1,strlen(dest)+1);
		strcpy(raw->daddrstr,dest);
	}
	parseaddr(raw, dest, &(raw->daddr));

//done
	if(strlen(errorstr) > 0)
		return 0;
	return 1;
}

void fprintdir(FILE *f, int dir)
{

	switch(dir)
	{
	case DIRFORW: 
			fprintf(f,"->");
			break;
	case DIRREV: 
			fprintf(f,"<-");
			break;
	case DIRBOTH: 
			fprintf(f,"<>");
			break;
	}
}

void fprintip(FILE *f, RuleIP *ip)
{
	if(!ip)
		return;
	if(ip->any)
		fprintf(f,"Any");
	else
	{
		if(ip->not)
			fprintf(f,"!");
		if(ip->var)
		{
			if(ip->varname)
				fprintf(f,"$%s",ip->varname);
		}
		else
		{
			fprintf(f,"%d.%d.%d.%d",ip->byte[0], ip->byte[1], ip->byte[2], ip->byte[3]);
			if(ip->cidr)
				fprintf(f,"/%d",ip->cidr);
		}
	}
	while(ip->next)
	{
		ip = ip->next;
		fprintf(f,",");
		if(ip->not)
		{
			fprintf(f,"!");
		}
		if(ip->var)
		{
			if(ip->varname)
				fprintf(f,"$%s",ip->varname);
		}
		else
		{
			fprintf(f,"%d.%d.%d.%d",ip->byte[0], ip->byte[1], ip->byte[2], ip->byte[3]);
			if(ip->cidr)
				fprintf(f,"/%d",ip->cidr);
		}
	}
}

void fprintport(FILE *f, RulePort *port)
{
	if(!port)
		return;
	if(port->any)
	{
		fprintf(f,"Any");
	}
	else
	{
		if(port->not)
		{
			fprintf(f,"!");
		}
		if(port->var)
		{
			if(port->varname)
				fprintf(f,"$%s",port->varname);
		}
		else
		{
			if(port->max && port->max != port->min)
				fprintf(f,"%d:%d", port->min, port->max);
			else
				fprintf(f,"%d", port->min);
		}		
	}
}

void fprintkey(FILE *f, RuleKey *key)
{
	if(!key)
		return;
	if(key->keystr)
		fprintf(f,"%s",key->key);
	if(key->parms)
	{
		RuleParm *tmp;
		if(key->parms->str)
			fprintf(f,":%s",key->parms->str);
		tmp = key->parms->next;
		while(tmp)
		{
			if(tmp->str)
				fprintf(f,",%s",tmp->str);
			tmp = tmp->next;
		}
	}
}

	
void clearrule(Rule *r)
{
	r->rulestr = NULL;
	r->type = NULL;
	r->proto = NULL;
	r->saddrstr = NULL;
	r->daddrstr = NULL;
	r->sportstr = NULL;
	r->dportstr = NULL;
	r->dirstr = NULL;
	r->keystr = NULL;
 	r->saddr = (RuleIP*)NULL;
	r->daddr = (RuleIP*)NULL;
	r->sport = (RulePort*)NULL;
	r->dport = (RulePort*)NULL;	
	r->keys = (RuleKey*)NULL;
	r->dir = NULL;
	r->comment = NULL;
	r->sid = NULL;
	r->rev = NULL;
	r->next = (Rule*)NULL;
};
	
inline Rule *newrule()
{
	return(calloc(1,sizeof(Rule)));
}

void freerule(Rule *rule)
{
	if(rule->rulestr)
		free(rule->rulestr);
	if(rule->type)
		free(rule->type);
	if(rule->proto)
		free(rule->proto);
	if(rule->daddrstr)
		free(rule->daddrstr);
	if(rule->saddrstr)
		free(rule->saddrstr);
	if(rule->sportstr)
		free(rule->sportstr);
	if(rule->dirstr)
		free(rule->dirstr);
	if(rule->keystr)
		free(rule->keystr);
	if(rule->comment)
		free(rule->comment);
	while(rule->saddr)
	{
		RuleIP *tmp;
		if(rule->saddr->ipstr)
			free(rule->saddr->ipstr);
		if(rule->saddr->varname)
			free(rule->saddr->varname);
		tmp = rule->saddr;
		rule->saddr = rule->saddr->next;
		free(tmp);
	}
	while(rule->daddr)
	{
		RuleIP *tmp;
		if(rule->daddr->ipstr)
			free(rule->daddr->ipstr);
		if(rule->daddr->varname)
			free(rule->daddr->varname);
		tmp = rule->daddr;
		rule->daddr = rule->daddr->next;
		free(tmp);
	}
	while(rule->sport)
	{
		RulePort *tmp;
		if(rule->sport->portstr)
			free(rule->sport->portstr);
		if(rule->sport->varname)
			free(rule->saddr->varname);
		tmp = rule->sport;
		rule->sport = rule->sport->next;
		free(tmp);
	}
	while(rule->dport)
	{
		RulePort *tmp;
		if(rule->dport->portstr)
			free(rule->dport->portstr);
		if(rule->dport->varname)
			free(rule->daddr->varname);
		tmp = rule->dport;
		rule->dport = rule->dport->next;
		free(tmp);
	}
	while(rule->keys)
	{
		RuleKey *tkey;
		tkey = rule->keys;
		if(tkey->keystr)
			free(tkey->keystr);
		if(tkey->key)
			free(tkey->key);
		while(rule->keys->parms)
		{
			RuleParm *tmp;
			tmp = rule->keys->parms;
			if(tmp->str)
				free(tmp->str);
			if(tmp->next)
				rule->keys->parms = tmp->next;
			free(tmp);
		}
		rule->keys = rule->keys->next;
		free(tkey);
	}
}
	
rulecmp(Rule *x, Rule *y)
{
	if(x->sid < y->sid)
		return 1;
	else if(x->sid == y->sid)
		return 0;
	return -1;
}

void *fprintrule(FILE *f, Rule *raw)
{
	if(!raw->type || !raw->proto || !raw->saddr || !raw->sport ||
		!raw->dir || !raw->daddr || !raw->dport)
	{
		fprintf(stderr,"Not outputing incomplete rule SID:%d\n",raw->sid);
		return;
	}
	if(raw->type)
		fprintf(f,"%s ",raw->type);
	if(raw->proto)
		fprintf(f,"%s ",raw->proto);
	fprintip(f,raw->saddr);
	fprintf(f," ");
	fprintport(f,raw->sport);
	fprintf(f," ");
	fprintdir(f,raw->dir);
	fprintf(f," ");
	fprintip(f,raw->daddr);
	fprintf(f," ");
	fprintport(f,raw->dport);
	if(raw->keys)
	{
		RuleKey *tmp;
		fprintf(f," ( ");
		fprintkey(f,raw->keys);
		tmp = raw->keys->next;
		while(tmp)
		{
			fprintf(f,"; ");
			fprintkey(f,tmp);
			tmp = tmp->next;
		}
		fprintf(f,"; )");
	}
	if(raw->comment)
	{
		fprintf(f,"# %s",raw->comment);
	}
	fputs("\n",f);
}

parsefile(char *fname)
{
FILE *fd;
Rule *raw;
char rulebuf[8192];
size_t len;
char *buf, *rulecopy, *tmp, *x;
char ruletype[] = "ruletype";
char preprocessor[] = "preprocessor";
char var[] = "var";
char include[] = "include";
char stin[] = "-";
char type[] = "type";
char output[] = "output";
char start[] = "{";
char stop[] = "}";


	fprintf(stderr,"Loading file: %s\n",fname);
	if(strcmp(fname,stin) == 0)
	{
		fd = stdin;
		fputs("Reading from standard input...\n",stderr);
	}
	else if(!(fd = fopen(fname,"r")))
	{
		fprintf(stderr,"Rule file not found: %s\n",fname);
		return;
	}
	while(!feof(fd))
	{
		fgets(rulebuf, 1024, fd);
		if(feof(fd))
		{
			printf("\n");
			break;
		}
more:
		while(rulebuf[strlen(rulebuf)-1] == '\\')
		{
			fgets(&(rulebuf[strlen(rulebuf)-1]),1024,fd);
			if(strlen(rulebuf) > 7168)
				break;
		}
		// brand new fresh and clean blank error message
		*errorstr = (char) NULL; 
		tmp = rulebuf;
		trim(&tmp);
		if(strncmp(tmp,preprocessor,12) == 0)
			fputs("Preprocessor configuration declaration, stripping...\n",stderr);
		else if(strncasecmp(tmp, var, 3) == 0)
		{
			rulecopy = calloc(1,strlen(tmp)+1);
			bcopy(tmp,rulecopy,strlen(tmp));
			if(!(tmp = strpbrk(rulecopy, " \t")))
			{
				errormsg("Bogus variable declaration, dude.\n");
			}
			else
			{
				splitstr(&rulecopy,&tmp);
				if(*tmp == '$')
				{
					errormsg("Extra \'$\' in var decraration stripped.\n");
					splitstr(&tmp,&tmp);
				}
				if(tmp && *tmp)
				{
					SnortVar *n;
					if(!(x = strpbrk(tmp, " \t")))
					{
						errormsg("Empty variable declaration value, ignoring.\n");
					}
					else
					{

						splitstr(&tmp,&x);
						n = (SnortVar *) calloc(sizeof(SnortVar),1);
						n->name = calloc(1,strlen(tmp)+1);
						bcopy(tmp,n->name,strlen(tmp));
						n->next = variables;
						variables = n;
						vars = splay(n,vars,varcmp);
						if(vars && varcmp(vars->key,n) == 0)
						{
							errormsg("Duplicate var declaration.\n");
							free(n);
						}
						else
						{
							vars = splayinsert(n,vars,varcmp);
							if(*x == '\"' || *x == '\'')
							{
								x++;
								errormsg("Removing broken quotes around variable value.\n");
								if(x[strlen(x)-1] = '\"')
									x[strlen(x)-1] = '\0';
								if(x[strlen(x)-1] = '\'')
									x[strlen(x)-1] = '\0';
								trim(&x);
							}
							n->val = calloc(1,strlen(x)+1);
							bcopy(x,n->val,strlen(x));
						}
					}
				}
				else
				{
					errormsg("Messed up variable declaration, no varname.\n");
				}
			}
			
			if(*errorstr)
				fprintf(stderr,"Declaration: %s\nErrors: %s\n--\n",rulebuf,errorstr);
			free(rulecopy);
		}
		else if(strncasecmp(tmp,ruletype,8) == 0)
		{
		char *name;
			x = strpbrk(tmp," \t");
			splitstr(&tmp,&x);
			if(x)
			{
				name = calloc(1,strlen(x)+1);
				bcopy(x,name,strlen(x));
				fgets(rulebuf,1024,fd);
				tmp = rulebuf;
				trim(&tmp);
				if(strcmp(tmp,start) == 0)
				{
					fprintf(outf,"ruletype %s\n",name);
					types = splayinsert(name,types,strcmp);
					fputs(tmp,outf);
					fputs("\n",outf);
					fgets(rulebuf,1024,fd);
					tmp = rulebuf;
					trim(&tmp);
					while(!strncmp(tmp,type,4) || !strncmp(tmp,output,6))
					{
						fputs(rulebuf,outf);
						fputs("\n",outf);
						fgets(rulebuf,1024,fd);
						tmp = rulebuf;
						trim(&tmp);
					}
					if(strncmp(tmp,stop,1))
					{
						fputs("Ruletype without closing \'}\', inserting.\n",stderr);
						fputs("}\n",outf);
						goto more;
					}
					else
						fputs("}\n",outf);
				}
				else
				{
					fputs("Ruletype without following declaration, ignoring.\n",stderr);
					goto more;
				}
			}
		}
		else if(strncmp(tmp,include,7) == 0)
		{
			x = strpbrk(tmp," \t");
			if(x)
			{
				splitstr(&tmp,&x);
				if(x)
					parsefile(x);
				else
					errormsg("Missing include filename after space...\n");
			}
			else
				errormsg("Missing include filename...\n");
		}
		else
		{
			raw = newrule();
			raw->rulestr = calloc(1,strlen(rulebuf)+1);
			bcopy(rulebuf,raw->rulestr,strlen(rulebuf));
			fflush(stdout);
			parserule(raw);
			if(!raw->sid)
			{
				raw->sid = localsid++;
				raw->rev = 1;
				errormsg("No SID, assigned temporary local SID.\n");
			}
			ruletree = splay(raw, ruletree, rulecmp);
			if(ruletree && rulecmp(raw,ruletree->key) == 0)
			{
				if(raw->rev <= ((Rule *)(ruletree->key))->rev)
					if(raw->sid)
						errormsg("Duplicate SID, ignoring equal or lower rev...\n");
				else
				{
					freerule((Rule *)(ruletree->key));
					ruletree->key = raw;
					errormsg("Replacing with higher revision level.\n");
				}
			}
			else
				ruletree = splayinsert(raw, ruletree, rulecmp);
			if(*errormsg)
			{
				if(raw->sid)
					fprintf(stderr,"SID:%d rev:%d\n",raw->sid, raw->rev);
				fprintf(stderr, "\nOriginal: %s\n",rulebuf);
				fprintf(stderr, "Modified: ");
				fprintrule(stderr, raw);
				fprintf(stderr,"\nErrors:\n%s",errorstr);
				fprintf(stderr,"\n--\n");
			}
		}
	}
}


void usage()
{
	fputs("This program reads in all the snort rules files on the command line\n",stderr);
	fputs("and merges their rules while cleaning the sysntax.\n",stderr);
	fputs("Default output is stdout unless -o <filename> is used.\n",stderr);
	fputs("The special filename \"-\" can be used for stdin.\n",stderr);
	fputs("Preprocessor configuration statements and duplicate SIDs are removed.\n",stderr);
	fputs("In the case of duplicates, the highest rev:number wins.\n",stderr);
	fputs("Please send bug reports to <dr@kyx.net>. --dr\n",stderr);
	fputs("\n",stderr);
	exit(1);
}

// test stub
main(int argc, char *argv[])
{
char pass[] = "pass";
char log[] = "log";
char alert[] = "alert";
extern char *optarg;
extern int optind;
extern int errno;
List *outlist;
int ch;

	variables = NULL;
	vars = NULL;
	ruletree = NULL;
	types = NULL;
	localsid = 2000000;
	outf = stdout;
	types = splayinsert(pass,types,strcmp);
	types = splayinsert(log,types,strcmp);
	types = splayinsert(alert,types,strcmp);

	fputs("snortpp: rules preprocessor - merger cleaner stripper and desert topping (by Dragos Ruiu <dr@kyx.net>)\n",stderr);
	if(argc < 2)
	{
		fprintf(stderr,"No arguments given. Blech!\nI suppose now you want some mamby-pamby usage diagnostic... use -h for help.\n");
		exit(1);
	}
	fprintf(stderr,"\n");
	fflush(stdout);
	fflush(stderr);


	while ((ch = getopt(argc, argv, "ho:")) != -1)
	{
		switch (ch)
		{
		case 'o':
				if (!(outf = fopen(optarg, "w+")))
				{
					fprintf(stderr, "snortpp: %s: %s\n", optarg, strerror(errno));
					exit(1);
				}
				break;
		     default:
			     usage();
		}
	}
	fputs("# Rules File generated by snortpp <dr@kyx.net>\n",outf);
	fputs("#\n# Rule Type Definitions\n#\n",outf);
	for(ch = optind; ch < argc; ch++)
	{
		parsefile(argv[ch]);
	}
	// ok lets print out this junk
	fputs("#\n# Variable Declarations\n#\n",outf);
	outlist = splaytolist(vars);
	while(outlist)
	{
		fprintf(outf,"var %s %s\n", ((SnortVar *)(outlist->key))->name, ((SnortVar *)(outlist->key))->val);
		outlist = outlist->next;
	}
	fputs("#\n# Rule Definitions\n#\n",outf);
	outlist = splaytolist(ruletree);
	while(outlist)
	{
		fprintrule(outf,(Rule *)outlist->key);
		outlist = outlist->next;
	}
	fputs("#\n# end of file generated by snortpp\n#\n",outf);
	if(outf != stdout)
		fclose(outf);
//phew... --dr
}
