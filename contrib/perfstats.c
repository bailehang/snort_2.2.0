/*
*   perfstats.c
*  
*   Utility to read and format the 'perfmon' preprocessor 'file' output. Displays
*   the csv stats to the console in a simple format.
*
*   usage: ./perfstats -q < perf.log      <-- displays a summary/average of the stats
*          tail -f perf.log | ./perfstats <-- displays the stats info as added to perf.log
*
*   Copyright (C) 2002 Sourcefire, Inc. 
*
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int compatable=0;
int cpu_cnt=1;

enum {
  MODE_STATS,
  MODE_SRV,
};

int quiet     = 0;
int mode      = MODE_STATS; /* 0-stats, 1-server */
unsigned nmax = 0xffffffff;

typedef struct _data
{
  time_t time;
  double drop;
  double mbits;
  double alerts;
  double kpkts;
  double avgbytes;
  double patmatch;

  double syns;
  double synacks;
  double new;
  double del;
  double active;
  double highwater;
  double flushes;
  double faults;
  double timeouts;
  double frag_completes;
  double frag_inserts;
  double frag_deletes;
  double frag_flushes;
  double frag_timeouts;
  double frag_faults;

  double user1,sys1,idle1;
  double user2,sys2,idle2;

} DATA;

void printstats( DATA * p)
{
   printf("         Mbits/Sec: %g\n",p->mbits);
   printf("         Drop Rate: %g%%\n",p->drop);
   printf("        Alerts/Sec: %g\n",p->alerts);
   printf("        K-Pkts/Sec: %g\n",p->kpkts);
   printf("     Avg Bytes/Pkt: %g\n",p->avgbytes);
   printf("       Pat-Matched: %g%%\n",p->patmatch);
   printf("          Syns/Sec: %g\n",p->syns);
   printf("       SynAcks/Sec: %g\n",p->synacks);
   printf("           New/Sec: %g\n",p->new);
   printf("           Del/Sec: %g\n",p->del);
   printf("            Active: %g\n",p->active);
   printf("        Max Active: %g\n",p->highwater);

if(!compatable )
{
   printf("       Flushes/Sec: %g\n",p->flushes);
   printf("        Faults/Sec: %g\n",p->faults);
   printf("          Timeouts: %g\n",p->timeouts);

   printf("Frag-Completes/Sec: %g\n",p->frag_completes);
   printf("  Frag-Inserts/Sec: %g\n",p->frag_inserts);
   printf("  Frag-Deletes/Sec: %g\n",p->frag_deletes);
   printf("  Frag-Flushes/Sec: %g\n",p->frag_flushes);
   printf("     Frag-Timeouts: %g\n",p->frag_timeouts);
   printf("       Frag-Faults: %g\n",p->frag_faults);
}

if( cpu_cnt == 2 )
{
   printf("              Usr1: %g%%\n",p->user1);
   printf("              Sys1: %g%%\n",p->sys1);
   printf("             Idle1: %g%%\n",p->idle1);
   printf("              Usr2: %g%%\n",p->user2);
   printf("              Sys2: %g%%\n",p->sys2);
   printf("             Idle2: %g%%\n",p->idle2);
}else{
   printf("               Usr: %g%%\n",p->user1);
   printf("               Sys: %g%%\n",p->sys1);
   printf("              Idle: %g%%\n",p->idle1);
}
   printf("\n");
}

/* avg, min, max */
void printstatsex( DATA * p, DATA * q,DATA * r)
{
   printf("         Mbits/Sec:  %9.1f %9.1f %9.1f\n", p->mbits,q->mbits,r->mbits);
   printf("         Drop Rate:  %8.4f%% %8.4f%% %8.4f%%\n", p->drop,q->drop,r->drop);
   printf("        Alerts/Sec:  %9.1f %9.1f %9.1f\n", p->alerts,q->alerts,r->alerts);
   printf("        K-Pkts/Sec:  %9.1f %9.1f %9.1f\n", p->kpkts,q->kpkts,r->kpkts);
   printf("     Avg Bytes/Pkt:  %9.1f %9.1f %9.1f\n", p->avgbytes,q->avgbytes,r->avgbytes);
   printf("       Pat-Matched:  %9.1f %9.1f %9.1f\n", p->patmatch,q->patmatch,r->patmatch);
   printf("          Syns/Sec:  %9.1f %9.1f %9.1f\n", p->syns,q->syns,r->syns);
   printf("       SynAcks/Sec:  %9.1f %9.1f %9.1f\n", p->synacks,q->synacks,r->synacks);
   printf("           New/Sec:  %9.1f %9.1f %9.1f\n", p->new,q->new,r->new);
   printf("           Del/Sec:  %9.1f %9.1f %9.1f\n", p->del,q->del,r->del);
   printf("            Active:  %9.1f\n", p->active);
   printf("        Max Active:  %9.1f\n", p->highwater);

if(!compatable )
{
   printf("       Flushes/Sec: %9.1f %9.1f %9.1f\n",p->flushes,q->flushes,r->flushes);
   printf("            Faults: %9.1f \n",p->faults);//,q->faults,r->faults);
   printf("          Timeouts: %9.1f \n",p->timeouts);

   printf("Frag-Completes/Sec: %9.1f %9.1f %9.1f\n",p->frag_completes,q->frag_completes,r->frag_completes);
   printf("  Frag-Inserts/Sec: %9.1f %9.1f %9.1f\n",p->frag_inserts,q->frag_inserts,r->frag_inserts);
   printf("  Frag-Deletes/Sec: %9.1f %9.1f %9.1f\n",p->frag_deletes,q->frag_deletes,r->frag_deletes);
   printf("  Frag-Flushes/Sec: %9.1f %9.1f %9.1f\n",p->frag_flushes,q->frag_flushes,r->frag_flushes);
   printf("     Frag-Timeouts: %9.1f\n",p->frag_timeouts);
   printf("       Frag-Faults: %9.1f\n",p->frag_faults);
}


if( cpu_cnt == 2 )
{
   printf("             Usr1:  %9.1f %9.1f %9.1f\n", p->user1,q->user1,r->user1);
   printf("             Sys1:  %9.1f %9.1f %9.1f\n", p->sys1, q->sys1, r->sys1);
   printf("            Idle1:  %9.1f %9.1f %9.1f\n", p->idle1,q->idle1,r->idle1);
   printf("             Usr2:  %9.1f %9.1f %9.1f\n", p->user2,q->user2,r->user2);
   printf("             Sys2:  %9.1f %9.1f %9.1f\n", p->sys2, q->sys2, r->sys2);
   printf("            Idle2:  %9.1f %9.1f %9.1f\n", p->idle2,q->idle2,r->idle2);
}else{
   printf("              Usr:  %9.1f %9.1f %9.1f\n", p->user1,q->user1,r->user1);
   printf("              Sys:  %9.1f %9.1f %9.1f\n", p->sys1, q->sys1, r->sys1);
   printf("             Idle:  %9.1f %9.1f %9.1f\n", p->idle1,q->idle1,r->idle1);
}
   printf("\n");
}


#define SETMIN(a,b) if((a)<(b))(b)=(a);
#define SETMAX(a,b) if((a)>(b))(b)=(a);

void setdata( DATA * q, double val )
{
       q->drop     = val;     
       q->mbits    = val;     
       q->alerts   = val;     
       q->kpkts    = val;     
       q->avgbytes = val;     
       q->patmatch = val;     
       q->syns     = val;     
       q->synacks  = val;     
       q->new      = val;     
       q->del      = val;     
       q->active   = val;     

       q->flushes  = val;
       q->faults   = val;
       q->timeouts = val;
       q->frag_completes= val;
       q->frag_inserts  = val;
       q->frag_deletes  = val;
       q->frag_flushes  = val;
       q->frag_timeouts = val;
       q->frag_faults   = val;

       q->user1     = val;     
       q->sys1      = val;     
       q->idle1     = val;     

       q->user2     = val;     
       q->sys2      = val;     
       q->idle2     = val;     
}

void accumdata( DATA * q, DATA * p )
{
       q->drop     += p->drop;     
       q->mbits    += p->mbits;
       q->alerts   += p->alerts;
       q->kpkts    += p->kpkts;
       q->avgbytes += p->avgbytes;
       q->patmatch+= p->patmatch;
       q->syns     += p->syns;
       q->synacks  += p->synacks;
       q->new      += p->new;
       q->del      += p->del;
       q->active   += p->active;

       if( p->highwater > q->highwater)
           q->highwater += p->highwater;

       q->flushes  += p->flushes;
       q->faults   += p->faults;
       q->timeouts += p->timeouts;
       q->frag_completes+= p->frag_completes;
       q->frag_inserts  += p->frag_inserts;
       q->frag_deletes  += p->frag_deletes;
       q->frag_flushes  += p->frag_flushes;
       q->frag_timeouts += p->frag_timeouts;
       q->frag_faults   += p->frag_faults;

       q->user1     += p->user1;
       q->sys1      += p->sys1;
       q->idle1     += p->idle1;

       q->user2     += p->user2;
       q->sys2      += p->sys2;
       q->idle2     += p->idle2;
}

void avgdata( DATA * q, int cnt )
{
   q->drop     /= cnt;     
   q->mbits    /= cnt;     
   q->alerts   /= cnt;     
   q->kpkts    /= cnt;     
   q->avgbytes /= cnt;     
   q->patmatch /= cnt;     
   q->syns     /= cnt;     
   q->synacks  /= cnt;     
   q->new      /= cnt;     
   q->del      /= cnt;     
   q->active   /= cnt;  

   q->flushes  /= cnt;
   q->faults   /= cnt;
   q->timeouts /= cnt;
   q->frag_completes/= cnt; 
   q->frag_inserts  /= cnt;
   q->frag_deletes  /= cnt;
   q->frag_flushes  /= cnt;
   q->frag_timeouts /= cnt;
   q->frag_faults   /= cnt;

   q->user1     /= cnt;     
   q->sys1      /= cnt;     
   q->idle1     /= cnt;     

   q->user2     /= cnt;     
   q->sys2      /= cnt;     
   q->idle2     /= cnt;     
}

void setdataminmax(DATA *p, DATA * qmin, DATA * qmax)
{
      SETMAX(p->drop,qmax->drop);  SETMIN(p->drop,qmin->drop);
      SETMAX(p->mbits,qmax->mbits);  SETMIN(p->drop,qmin->mbits);
      SETMAX(p->alerts,qmax->alerts);  SETMIN(p->drop,qmin->alerts);
      SETMAX(p->kpkts,qmax->kpkts);  SETMIN(p->kpkts,qmin->kpkts);
      SETMAX(p->avgbytes,qmax->avgbytes);  SETMIN(p->avgbytes,qmin->avgbytes);
      SETMAX(p->patmatch,qmax->patmatch);  SETMIN(p->patmatch,qmin->patmatch);
      SETMAX(p->syns,qmax->syns);  SETMIN(p->syns,qmin->syns);
      SETMAX(p->synacks,qmax->synacks);  SETMIN(p->synacks,qmin->synacks);
      SETMAX(p->new,qmax->new);  SETMIN(p->new,qmin->new);
      SETMAX(p->del,qmax->del);  SETMIN(p->del,qmin->del);
      SETMAX(p->active,qmax->active);  SETMIN(p->active,qmin->active);

      SETMAX(p->flushes,qmax->flushes);  SETMIN(p->flushes,qmin->flushes);
      SETMAX(p->faults,qmax->faults);  SETMIN(p->faults,qmin->faults);
      SETMAX(p->timeouts,qmax->timeouts);  SETMIN(p->flushes,qmin->flushes);

      SETMAX(p->frag_completes,qmax->frag_completes);  SETMIN(p->frag_completes,qmin->frag_completes);
      SETMAX(p->frag_inserts,qmax->frag_inserts);  SETMIN(p->frag_inserts,qmin->frag_inserts);
      SETMAX(p->frag_deletes,qmax->frag_deletes);  SETMIN(p->frag_deletes,qmin->frag_deletes);
      SETMAX(p->frag_flushes,qmax->frag_flushes);  SETMIN(p->frag_flushes,qmin->frag_flushes);
      SETMAX(p->frag_timeouts,qmax->frag_timeouts);  SETMIN(p->frag_timeouts,qmin->frag_timeouts);
      SETMAX(p->frag_faults,qmax->frag_faults);  SETMIN(p->frag_faults,qmin->frag_faults);

      SETMAX(p->user1,qmax->user1);  SETMIN(p->user1,qmin->user1);
      SETMAX(p->sys1,qmax->sys1);  SETMIN(p->sys1,qmin->sys1);
      SETMAX(p->idle1,qmax->idle1);  SETMIN(p->idle1,qmin->idle1);

      SETMAX(p->user2,qmax->user2);  SETMIN(p->user2,qmin->user2);
      SETMAX(p->sys2,qmax->sys2);  SETMIN(p->sys2,qmin->sys2);
      SETMAX(p->idle2,qmax->idle2);  SETMIN(p->idle2,qmin->idle2);
}

int parsedata( DATA * p, char * t )
{
       p->time = atoi(t);     
             
       t = strtok( 0," ,\n"); if(!t)return 1; p->drop     = atof(t);     
       t = strtok( 0," ,\n"); if(!t)return 1; p->mbits    = atof(t);     
       t = strtok( 0," ,\n"); if(!t)return 1; p->alerts   = atof(t);     
       t = strtok( 0," ,\n"); if(!t)return 1; p->kpkts    = atof(t);     
       t = strtok( 0," ,\n"); if(!t)return 1; p->avgbytes = atof(t);     
       t = strtok( 0," ,\n"); if(!t)return 1; p->patmatch = atof(t);     
       t = strtok( 0," ,\n"); if(!t)return 1; p->syns     = atof(t);     
       t = strtok( 0," ,\n"); if(!t)return 1; p->synacks  = atof(t);     
       t = strtok( 0," ,\n"); if(!t)return 1; p->new      = atof(t);     
       t = strtok( 0," ,\n"); if(!t)return 1; p->del      = atof(t);     
       t = strtok( 0," ,\n"); if(!t)return 1; p->active   = atof(t);     
       t = strtok( 0," ,\n"); if(!t)return 1; p->highwater = atof(t);     

if(!compatable )
{
       t = strtok( 0," ,\n"); if(!t)return 1; p->flushes = atof(t);     
       t = strtok( 0," ,\n"); if(!t)return 1; p->faults  = atof(t);     
       t = strtok( 0," ,\n"); if(!t)return 1; p->timeouts= atof(t);     
       t = strtok( 0," ,\n"); if(!t)return 1; p->frag_completes = atof(t);     
       t = strtok( 0," ,\n"); if(!t)return 1; p->frag_inserts = atof(t);     
       t = strtok( 0," ,\n"); if(!t)return 1; p->frag_deletes = atof(t);     
       t = strtok( 0," ,\n"); if(!t)return 1; p->frag_flushes = atof(t);     
       t = strtok( 0," ,\n"); if(!t)return 1; p->frag_timeouts = atof(t);     
       t = strtok( 0," ,\n"); if(!t)return 1; p->frag_faults = atof(t);     
}

       t = strtok( 0," ,\n"); if(!t)return 1; p->user1     = atof(t);     
       t = strtok( 0," ,\n"); if(!t)return 1; p->sys1      = atof(t);     
       t = strtok( 0," ,\n"); if(!t)return 1; p->idle1     = atof(t);     


       t = strtok( 0," ,\n"); if(!t)return 0; p->user2     = atof(t);
       t = strtok( 0," ,\n"); if(!t)return 0; p->sys2      = atof(t);
       t = strtok( 0," ,\n"); if(!t)return 0; { p->idle2   = atof(t); cpu_cnt=2; }


   return 0;
}

int do_stats()
{
   char buff[8192], *t;
   DATA d1, *p = &d1;
   DATA d2, *q = &d2;
   DATA d3, *qmin = &d3;
   DATA d4, *qmax = &d4;
   int  cnt = 0;
   unsigned n = 0;

   memset(p,0,sizeof(DATA));
   memset(q,0,sizeof(DATA));

   setdata( qmin, 1.e+22 );
   setdata( qmax, -1.e+22 );

   while( (n < nmax)   &&   fgets(buff,sizeof(buff),stdin) )
   {
       t       = strtok( buff, " ,\n");
       if( !t ) continue;
       if( *t == '#' ) continue;

       n++;
  
       if( parsedata(p,t) )
           break;

       /* Get Min-Max Values */
       setdataminmax(p,qmin,qmax);

       /* Accumulate for Averaging */
       accumdata( q, p );
  
       if( !quiet )
       {
           printf("%s",ctime(&p->time));
           printstats( p );
       }

       cnt++;
   }

   if( !n ){
       printf("*** no performance records found, invalid file or file may be empty\n");
       return 0;
   }
   
   /* Calc Average */
   avgdata( q, cnt );

   printf("%d statistics lines read\n\n",cnt);

   printstatsex( q, qmin, qmax );

   return 0;
}


int do_srv()
{
   return 0;
}


void help()
{
   printf("\n");
   printf("usage: perfstats [-q(uiet)] [-n(lines) #] [-c(ompatable mode)]\n");
   printf("   - q only does a summary/avg\n");
   printf("   - n number of lines to process from a file\n");
   printf("   - c (compatability with older versions)\n");
   printf(" notes: you must pass text data via stdin\n");
   printf("\n");
   exit(0);
}


int init ( int argc, char ** argv )
{
   int i;
   for(i=1;i<argc;i++)
   {
     if( strcmp(argv[i],"-q")==0          ) quiet = 1;
     else if( strcmp(argv[i],"-n")==0     ) nmax = atoi( argv[++i] );/* max lines to read */
     else if( strcmp(argv[i],"-h")==0     ) help();
     else if( strcmp(argv[i],"-c")==0     ) compatable=1;
     else 
       {
          printf("*** unknown argument '%s' \n\n",argv[i]);
          help();
       }
   }
   return 0;
}



/*
*
*/
int main ( int argc, char ** argv )
{
   init(argc,argv);

   do_stats();
   
   return 0;
}
