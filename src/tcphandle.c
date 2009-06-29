#include <sys/types.h>
#include <unistd.h>
#include <sys/param.h>
#include <netdb.h>
#include <signal.h>
#include <netinet/in.h>
#include "uint16.h"
#include "str.h"
#include "byte.h"
#include "fmt.h"
#include "scan.h"
#include "ip4.h"
#include "fd.h"
#include "exit.h"
#include "env.h"
#include "prot.h"
#include "open.h"
#include "wait.h"
#include "stralloc.h"
#include "alloc.h"
#include "buffer.h"
#include "error.h"
#include "strerr.h"
#include "sgetopt.h"
#include "socket.h"
#include "ndelay.h"
#include "remoteinfo.h"
#include "rules.h"
#include "sig.h"
#include "dns.h"
#include "iopause.h"
#include "coe.h"
#include "lock.h"

extern void server(int argcs,char * const *argvs);
const char *self;

int verbosity = 1;
int flagkillopts = 1;
int flagdelay = 0;
const char *banner = "";
int flagremoteinfo = 1;
int flagremotehost = 1;
int flagparanoid = 0;
unsigned long timeout = 26;
int selfpipe[2];
int flagexit = 0;

static stralloc tcpremoteinfo;

uint16 localport;
char localportstr[FMT_ULONG];
char localip[4];
char localipstr[IP4_FMT];
static stralloc localhostsa;
const char *localhost = 0;
const char *lockfile = 0;
int fdlock;

char **e;
char **e1;

uint16 remoteport;
char remoteportstr[FMT_ULONG];
char remoteip[4];
char remoteipstr[IP4_FMT];
static stralloc remotehostsa;
char *remotehost = 0;

char strnum[FMT_ULONG];
char strnum2[FMT_ULONG];

static stralloc tmp;
static stralloc fqdn;
static stralloc addresses;
stralloc envplus = {0};
stralloc envtmp = {0};

char bspace[16];
buffer b;


/* ---------------------------- child */

#define DROP ": warning: dropping connection, "

int flagdeny = 0;
int flagallownorules = 0;
const char *fnrules = 0;

void drop_nomem(void) {
  strerr_die3sys(111,self,DROP,"out of memory");
}
void cats(const char *s) {
  if (!stralloc_cats(&tmp,s)) drop_nomem();
}
void append(const char *ch) {
  if (!stralloc_append(&tmp,ch)) drop_nomem();
}
void safecats(const char *s) {
  char ch;
  int i;

  for (i = 0;i < 100;++i) {
    ch = s[i];
    if (!ch) return;
    if (ch < 33) ch = '?';
    if (ch > 126) ch = '?';
    if (ch == '%') ch = '?'; /* logger stupidity */
    if (ch == ':') ch = '?';
    append(&ch);
  }
  cats("...");
}
void env(const char *s,const char *t) {
  if (!s) return;
  if (!stralloc_copys(&envtmp,s)) drop_nomem();
  if (t) {
    if (!stralloc_cats(&envtmp,"=")) drop_nomem();
    if (!stralloc_cats(&envtmp,t)) drop_nomem();
  }
  if (!stralloc_0(&envtmp)) drop_nomem();
  if (!stralloc_cat(&envplus,&envtmp)) drop_nomem();
}
void env_set(void) {
  unsigned int elen;
  unsigned int i;
  unsigned int j;
  unsigned int split;
  unsigned int t;

  if (!stralloc_cats(&envplus,"")) return;

  elen = 0;
  for (i = 0;environ[i];++i)
    ++elen;
  for (i = 0;i < envplus.len;++i)
    if (!envplus.s[i])
      ++elen;

  e = (char **) alloc((elen + 1) * sizeof(char *));
  if (!e) return;

  elen = 0;
  for (i = 0;environ[i];++i)
    e[elen++] = environ[i];

  j = 0;
  for (i = 0;i < envplus.len;++i)
    if (!envplus.s[i]) {
      split = str_chr(envplus.s + j,'=');
      for (t = 0;t < elen;++t)
	if (byte_equal(envplus.s + j,split,e[t]))
	  if (e[t][split] == '=') {
	    --elen;
	    e[t] = e[elen];
	    break;
	  }
      if (envplus.s[j + split])
	e[elen++] = envplus.s + j;
      j = i + 1;
    }
  e[elen] = 0;

  e1 = environ;
  environ = e;
}
void env_reset(void) {
  if (e) {
    if (e != environ) strerr_die3x(111,self,DROP,"environ changed");
    alloc_free((char *)e);
  }

  environ = e1;
  envplus.len = 0;
}
void drop_rules(void) {
  strerr_die5sys(111,self,DROP,"unable to read ",fnrules,": ");
}

void found(char *data,unsigned int datalen) {
  unsigned int next0;
  unsigned int split;

  while ((next0 = byte_chr(data,datalen,0)) < datalen) {
    switch(data[0]) {
      case 'D':
	flagdeny = 1;
	break;
      case '+':
	split = str_chr(data + 1,'=');
	if (data[1 + split] == '=') {
	  data[1 + split] = 0;
	  env(data + 1,data + 1 + split + 1);
	}
	break;
    }
    ++next0;
    data += next0; datalen -= next0;
  }
}

int doit(int t) {
  int j;

  remoteipstr[ip4_fmt(remoteipstr,remoteip)] = 0;

  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    strerr_warn5(self,": pid ",strnum," from ",remoteipstr,0);
  }

  if (flagkillopts)
    socket_ipoptionskill(t);
  if (!flagdelay)
    socket_tcpnodelay(t);

  if (*banner) {
    buffer_init(&b,buffer_unixwrite,t,bspace,sizeof bspace);
    if (buffer_putsflush(&b,banner) == -1)
      strerr_die3sys(111,self,DROP,"unable to print banner: ");
  }

  if (socket_local4(t,localip,&localport) == -1)
    strerr_die3sys(111,self,DROP,"unable to get local address: ");

  localipstr[ip4_fmt(localipstr,localip)] = 0;
  remoteportstr[fmt_ulong(remoteportstr,remoteport)] = 0;

  if (!localhost)
    if (dns_name4(&localhostsa,localip) == 0)
      if (localhostsa.len) {
	if (!stralloc_0(&localhostsa)) drop_nomem();
	localhost = localhostsa.s;
      }
  env("PROTO","TCP");
  env("TCPLOCALIP",localipstr);
  env("TCPLOCALPORT",localportstr);
  env("TCPLOCALHOST",localhost);

  if (flagremotehost)
    if (dns_name4(&remotehostsa,remoteip) == 0)
      if (remotehostsa.len) {
	if (flagparanoid)
	  if (dns_ip4(&tmp,&remotehostsa) == 0)
	    for (j = 0;j + 4 <= tmp.len;j += 4)
	      if (byte_equal(remoteip,4,tmp.s + j)) {
		flagparanoid = 0;
		break;
	      }
	if (!flagparanoid) {
	  if (!stralloc_0(&remotehostsa)) drop_nomem();
	  remotehost = remotehostsa.s;
	}
      }
  env("TCPREMOTEIP",remoteipstr);
  env("TCPREMOTEPORT",remoteportstr);
  env("TCPREMOTEHOST",remotehost);

  if (flagremoteinfo) {
    if (remoteinfo(&tcpremoteinfo,remoteip,remoteport,localip,localport,timeout) == -1)
      flagremoteinfo = 0;
    if (!stralloc_0(&tcpremoteinfo)) drop_nomem();
  }
  env("TCPREMOTEINFO",flagremoteinfo ? tcpremoteinfo.s : 0);

  if (fnrules) {
    int fdrules;

    flagdeny = 0;
    fdrules = open_read(fnrules);
    if (fdrules == -1) {
      if (errno != error_noent) drop_rules();
      if (!flagallownorules) drop_rules();
    }
    else {
      if (rules(found,fdrules,remoteipstr,remotehost,flagremoteinfo ? tcpremoteinfo.s : 0) == -1)
	drop_rules();
      close(fdrules);
    }
  }

  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    if (!stralloc_copys(&tmp,self)) drop_nomem();
    if (!stralloc_cats(&tmp,": ")) drop_nomem();
    safecats(flagdeny ? "deny" : "ok");
    cats(" "); safecats(strnum);
    cats(" "); if (localhost) safecats(localhost);
    cats(":"); safecats(localipstr);
    cats(":"); safecats(localportstr);
    cats(" "); if (remotehost) safecats(remotehost);
    cats(":"); safecats(remoteipstr);
    cats(":"); if (flagremoteinfo) safecats(tcpremoteinfo.s);
    cats(":"); safecats(remoteportstr);
    cats("\n");
    buffer_putflush(buffer_2,tmp.s,tmp.len);
  }

  if (flagdeny) {
    close(t);
    return(0);
  }
  env_set();

  return 1;
}

void done(void) {
  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    if (!stralloc_copys(&tmp,self)) drop_nomem();
    if (!stralloc_cats(&tmp,": ")) drop_nomem();
    cats("done "); safecats(strnum); cats("\n");
    buffer_putflush(buffer_2,tmp.s,tmp.len);
  }
}



/* ---------------------------- parent */

#define FATAL ": fatal: "

void usage(void) {
  strerr_warn4(self,"\
: usage: ",self," \
[ -1UXpPhHrRoOdDqQv ] \
[ -c limit ] \
[ -x rules.cdb ] \
[ -B banner ] \
[ -g gid ] \
[ -u uid ] \
[ -b backlog ] \
[ -l localname ] \
[ -t timeout ] \
[ -f lockfile ] \
host port",0);
  _exit(100);
}

unsigned long limit = 40;
unsigned long numchildren = 0;

int flag1 = 0;
unsigned long backlog = 20;
unsigned long uid = 0;
unsigned long gid = 0;

void printstatus(void) {
  if (verbosity < 2) return;
  strnum[fmt_ulong(strnum,numchildren)] = 0;
  strnum2[fmt_ulong(strnum2,limit)] = 0;
  strerr_warn5(self,": status: ",strnum,"/",strnum2,0);
}

void trigger(void) {
  buffer_unixwrite(selfpipe[1],"",1);
}

void sigterm(void) {
  int pid;

  flagexit = 1;
  pid = getpid();
  if (pid < 0) strerr_die2sys(111,FATAL,"cannot get pid: ");
  kill(-pid,SIGTERM);
  trigger();
}

void sigchld(void) {
  int wstat;
  int pid;
 
  while ((pid = wait_nohang(&wstat)) > 0) {
    if (verbosity >= 2) {
      strnum[fmt_ulong(strnum,pid)] = 0;
      strnum2[fmt_ulong(strnum2,wstat)] = 0;
      strerr_warn5(self,": end ",strnum," status ",strnum2,0);
    }
    if (numchildren) --numchildren; printstatus();
    if (flagexit && !numchildren) _exit(0);
  }
  trigger();
}

void spawn(int s,int argc,char * const *argv) {
  int t;

  while (numchildren >= limit) sig_pause();
  while (numchildren < limit) {
    ++numchildren; printstatus();
 
    switch(fork()) {
      case 0:
	sig_uncatch(sig_child);
	sig_unblock(sig_child);
	sig_uncatch(sig_term);
	sig_uncatch(sig_pipe);
	for (;;) {
	  if (lockfile) {
	    if (lock_ex(fdlock) == -1)
	      strerr_die5sys(111,self,FATAL,"unable to lock ",lockfile,": ");
	    t = socket_accept4(s,remoteip,&remoteport);
	    lock_un(fdlock);
	  }
	  else
	    t = socket_accept4(s,remoteip,&remoteport);

	  if (t == -1) continue;
	  if (!doit(t)) continue;
	  if ((fd_move(0,t) == -1) || (fd_copy(1,0) == -1))
	    strerr_die3sys(111,self,DROP,"unable to set up descriptors: ");
	  server(argc,argv);
	  close(0); close(1);
	  buffer_seek(buffer_0,buffer_0->p);
	  buffer_seek(buffer_1,buffer_1->p);
	  env_reset();
	  done();
	}
	break;
      case -1:
	strerr_warn3(self,DROP,"unable to fork: ",&strerr_sys);
	--numchildren; printstatus();
    }
  }
}

int main(int argc,char * const *argv) {
  const char *hostname;
  int opt;
  struct servent *se;
  const char *x;
  unsigned long u;
  int s;
  iopause_fd io[2];
  char ch;
  struct taia deadline;
  struct taia stamp;

  self = argv[0];
  while ((opt = getopt(argc,argv,"dDvqQhHrR1UXx:t:u:g:l:b:B:c:pPoOf:")) != opteof)
    switch(opt) {
      case 'b': scan_ulong(optarg,&backlog); break;
      case 'c': scan_ulong(optarg,&limit); break;
      case 'X': flagallownorules = 1; break;
      case 'x': fnrules = optarg; break;
      case 'B': banner = optarg; break;
      case 'd': flagdelay = 1; break;
      case 'D': flagdelay = 0; break;
      case 'v': verbosity = 2; break;
      case 'q': verbosity = 0; break;
      case 'Q': verbosity = 1; break;
      case 'P': flagparanoid = 0; break;
      case 'p': flagparanoid = 1; break;
      case 'O': flagkillopts = 1; break;
      case 'o': flagkillopts = 0; break;
      case 'H': flagremotehost = 0; break;
      case 'h': flagremotehost = 1; break;
      case 'R': flagremoteinfo = 0; break;
      case 'r': flagremoteinfo = 1; break;
      case 't': scan_ulong(optarg,&timeout); break;
      case 'U': x = env_get("UID"); if (x) scan_ulong(x,&uid);
		x = env_get("GID"); if (x) scan_ulong(x,&gid); break;
      case 'u': scan_ulong(optarg,&uid); break;
      case 'g': scan_ulong(optarg,&gid); break;
      case '1': flag1 = 1; break;
      case 'l': localhost = optarg; break;
      case 'f': lockfile = optarg; break;
      default: usage();
    }
  argc -= optind;
  argv += optind;

  if (!verbosity)
    buffer_2->fd = -1;
 
  hostname = *argv++; --argc;
  if (!hostname) usage();
  if (str_equal(hostname,"")) hostname = "0.0.0.0";
  if (str_equal(hostname,"0")) hostname = "0.0.0.0";

  x = *argv++; --argc;
  if (!x) usage();
  if (!x[scan_ulong(x,&u)])
    localport = u;
  else {
    se = getservbyname(x,"tcp");
    if (!se)
      strerr_die4x(111,self,FATAL,"unable to figure out port number for ",x);
    localport = ntohs(se->s_port);
  }

  if (setsid() == -1)
    if (getpgrp() != getpid())
      strerr_die3sys(111,self,FATAL,"unable to create process group: ");
    
  if (lockfile) {
    fdlock = open_append(lockfile);
    if (fdlock == -1)
      strerr_die5sys(111,self,FATAL,"unable to open ",lockfile,": ");
  }

  if (pipe(selfpipe) == -1)
    strerr_die3sys(111,self,FATAL,"unable to create pipe: ");
  coe(selfpipe[0]);
  coe(selfpipe[1]);
  ndelay_on(selfpipe[0]);
  ndelay_on(selfpipe[1]);

  sig_block(sig_child);
  sig_catch(sig_child,sigchld);
  sig_catch(sig_term,sigterm);
  sig_ignore(sig_pipe);
 
  if (!stralloc_copys(&tmp,hostname))
    strerr_die3x(111,self,FATAL,"out of memory");
  if (dns_ip4_qualify(&addresses,&fqdn,&tmp) == -1)
    strerr_die5sys(111,self,FATAL,"temporarily unable to figure out IP address for ",hostname,": ");
  if (addresses.len < 4)
    strerr_die4x(111,self,FATAL,"no IP address for ",hostname);
  byte_copy(localip,4,addresses.s);

  s = socket_tcp();
  if (s == -1)
    strerr_die3sys(111,self,FATAL,"unable to create socket: ");
  if (socket_bind4_reuse(s,localip,localport) == -1)
    strerr_die3sys(111,self,FATAL,"unable to bind: ");
  if (socket_local4(s,localip,&localport) == -1)
    strerr_die3sys(111,self,FATAL,"unable to get local address: ");
  if (socket_listen(s,backlog) == -1)
    strerr_die3sys(111,self,FATAL,"unable to listen: ");
  ndelay_off(s);

  if (gid) if (prot_gid(gid) == -1)
    strerr_die3sys(111,self,FATAL,"unable to set gid: ");
  if (uid) if (prot_uid(uid) == -1)
    strerr_die3sys(111,self,FATAL,"unable to set uid: ");

  localportstr[fmt_ulong(localportstr,localport)] = 0;
  if (flag1) {
    buffer_init(&b,buffer_unixwrite,1,bspace,sizeof bspace);
    buffer_puts(&b,localportstr);
    buffer_puts(&b,"\n");
    buffer_flush(&b);
  }
 
  close(0);
  close(1);
  printstatus();

  for (;;) {
    if (!flagexit) spawn(s,argc,argv);

    sig_unblock(sig_child);
    io[0].fd = selfpipe[0];
    io[0].events = IOPAUSE_READ;
    taia_now(&stamp);
    taia_uint(&deadline,3600);
    taia_add(&deadline,&stamp,&deadline);
    iopause(io,1,&deadline,&stamp);
    sig_block(sig_child);

    if (flagexit && !numchildren) _exit(0);
    while (buffer_unixread(selfpipe[0],&ch,1) == 1)
      ;
  }
}


