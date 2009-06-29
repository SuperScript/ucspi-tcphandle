#include "exit.h"
#include "iopause.h"
#include "strerr.h"
#include "scan.h"
#include "ndelay.h"

#define FATAL "tcpconnect-io: fatal: "

void die_usage(void) {
  strerr_die1x(100,"tcpconnect-io: usage: tcpconnect-io [ timeout ]");
}

void die_ndelay(void) {
  strerr_die2sys(100,FATAL,"unable to set file descriptor to non-blocking: ");
}

int main(int argc,char * const *argv) {
  unsigned int timeout;

  timeout = 3600;
  if (argc > 1) scan_uint(*++argv,&timeout);
  if (!timeout) --timeout;
  if (ndelay_on(0) == -1) die_ndelay();
  if (ndelay_on(7) == -1) die_ndelay();
  if (ndelay_on(6) == -1) die_ndelay();
  if (ndelay_on(1) == -1) die_ndelay();
  switch(iopause_proxy(0,7,6,1,timeout)) {
    case 0: _exit(0);
    case -1: strerr_die2x(111,FATAL,"read error");
    case -2: strerr_die2x(111,FATAL,"write error");
  }
  strerr_die2x(111,FATAL,"unknown error");
}
