#include "buffer.h"
#include "env.h"

static char *e[] = {0};
static int n = 0;

void server(int argc,const char * const *argv) {
  char *x;

  buffer_puts(buffer_1,"\nPROTO=");
  x = env_get("PROTO");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nTCPLOCALHOST=");
  x = env_get("TCPLOCALHOST");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nTCPLOCALIP=");
  x = env_get("TCPLOCALIP"); 
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nTCPLOCALPORT=");
  x = env_get("TCPLOCALPORT"); 
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nTCPREMOTEHOST=");
  x = env_get("TCPREMOTEHOST"); 
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nTCPREMOTEIP=");
  x = env_get("TCPREMOTEIP"); 
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nTCPREMOTEPORT=");
  x = env_get("TCPREMOTEPORT"); 
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nTCPREMOTEINFO=");
  x = env_get("TCPREMOTEINFO"); 
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_putsflush(buffer_1,"\n");

  if (++n > 1) {
    environ = e;
  }
}
