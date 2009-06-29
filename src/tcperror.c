#include "buffer.h"
#include "exit.h"

void server(int argc,const char * const *prog) {
  buffer_putsflush(buffer_1,"I'm dying here...\n");
  _exit(100);
}
