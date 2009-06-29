#include "buffer.h"
#include "exit.h"

void server(int argc,const char * const *argv) {
  int newline;
  char ch;

  newline = 0;
  while (buffer_GETC(buffer_0,&ch) == 1) {
    buffer_PUTC(buffer_1,ch);
    if (ch == "\n"[0]) {
      if (newline) {
	buffer_flush(buffer_1);
	_exit(0);
      }
      else
	newline = 1;
    }
    else
      newline = 0;
  }
}
