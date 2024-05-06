#include "common.h"

void hexify(unsigned char *obuf, const unsigned char *ibuf, int len){
  unsigned char l, h;

  while( len != 0 ) {
    h = *ibuf / 16;
    l = *ibuf % 16;

    if( h < 10 )
      *obuf++ = '0' + h;
    else
      *obuf++ = 'a' + h - 10;

    if( l < 10 )
      *obuf++ = '0' + l;
    else
      *obuf++ = 'a' + l - 10;

    ++ibuf;
    len--;
  }
}