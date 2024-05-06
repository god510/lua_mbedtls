#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "lmbedtls_base64.h"



LUALIB_API int lmbedtls_base64Encode(lua_State *L) {
  size_t slen, olen, dlen;
  const unsigned char *src = (unsigned char *) luaL_checklstring(L, 1, &slen);
  /* obtain the expected length */
  mbedtls_base64_encode(NULL, 0, &dlen, src, slen);
  unsigned char dst[dlen];
  mbedtls_base64_encode(dst, dlen, &olen, src, slen);
  lua_pushlstring(L, (const char *)dst, olen);
  return 1;
}


LUALIB_API int lmbedtls_base64Decode(lua_State *L) {
  size_t slen, olen, dlen;
  const unsigned char *src = (unsigned char *) luaL_checklstring(L, 1, &slen);
  /* obtain the expected length */
  mbedtls_base64_decode(NULL, 0, &dlen, src, slen);
  unsigned char dst[dlen];
  mbedtls_base64_decode(dst, dlen, &olen, src, slen);
  lua_pushlstring(L, (const char *)dst, olen);
  return 1;
}