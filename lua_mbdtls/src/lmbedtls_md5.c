#include "lmbedtls_md5.h"
#include "mbedtls/md5.h"
#include "common.h"



LUALIB_API int lmbedtls_md5(lua_State *L) {
  size_t ilen;
  unsigned char output[16];
  const unsigned char *input = (unsigned char *) luaL_checklstring(L, 1, &ilen);

  mbedtls_md5(input, ilen, output);
  unsigned char obuf[33];
  hexify(obuf, output, 16);
  obuf[32] = '\0';


  lua_pushlstring(L, (const char *)obuf, 33);
  return 1;
}


