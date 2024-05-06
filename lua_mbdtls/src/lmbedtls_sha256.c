#include "lmbedtls_sha256.h"
#include "common.h"

LUALIB_API int lmbedtls_sha256(lua_State *L) {
  size_t ilen;
  unsigned char output[32];
  const unsigned char *input = (unsigned char *) luaL_checklstring(L, 1, &ilen);
  size_t olen = 32;
  mbedtls_sha256(input, ilen, output, 0);

  unsigned char obuf[65];
  hexify(obuf, output, olen);
  obuf[64] = '\0';

  lua_pushlstring(L, (const char *)obuf, 65);
  return 1;
}