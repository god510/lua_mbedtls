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
  int ret = mbedtls_base64_decode(NULL, 0, &dlen, src, slen);
  if(ret == MBEDTLS_ERR_BASE64_INVALID_CHARACTER){
    lua_pushnil(L);
    lua_pushstring(L, "MBEDTLS_ERR_BASE64_INVALID_CHARACTER");
    return 2; // 返回值的数量
  }
  unsigned char dst[dlen];
  ret = mbedtls_base64_decode(dst, dlen, &olen, src, slen);
  if(ret != 0){
    lua_pushnil(L);
    lua_pushstring(L, "mbedtls_base64_decode failed");
    return 2; // 返回值的数量
  }
  lua_pushlstring(L, (const char *)dst, olen);
  return 1;
}