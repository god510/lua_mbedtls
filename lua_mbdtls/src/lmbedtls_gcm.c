#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "lmbedtls_gcm.h"


static int gcm_crypt(lua_State *L, unsigned int mode) {
  size_t dataLen, keyLen, ivLen;
  const unsigned char *const data = (const unsigned char *)luaL_checklstring(L, 1, &dataLen);
  const unsigned char *const key = (const unsigned char *)luaL_checklstring(L, 2, &keyLen);
  const unsigned char *const iv = (const unsigned char *)luaL_checklstring(L, 3, &ivLen);

  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);

  const int err1 = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, keyLen * 8);
  if (err1) {
    mbedtls_gcm_free(&ctx);
    return luaL_error(L, "mbedtls_gcm_setkey failed: err:%d errno:%d", err1, errno);
  }

  unsigned char *const output = (unsigned char *)malloc(dataLen);
  if (!output) {
    mbedtls_gcm_free(&ctx);
    return luaL_error(L, "malloc failed: %d", errno);
  }

  const size_t tagLen = 16;
  unsigned char tag[tagLen];
  const int err2 = mbedtls_gcm_crypt_and_tag(
    &ctx,
    mode,
    dataLen,
    iv, ivLen,
    NULL, 0,
    data, output,
    tagLen, tag);
  mbedtls_gcm_free(&ctx);
  if (err2) {
    free(output);
    return luaL_error(L, "mbedtls_gcm_crypt_and_tag failed: err:%d errno:%d", err2, errno);
  }

  tag[tagLen + 1] = '\0';
  lua_pushlstring(L, (const unsigned char *)output, dataLen);
  lua_pushlstring(L, (const unsigned char *)tag, tagLen);

  free(output);
  return 2;
}

LUALIB_API int lmbedtls_gcmEncrypt(lua_State *L) {
  return gcm_crypt(L, MBEDTLS_GCM_ENCRYPT);
}

LUALIB_API int lmbedtls_gcmDecrypt(lua_State *L) {
  return gcm_crypt(L, MBEDTLS_GCM_DECRYPT);
}