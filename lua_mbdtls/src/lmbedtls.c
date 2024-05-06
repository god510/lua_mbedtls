#include "lmbedtls_gcm.h"
#include "lmbedtls_sha256.h"
#include "lmbedtls_base64.h"
#include "lmbedtls_aes.h"
#include "lmbedtls_md5.h"

static const luaL_Reg funcs[] = {
  {"gcmEncrypt", lmbedtls_gcmEncrypt},
  {"gcmDecrypt", lmbedtls_gcmDecrypt},
  {"sha256", lmbedtls_sha256},
  {"base64Encode", lmbedtls_base64Encode},
  {"base64Decode", lmbedtls_base64Decode},
  {"aesECBEncrypt", lmbedtls_aesECBEncrypt},
  {"aesECBDecrypt", lmbedtls_aesECBDecrypt},
  {"aesCBCEncrypt", lmbedtls_aesCBCEncrypt},
  {"aesCBCDecrypt", lmbedtls_aesCBCDecrypt},
  {"md5", lmbedtls_md5},
  {NULL, NULL}
};



LUALIB_API int luaopen_mbedtls(lua_State *L) {
  luaL_newlib(L, funcs);
  return 1;
}
