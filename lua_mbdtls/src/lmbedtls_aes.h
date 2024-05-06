#ifndef LMBEDTLS_AES_H
#define LMBEDTLS_AES_H
#include "lua.h"
#include "lauxlib.h"
#include "mbedtls/aes.h"


LUALIB_API int lmbedtls_aesECBEncrypt(lua_State *L);
LUALIB_API int lmbedtls_aesECBDecrypt(lua_State *L);

LUALIB_API int lmbedtls_aesCBCEncrypt(lua_State *L);
LUALIB_API int lmbedtls_aesCBCDecrypt(lua_State *L);

#endif