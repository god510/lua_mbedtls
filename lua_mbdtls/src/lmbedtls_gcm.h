#ifndef LMBEDTLS_GCM_H
#define LMBEDTLS_GCM_H
#include "lua.h"
#include "lauxlib.h"
#include "mbedtls/gcm.h"


LUALIB_API int lmbedtls_gcmEncrypt(lua_State *L);
LUALIB_API int lmbedtls_gcmDecrypt(lua_State *L);

#endif