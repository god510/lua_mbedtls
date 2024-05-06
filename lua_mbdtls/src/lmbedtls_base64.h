#ifndef LMBEDTLS_BASE_64_H
#define LMBEDTLS_BASE_64_H
#include "lua.h"
#include "lauxlib.h"
#include "mbedtls/base64.h"


LUALIB_API int lmbedtls_base64Encode(lua_State *L);
LUALIB_API int lmbedtls_base64Decode(lua_State *L);

#endif