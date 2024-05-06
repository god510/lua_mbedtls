#ifndef LMBEDTLS_SHA256_H
#define LMBEDTLS_SHA256_H
#include "lua.h"
#include "lauxlib.h"
#include "mbedtls/sha256.h"


LUALIB_API int lmbedtls_sha256(lua_State *L);

#endif