#ifndef LMBEDTLS_MD5_H
#define LMBEDTLS_MD5_H
#include "lua.h"
#include "lauxlib.h"
#include "mbedtls/md5.h"


LUALIB_API int lmbedtls_md5(lua_State *L);

#endif