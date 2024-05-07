#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "lmbedtls_aes.h"


// 填充函数，确保数据长度为16的倍数
void pad_data(const unsigned char *input, size_t input_len,
              unsigned char *output, size_t *output_len) {
    size_t padding_len = 16 - (input_len % 16);
    memcpy(output, input, input_len);

    for(size_t i = 0; i < padding_len; i++) {
        output[input_len + i] = (unsigned char)padding_len;
    }

    *output_len = input_len + padding_len;
}

// 加密接口函数
int ecbencode_data(const unsigned char *input, size_t input_len,
                 unsigned char **output, size_t *output_len, const unsigned char *key) {
    // 检查输入参数
    if (!input || !output || !output_len || !key) {
        return -1; // 参数错误
    }

    // 初始化AES上下文
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    // 设置密钥
    mbedtls_aes_setkey_enc(&ctx, key, 128);

    // 计算填充后的长度并分配内存
    *output_len = input_len + (16 - (input_len % 16));
    *output = malloc(*output_len);
    if (!*output) {
        mbedtls_aes_free(&ctx);
        return -2; // 内存分配失败
    }

    // 填充数据
    pad_data(input, input_len, *output, output_len);

    // 加密数据
    for (size_t i = 0; i < *output_len; i += 16) {
        mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, *output + i, *output + i);
    }

    // 清理
    mbedtls_aes_free(&ctx);

    return 0; // 成功
}

static int lecbencode(lua_State *L) {
    size_t input_len;
    const unsigned char *input = (const unsigned char *)luaL_checklstring(L, 1, &input_len);
    const unsigned char *key = (const unsigned char *)luaL_checkstring(L, 2);

    unsigned char *output;
    size_t output_len;

    // 调用之前定义的encrypt_data函数
    int result = ecbencode_data(input, input_len, &output, &output_len, key);

    // 检查加密是否成功
    if (result == 0) {
        lua_pushlstring(L, (const char *)output, output_len); // 返回加密后的数据
        free(output); // 释放内存
    } else {
        lua_pushnil(L); // 加密失败，返回nil
    }

    return 1; // 返回值的数量
}


// 解密函数
int ecbdecode_data(const unsigned char *input, size_t input_len,
                 unsigned char **output, size_t *output_len, const unsigned char *key) {
    // 检查输入参数
    if (!input || !output || !output_len || !key) {
        return -1; // 参数错误
    }

    // 初始化AES上下文
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    // 设置密钥
    mbedtls_aes_setkey_dec(&ctx, key, 128);

    // 分配内存给输出
    *output = malloc(input_len);
    if (!*output) {
        mbedtls_aes_free(&ctx);
        return -2; // 内存分配失败
    }

    // 解密数据
    for (size_t i = 0; i < input_len; i += 16) {
        mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, input + i, *output + i);
    }

    // // // 设置输出长度
    // *output_len = input_len;

      // 移除PKCS#7填充
    size_t pad_len = (*output)[input_len - 1];
    if (pad_len > 16) {
        free(*output);
        return -4; // 填充长度不合法
    }
    *output_len = input_len - pad_len;
    memset(*output + *output_len, 0, pad_len);

    // 清理
    mbedtls_aes_free(&ctx);

    return 0; // 成功
}

static int lecbdecode(lua_State *L) {
    size_t input_len;
    const unsigned char *input = (const unsigned char *)luaL_checklstring(L, 1, &input_len);
    const unsigned char *key = (const unsigned char *)luaL_checkstring(L, 2);

    unsigned char *output;
    size_t output_len;

    // 调用解密函数
    int result = ecbdecode_data(input, input_len, &output, &output_len, key);

    // 检查解密是否成功
    if (result == 0) {
        lua_pushlstring(L, (const char *)output, output_len); // 返回解密后的数据
        free(output); // 释放内存
    } else {
        lua_pushnil(L); // 解密失败，返回nil
    }

    return 1; // 返回值的数量
}



// 加密函数
int cbcencode_data(const unsigned char *input, size_t input_len,
                     unsigned char **output, size_t *output_len, 
                     const unsigned char *key, unsigned char *iv) {
    // 检查输入参数
    if (!input || !output || !output_len || !key || !iv) {
        return -1; // 参数错误
    }

    // 初始化AES上下文
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    // 设置密钥
    mbedtls_aes_setkey_enc(&ctx, key, 128);

    // 计算填充后的长度并分配内存
    *output_len = input_len + (16 - (input_len % 16));
    *output = malloc(*output_len);
    if (!*output) {
        mbedtls_aes_free(&ctx);
        return -2; // 内存分配失败
    }

    // 填充数据
    size_t padded_len = *output_len - input_len;
    memcpy(*output, input, input_len);
    memset(*output + input_len, padded_len, padded_len); // PKCS#7填充

    // 加密数据
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, *output_len, iv, *output, *output);

    // 清理
    mbedtls_aes_free(&ctx);

    return 0; // 成功
}

// Lua的C包装器函数
static int lcbcencode(lua_State *L) {
    size_t input_len;
    const unsigned char *input = (const unsigned char *)luaL_checklstring(L, 1, &input_len);
    const unsigned char *key = (const unsigned char *)luaL_checkstring(L, 2);
    size_t iv_len;
    unsigned char *iv = (unsigned char *)luaL_checklstring(L, 3, &iv_len);

    // 检查iv长度是否正确
    if (iv_len != 16) {
        lua_pushnil(L);
        lua_pushstring(L, "Invalid IV length. It must be 16 bytes.");
        return 2; // 返回值的数量
    }

    unsigned char *output;
    size_t output_len;

    // 调用加密函数
    int result = cbcencode_data(input, input_len, &output, &output_len, key, iv);

    // 检查加密是否成功
    if (result == 0) {
        lua_pushlstring(L, (const char *)output, output_len); // 返回加密后的数据
        free(output); // 释放内存
    } else {
        lua_pushnil(L); // 加密失败，返回nil
    }

    return 1; // 返回值的数量
}


// 解密函数
int cbcdecode_data(const unsigned char *input, size_t input_len,
                     unsigned char **output, size_t *output_len, 
                     const unsigned char *key, unsigned char *iv) {
    // 检查输入参数
    if (!input || !output || !output_len || !key || !iv) {
        return -1; // 参数错误
    }

    // 输入长度必须是16的整数倍
    if (input_len % 16 != 0) {
        return -2; // 输入长度不合法
    }

    // 初始化AES上下文
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    // 设置密钥
    mbedtls_aes_setkey_dec(&ctx, key, 128);

    // 分配内存给输出
    *output = malloc(input_len);
    if (!*output) {
        mbedtls_aes_free(&ctx);
        return -3; // 内存分配失败
    }

    // 解密数据
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, input_len, iv, input, *output);

    // 移除PKCS#7填充
    size_t pad_len = (*output)[input_len - 1];
    if (pad_len > 16) {
        free(*output);
        return -4; // 填充长度不合法
    }
    *output_len = input_len - pad_len;
    memset(*output + *output_len, 0, pad_len);

    // 清理
    mbedtls_aes_free(&ctx);

    return 0; // 成功
}

// Lua的C包装器函数
static int lcbcdecode(lua_State *L) {
    size_t input_len;
    const unsigned char *input = (const unsigned char *)luaL_checklstring(L, 1, &input_len);
    const unsigned char *key = (const unsigned char *)luaL_checkstring(L, 2);
    size_t iv_len;
    unsigned char *iv = (unsigned char *)luaL_checklstring(L, 3, &iv_len);

    // 检查iv长度是否正确
    if (iv_len != 16) {
        lua_pushnil(L);
        lua_pushstring(L, "Invalid IV length. It must be 16 bytes.");
        return 2; // 返回值的数量
    }

    unsigned char *output;
    size_t output_len;

    // 调用解密函数
    int result = cbcdecode_data(input, input_len, &output, &output_len, key, iv);

    // 检查解密是否成功
    if (result == 0) {
        lua_pushlstring(L, (const char *)output, output_len); // 返回解密后的数据
        free(output); // 释放内存
        return 1; // 返回值的数量
    } else {
        lua_pushnil(L); // 解密失败，返回nil
        lua_pushinteger(L, result); // 返回错误代码
        return 2; // 返回值的数量
    }

    
}

LUALIB_API int lmbedtls_aesECBEncrypt(lua_State *L) {
  return lecbencode(L);
}

LUALIB_API int lmbedtls_aesECBDecrypt(lua_State *L) {
  return lecbdecode(L);
}

LUALIB_API int lmbedtls_aesCBCEncrypt(lua_State *L) {
  return lcbcencode(L);
}

LUALIB_API int lmbedtls_aesCBCDecrypt(lua_State *L) {
  return lcbcdecode(L);
}