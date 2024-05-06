local mbedtls = require "mbedtls"
print(type(mbedtls))

local abc = mbedtls.sha256("abc")
print("abc", abc)


-- local abc = mbedtls.aesECBEncrypt("123456", "qwzasdzxcqwertty")
print("abc", mbedtls.base64Encode("abc"))