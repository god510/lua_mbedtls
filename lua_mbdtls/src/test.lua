local mbedtls = require "mbedtls"
local utils = {}

--将字符串按格式转为16进制串
function str2hex(hex)
	--判断输入类型
	if (type(hex)~="string") then
		return nil,"str2hex invalid input type"
	end
	--拼接字符串
	local index=1
	local ret=""
	for index=1,hex:len() do
		ret=ret..string.format("%02X",hex:sub(index):byte())
	end

	return ret
end

--将16进制串转换为字符串
function hex2str(str)
	--判断输入类型
	if (type(str)~="string") then
		print("hex2str invalid input type")
		return nil
	end
	--滤掉分隔符
	str=str:gsub("[%s%p]",""):upper()
	--检查内容是否合法
	if(str:find("[^0-9A-Fa-f]")~=nil) then
		print("hex2str invalid input content")
		return nil
	end
	--检查字符串长度
	if(str:len()%2~=0) then
		print("hex2str invalid input lenth")
		return nil
	end
	--拼接字符串
	local index=1
	local ret=""
	for index=1,str:len(),2 do
		ret=ret..string.char(tonumber(str:sub(index,index+1),16))
	end

	return ret
end


math.randomseed(os.time())
function generateBinaryString(length)
	local result = {}
	for i = 1, length do
		table.insert(result, string.char(math.random(0, 255)))
	end
	return table.concat(result)
end

--[[
-- 加密
-- aes-128-gcm 加密
-- base64 编码
]]
function utils.gcmEncrypt(msg, key)
	local iv = generateBinaryString(12)
	local key = hex2str(key)
	local tmpMsg0, tag = mbedtls.gcmEncrypt(msg, key, iv)
	local buff = iv..tmpMsg0..tag
	local tmpMsg1 = mbedtls.base64Encode(buff)
	return tmpMsg1, tag
end

--[[
-- 解密
-- base64 解码
-- aes-128-gcm 解密
]]
function utils.gcmDecrypt(msg, key)
	local tmpMsg0 = mbedtls.base64Decode(msg)
	local iv = string.sub(tmpMsg0, 1, 12)
	local tmpMsg1 = string.sub(tmpMsg0, 13, #tmpMsg0 - 16)
	local tag0 = string.sub(tmpMsg0, #tmpMsg0 - 15, #tmpMsg0)
	local key = hex2str(key)
	local srcMsg, tag = mbedtls.gcmDecrypt(tmpMsg1, key, iv)
	return srcMsg, tag
end

-- aes-128-gcm test 
function gmcTest(msg, key)
	local srcMsg, tag0 = utils.gcmEncrypt(msg, key)
	print("gcmEncrypt ==", srcMsg)
	print("gcmEncrypt ==tag", tag0)
	local srcMsg = srcMsg --[[CqT/33f3jyoiYqT8MtxEFk3x2rlfhmgzhxpHqWosSj4d3hq2EbrtVyx2aLj565ZQNTcPrcDipnvpq/D/vQDaLKW70083Q42zvRO//OfnYLcljTPMnqa+SOhsjQrSdu66ySSORCAo]]
	local destMsg, tag1 = utils.gcmDecrypt(srcMsg, key)
	print("gcmDecrypt ==", destMsg)
	print("gcmDecrypt ==tag", tag1)
	print("tag0 == tag1", tag0 == tag1)
	print("msg == destMsg", msg == destMsg)
	print("#msg", #msg)
	print("#destMsg", #destMsg)
end


local key = "2836e95fcd10e04b0069bb1ee659955b"
local msg = [[{"ai":"test-accountId","name":"用户姓名","idNum":"371321199012310912"}]]
-- gmcTest(msg, key)


local cryped = mbedtls.aesECBEncrypt('123456', 'qwaw012z34llxwz!')
local cryb = mbedtls.base64Encode(cryped)
print('cryb ---', cryb)

local dcryb = mbedtls.base64Decode(cryb)
local dcryped = mbedtls.aesECBDecrypt(dcryb, 'qwaw012z34llxwz!')
print('dcryped --', dcryped, #dcryped)



-- local cryped = mbedtls.aesCBCEncrypt('222222222222224', '1111111111111111', '1234567890abcdef')
-- local cryb = mbedtls.base64Encode(cryped)
-- print('cryb ---', cryb)

-- local dcryb = mbedtls.base64Decode(cryb)
-- -- local newIV = string.sub(dcryb, 1, 16)
-- local dcryped = mbedtls.aesCBCDecrypt(dcryb, '1111111111111111', '1234567890abcdef')
-- print('dcryped --', dcryped)

print('md50', mbedtls.md5('1'))

local a, b = mbedtls.base64Decode('@')
print('base64Decode', a, b)


return utils