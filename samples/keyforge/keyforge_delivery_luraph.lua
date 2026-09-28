-- fixture: the body the /v1/load endpoint serves
local key = _G.script_key
assert(type(key) == "string" and #key > 0, "KeyForge: no script key")

local url = "https://cdn-luraph.example-keyforge.test/payload.enc?k=" .. key
local body = game:HttpGet(url)
assert(type(body) == "string" and #body > 0, "KeyForge: empty delivery")

local b64 = body:gsub("%s+", "")
local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local lookup = {}
for i = 1, #alphabet do
	lookup[alphabet:sub(i, i)] = i - 1
end

local bytes = {}
for i = 1, #b64, 4 do
	local a = lookup[b64:sub(i, i)] or 0
	local b = lookup[b64:sub(i + 1, i + 1)] or 0
	local c = lookup[b64:sub(i + 2, i + 2)] or 0
	local d = lookup[b64:sub(i + 3, i + 3)] or 0
	local n = a * 262144 + b * 4096 + c * 64 + d
	bytes[#bytes + 1] = math.floor(n / 65536) % 256
	bytes[#bytes + 1] = math.floor(n / 256) % 256
	bytes[#bytes + 1] = n % 256
end

local out = {}
for i = 1, #bytes do
	out[i] = string.char(bit32.bxor(bytes[i], string.byte(key, (i - 1) % #key + 1)))
end

local chunk = loadstring(table.concat(out))
assert(chunk, "KeyForge: payload did not compile")
return chunk()
