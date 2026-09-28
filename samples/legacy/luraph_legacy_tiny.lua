-- A miniature legacy-style loader: aliased builtins, a payload assembled at
-- runtime, one loadstring capture, then a tail error. The normalizer must
-- inline the aliases without changing the captured bytes.
local P = loadstring
local z = pcall
local ch = string.char
local payload = ch(114, 101, 116, 117, 114, 110, 32, 52, 50)
local fn = P(payload, "Tiny")
print(fn())
error("tail-error")
