-- the "protected" script behind the chain (fixture)
local Players = game:GetService("Players")
local RunService = game:GetService("RunService")

local function greet(name)
	return "hello, " .. name
end

local count = 0
for i = 1, 5 do
	count = count + i
end

print(greet("keyforge"), count, Players.LocalPlayer and Players.LocalPlayer.Name)
