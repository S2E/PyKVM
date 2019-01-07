--[[
This is a bare minimum S2E config file to demonstrate the use of libs2e with PyKVM.
Please refer to the S2E documentation for more details.
]]--

s2e = {
    kleeArgs = {}
}

plugins = {
    "BaseInstructions",
    "TestCaseGenerator",
    "ExecutionTracer"
}

pluginsConfig = {}

-- Generate concrete data when paths terminate
pluginsConfig.TestCaseGenerator = {
   generateOnSegfault = false
}
