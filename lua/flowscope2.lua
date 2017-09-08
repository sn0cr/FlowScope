local lm = require "libmoon"
local device = require "device"
local ffi = require "ffi"
local flowtracker = require "flowtracker2"

function configure(parser)
    parser:argument("module", "Path to user-defined analysis module")
    parser:argument("dev", "Devices to use."):args("+"):convert(tonumber)
    parser:option("--size", "Storage capacity of the in-memory ring buffer in GiB."):convert(tonumber):default("8")
    parser:option("--rate", "Rate of the generated traffic in buckets/s."):convert(tonumber):default("10")
    parser:option("--rx-threads", "Number of rx threads per device. If --generate is given, then number of traffic generator threads."):convert(tonumber):default("1"):target("rxThreads")
    parser:option("--analyze-threads", "Number of analyzer threads."):convert(tonumber):default("1"):target("analyzeThreads")
    parser:option("--dump-threads", "Number of dump threads."):convert(tonumber):default("1"):target("dumperThreads")
    parser:option("--path", "Path for output pcaps."):default(".")
    parser:option("--log-level", "Log level"):default("WARN"):target("logLevel")
    parser:option("--max-rules", "Maximum number of rules"):convert(tonumber):default("100"):target("maxRules")
    parser:flag("--generate", "Generate traffic instead of reading from a device"):default(False)
    parser:option("-p --api-port", "Port for the HTTP REST api."):convert(tonumber):default("8000"):target("apiPort")
    parser:option("-b --api-bind", "Bind to a specific IP address. (for example 127.0.0.1)"):target("apiAddress")
    parser:option("-t --api-token", "Token for authorization to api."):default("hardToGuess"):target("apiToken"):count("*")
    local args = parser:parse()
    return args
end


function master(args)
    local userModule = loadfile(args.module)()
    local tracker = flowtracker.new {
        stateType = userModule.stateType,
        -- default = ffi.new(userModule.stateType, { other defaults go here })
    }

    -- this part should be wrapped by flowscope and exposed via CLI arguments
    for i, dev in ipairs(args.dev) do
        args.dev[i] = device.config{
            port = dev,
            rxQueues = args.rxThreads,
            rssQueues = args.rxThreads
        }
        for threadId = 0, args.rxThreads - 1 do
            -- get from QQ or from a device queue
            lm.startTask(flowtracker.analyzerTask, tracker, args.module, args.dev[i]:getRxQueue(threadId))
        end
    end
    device.waitForLinks()
    -- end wrapped part
    lm.waitForTasks()
    tracker:delete()
    log:info("[master]: Shutdown")
end