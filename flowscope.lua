local moon   = require "libmoon"
local device = require "device"
local stats  = require "stats"
local pktLib = require "packet"
local eth    = require "proto.ethernet"
local ip     = require "proto.ip4"
local log    = require "log"
local pcap   = require "pcap"
local pf     = require "pf"
local qq     = require "qq"
local S      = require "syscall"
local ffi    = require "ffi"
local colors = require "colors"
local pipe   = require "pipe"
local timer  = require "timer"
local flowtracker = require "flowtracker"
local ev = require "event"
local webServer = require "webserver"
local restApi	= require "restApi"

local jit = require "jit"
jit.opt.start("maxrecord=10000", "maxirconst=1000", "loopunroll=40")


function configure(parser)
	parser:argument("dev", "Devices to use."):args("+"):convert(tonumber)
	parser:option("--size", "Storage capacity of the in-memory ring buffer in GiB."):convert(tonumber):default("8")
	parser:option("--rate", "Rate of the generated traffic in buckets/s."):convert(tonumber):default("10")
	parser:option("--rx-threads", "Number of rx threads per device. If --generate is give, then number of traffic generator threads."):convert(tonumber):default("1"):target("rxThreads")
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
	log:setLevel(args.logLevel)
	if not args.generate then
		for i, dev in ipairs(args.dev) do
			args.dev[i] = device.config{
				port = dev,
				rxQueues = args.rxThreads,
				rssQueues = args.rxThreads
			}
		end
		device.waitForLinks()
	end

	local qq = qq.createQQ(args.size)
	for i, dev in ipairs(args.dev) do
		for i = 0, args.rxThreads - 1 do
			if args.generate then
				moon.startTask("traffic_generator", args, qq, i, nil, 200, args.rate)
			else
				moon.startTask("inserter", dev:getRxQueue(i), qq)
			end
		end
	end

	local pipes = {}
	for i = 1, args.dumperThreads do
		pipes[i] = pipe.newSlowPipe()
		moon.startTask("continuousDumper", args, qq, i, args.path, pipes[i])
	end

	-- start the webserver
	if args.apiAddress ~= nil then
		webServer.startWebserverTask(
		{
			port = args.apiPort,
			bind = args.apiAddress,
			init = 'initWebserverTask'
		}, args, pipes)
	end

	for i, v in ipairs(pipes) do
		-- libmoon has no destroy function for pipes
	end

	moon.startSharedTask("fillLevelChecker", args, qq)
	--moon.startTask("fillLevelChecker", args, qq)
	moon.waitForTasks()
	tracker:delete()
	qq:delete()
	log:info("[master]: Shutdown")
end

function inserter(rxQueue, qq)
	-- the inserter is C++ in libqq to get microsecond-level software timestamping precision
	qq:inserterLoop(rxQueue)
	log:info("[Inserter]: Shutdown")
end

function initWebserverTask(turbo, args, pipes)
	return restApi.start(turbo, args, pipes)
end

function traffic_generator(args, qq, id, packetSize, newFlowRate, rate)
	log:setLevel(args.logLevel)
	local packetSize = packetSize or 64
	local newFlowRate = newFlowRate or 0.5 -- new flows/s
	local concurrentFlows = 1000
	local rate = rate or 20 -- buckets/s
	local baseIP = parseIPAddress("10.0.0.2")
	local txCtr = stats:newManualTxCounter("Generator Thread #" .. id, "plain")
	local rateLimiter = timer:new(1.0 / rate)
	local newFlowTimer = timer:new(1.0 / newFlowRate)

	local buf = {}
	buf["ptr"] = ffi.new("uint8_t[?]", packetSize)
	buf["getData"] = function() return ffi.cast("void*", buf.ptr) end
	local pkt = pktLib.getUdp4Packet(buf)
	pkt:fill{pktLength = packetSize}
	pkt.ip4.src:set(baseIP - 1)
	pkt.ip4.dst:set(baseIP)
	pkt.ip4:setProtocol(ip.PROTO_UDP)
	pkt.ip4:setTTL(64)
	pkt.udp:setSrcPort(1000)
	pkt.udp:setDstPort(2000)
	pkt:dump()

	while moon.running() do
		local s1 = qq:enqueue()
		local ts = moon.getTime() * 10^6
		repeat
-- 			pkt.ip4.dst:set(baseIP)
			pkt.ip4.dst:set(baseIP + math.random(0, concurrentFlows - 1))
			if math.random(0, 20000000) == 0 then
				pkt.ip4:setTTL(70)
			else
				pkt.ip4:setTTL(64)
			end
		until not s1:store(ts, 0, packetSize, buf.ptr)
		txCtr:updateWithSize(s1:size(), packetSize)
		s1:release()
		if newFlowTimer:expired() then
			baseIP = baseIP + 1
			newFlowTimer:reset()
		end
		rateLimiter:wait()
		rateLimiter:reset()
	end
	txCtr:finalize()
	log:info("[Traffic Generator]: Shutdown")
end

function fillLevelChecker(args, qq)
	log:setLevel(args.logLevel)
	while moon.running() do
		print(green("[QQ] Stored buckets: ") .. qq:size() .. "/" .. qq:capacity() .. green(" Overflows: ") .. qq:getEnqueueOverflowCounter())
		moon.sleepMillisIdle(1000)
	end
	log:info("[fillLevelChecker]: Shutdown")
end

function filterExprFromTuple(tpl)
	local s = ""
	local ipAddr = ffi.new("union ip4_address")
	ipAddr:set(tpl.ip_src)
	s = s .. "src host " .. ipAddr:getString()
	ipAddr:set(tpl.ip_dst)
	s = s .. " src port " .. tonumber(tpl.port_src)
	ipAddr:set(tpl.ip_dst)
	s = s .. " dst host " .. ipAddr:getString()
	s = s .. " dst port " .. tonumber(tpl.port_dst)

	-- L4 Protocol
	local proto = tpl.proto
	if proto == ip.PROTO_UDP then
		proto = " udp"
	elseif proto == ip.PROTO_TCP then
		proto = " tcp"
	else
		proto = ""
	end
	s = s .. proto
	return s
end

function continuousDumper(args, qq, id, path, filterPipe)
	log:setLevel(args.logLevel)
	pcap:setInitialFilesize(2^21) -- 2 MiB
	local ruleSet = {} -- Used to maintain the rules
	local ruleList = {} -- Build from the ruleSet for performance
	local maxRules = args.maxRules
	local rxCtr = stats:newManualRxCounter("Dumper Thread   #" .. id, "plain")
	local lastTS = 0

	require("jit.p").start("l2s")
	while moon.running() do
		-- Get new filters
		-- TODO: loop until all messages are read
		local needRebuild = false
		local event = filterPipe:tryRecv(0)
		if event ~= nil then
			log:debug("[Dumper %i]: Got event %i, %s, %i", id, event.action, event.filter, event.timestamp or 0)
			if event.action == ev.create and ruleSet[event.id] == nil and #ruleList < maxRules then
				local triggerWallTime = wallTime()
				local pcapFileName = path .. "/" .. ("FlowScope-dump " .. os.date("%Y-%m-%d %H-%M-%S", triggerWallTime) .. " " .. event.id .. " part " .. id .. ".pcap"):gsub("[ /\\]", "_")
				local pcapWriter = pcap:newWriter(pcapFileName, triggerWallTime)
				ruleSet[event.id] = {pfFn = pf.compile_filter(event.filter), pcap = pcapWriter}
				--ruleSet[event.filter] = {pfFn = function() return false end, pcap = nil}
				needRebuild = true
			elseif event.action == ev.delete and ruleSet[event.id] ~= nil then
				ruleSet[event.id].timestamp = event.timestamp
				log:info("[Dumper %i#]: Marked rule %s as expired", id, event.id)
			end
		end

		-- Check for expired rules
		for k, v in pairs(ruleSet) do
			if v.timestamp ~= nil and lastTS > v.timestamp then
				if ruleSet[k].pcap then
					ruleSet[k].pcap:close()
				end
				log:info("[Dumper %i#]: Expired rule %s, %i > %i", id, k, lastTS, v.timestamp)
				ruleSet[k] = nil
				needRebuild = true
			end
		end

		-- Update ruleList
		if needRebuild then
			ruleList = {}
			for _, v in pairs(ruleSet) do
				ruleList[#ruleList+1] = {v.pfFn, v.pcap}
			end
			log:info("Dumper #%i: total number of rules: %i", id, #ruleList)
		end
		local storage = qq:tryDequeue()
		if storage == nil then
			goto skip
		end
		rxCtr:updateWithSize(storage:size(), 0)
		for i = 0, storage:size() - 1 do
			local pkt = storage:getPacket(i)
			local timestamp = pkt:getTimestamp()
			local data = pkt.data
			local len = pkt.len
			lastTS = tonumber(pkt.ts_vlan)
			-- Do not use ipairs() here
			for j = 1, #ruleList do
				local filter = ruleList[j][1]
				local pcap = ruleList[j][2]
				if filter(data, len) then
					if pcap then
						pcap:write(timestamp, data, len)
					end
				end
			end
		end
		storage:release()
		::skip::
	end
	require("jit.p").stop()
	rxCtr:finalize()
	for _, rule in pairs(ruleSet) do
		if rule.pcap then
			rule.pcap:close()
		else
			log:error("[Dumper #%i]: Rule got no pcap", id)
		end
	end
	log:info("[Dumper]: Shutdown")
end
