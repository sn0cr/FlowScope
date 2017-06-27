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

function configure(parser)
	parser:argument("dev", "Devices to use."):args("+"):convert(tonumber)
	parser:option("--size", "Storage capacity of the in-memory ring buffer in GiB."):convert(tonumber):default("8")
	parser:option("--rate", "Rate of the generated traffic in buckets/s."):convert(tonumber):default("10")
	parser:option("--rx-threads", "Number of rx threads per device. If --generate is give, then number of traffic generator threads."):convert(tonumber):default("1"):target("rxThreads")
	parser:option("--analyze-threads", "Number of analyzer threads."):convert(tonumber):default("1"):target("analyzeThreads")
	parser:option("--dump-threads", "Number of dump threads."):convert(tonumber):default("1"):target("dumperThreads")
	parser:option("--path", "Path for output pcaps."):default(".")
	parser:flag("--generate", "Generate traffic instead of reading from a device"):default(False)
	local args = parser:parse()
	return args
end

function master(args)
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
				moon.startTask("traffic_generator", qq, i, nil, 1, args.rate)
			else
				moon.startTask("inserter", dev:getRxQueue(i), qq)
			end
		end
	end
	
	local pipes = {}
	for i = 1, args.dumperThreads do
		pipes[i] = pipe.newSlowPipe()
		moon.startTask("continuousDumper", qq, i, args.path, pipes[i])
	end
	
-- 	local tracker = flowtracker.createTBBMapv4(2^20)

	local tracker = flowtracker.createTBBTracker(2^20)
	moon.startTask("swapper", tracker, pipes)
	
	for i = 1, args.analyzeThreads do
-- 		moon.startTask("dummyAnalyzer", qq, i)
-- 		moon.startTask("TBBAnalyzer", qq, i, tracker, pipes)
		moon.startTask("TBBTrackerAnalyzer", qq, i, tracker, pipes)
	end
	
	for i, v in ipairs(pipes) do
		-- libmoon has no destroy function for pipes
	end
	
	moon.startSharedTask("fillLevelChecker", qq)
	--moon.startTask("fillLevelChecker", qq)
	moon.waitForTasks()
	tracker:delete()
	qq:delete()
end

function inserter(rxQueue, qq)
	-- the inserter is C++ in libqq to get microsecond-level software timestamping precision
	qq:inserterLoop(rxQueue)
end

function swapper(tracker, pipes)
	local buf = ffi.new("struct ipv4_5tuple[?]", 128)
	while moon.running() do
		local c = tracker:swapper(buf, 128)
		for i = 0, tonumber(c) - 1 do
			local event = {action = "delete", filter = filterExprFromTuple(buf[i])}
			print(bred("[Swapper]: send event:"), event.action, event.filter)
			for _, pipe in ipairs(pipes) do
				pipe:send(event)
			end
		end
	end
end

function traffic_generator(qq, id, packetSize, newFlowRate, rate)
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
		local ts = moon.getTime()
		repeat
-- 			pkt.ip4.dst:set(baseIP)
			pkt.ip4.dst:set(baseIP + math.random(0, concurrentFlows - 1))
			if math.random(0, 10000000) == 0 then
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
end

function fillLevelChecker(qq)
	while moon.running() do
		print(green("[QQ] Stored buckets: ") .. qq:size() .. "/" .. qq:capacity() .. green(" Overflows: ") .. qq:getEnqueueOverflowCounter())
		moon.sleepMillisIdle(1000)
	end
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
	s = s .. " udp"
	return s
end

-- TODO
function buildFilterExpr(pkt)
	return "src host " .. pkt.ip4.src:getString() .. " src port " .. pkt.udp:getSrcPort() .. 
			" dst host " .. pkt.ip4.dst:getString() .. " dst port " .. pkt.udp:getDstPort()
end

function TBBAnalyzer(qq, id, hashmap, pipes)
	local hashmap = hashmap
	local rxCtr = stats:newManualRxCounter("TBB Analyzer Thread #" .. id, "plain")
	local epsilon = 2  -- allowed area around the avrg. TLL
	
	local tuple = ffi.new("struct ipv4_5tuple")
	
	while moon.running() do
		local storage = qq:peek()
		for i = 0, storage:size() - 1 do
			local pkt = storage:getPacket(i)
			rxCtr:updateWithSize(1, pkt.len)
			local parsedPkt = pktLib.getUdp4Packet(pkt)
			tuple.ip_dst = parsedPkt.ip4:getDst()
			tuple.ip_src = parsedPkt.ip4:getSrc()
			tuple.port_dst = parsedPkt.udp:getDstPort()
			tuple.port_src = parsedPkt.udp:getSrcPort()
			tuple.proto = parsedPkt.ip4:getProtocol()
			local TTL = parsedPkt.ip4:getTTL()
			
			local ano = hashmap:checkAndUpdate(tuple, TTL, epsilon)
			if ano ~= 0 then
				local event = {action = "create", filter = buildFilterExpr(parsedPkt)}
				print(bred("[TBB Analyzer Thread #".. id .."]") .. ": Anomaly detected:", ano, TTL, event.action, event.filter)
				for _, pipe in ipairs(pipes) do
					pipe:send(event)
				end
			end
		end
		storage:release()
	end
	rxCtr:finalize()
end

function TBBTrackerAnalyzer(qq, id, hashmap, pipes)
	local hashmap = hashmap
	local rxCtr = stats:newManualRxCounter("TBB Tracker Analyzer Thread #" .. id, "plain")
	local epsilon = 2  -- allowed area around the avrg. TLL
	local tuple = ffi.new("struct ipv4_5tuple")
	
	local acc = flowtracker.createAccessor()
	
	while moon.running() do
		local storage = qq:peek()
		for i = 0, storage:size() - 1 do
-- 			local ts = moon.getTime()
			local pkt = storage:getPacket(i)
			rxCtr:updateWithSize(1, pkt.len)
			local parsedPkt = pktLib.getUdp4Packet(pkt)
			tuple.ip_dst = parsedPkt.ip4:getDst()
			tuple.ip_src = parsedPkt.ip4:getSrc()
			tuple.port_dst = parsedPkt.udp:getDstPort()
			tuple.port_src = parsedPkt.udp:getSrcPort()
			tuple.proto = parsedPkt.ip4:getProtocol()
			local TTL = parsedPkt.ip4:getTTL()
			
			--local acc = hashmap:access(tuple)
			hashmap:access2(tuple, acc)
			local ttlData = acc:get()
			local ano = flowtracker.updateAndCheck(ttlData, TTL, epsilon)
			--local ano = math.random(0, 10000000) == 0 or 0
			acc:release()
			if ano ~= 0 then
				--local event = {action = "create", filter = buildFilterExpr(parsedPkt)}
				local event = {action = "create", filter = filterExprFromTuple(tuple)}
				print(bred("[TBB Analyzer Thread #".. id .."]") .. ": send event", event.action, event.filter)
				for _, pipe in ipairs(pipes) do
					pipe:send(event)
				end
			end
-- 			local ts2 = moon.getTime()
-- 			print(1, ts2 - ts)
		end
		storage:release()
	end
	rxCtr:finalize()
	acc:free()
end

function dummyAnalyzer(qq, id)
	local rxCtr = stats:newManualRxCounter("QQ Dummy Analyzer Thread #" .. id, "plain")
	while moon.running() do
		local storage = qq:peek()
		for i = 0, storage:size() - 1 do
			local pkt = storage:getPacket(i)
			rxCtr:updateWithSize(1, pkt.len)
		end
		storage:release()
	end
	rxCtr:finalize()
end

function continuousDumper(qq, id, path, filterPipe)
	local ruleSet = {} -- Used to maintain the rules
	local ruleList = {} -- Build from the ruleSet for performance
	local rxCtr = stats:newManualRxCounter("Dumper Thread   #" .. id, "plain")
	local ruleExpirationTimer = timer:new(30)
	
	while moon.running() do
-- 		if ruleExpirationTimer:expired() then
-- 			print("Filter rules expired")
-- 			for _, rule in ipairs(ruleList) do
-- 				if rule.pcap then
-- 					rule.pcap:close()
-- 				end
-- 			end
-- 			ruleExpirationTimer:reset()
-- 		end
		
		-- Get new filters
		-- TODO: loop until all messages are read
		local event = filterPipe:tryRecv(0)
		if event ~= nil then
			if event.action == "create" and ruleSet[event.filter] == nil then
				local triggerWallTime = wallTime()
				local pcapFileName = path .. "/FlowScope-dump_" .. os.date("%Y-%m-%d %H:%M:%S", triggerWallTime) .. "_" .. event.filter .. ".pcap"
				local pcapWriter = pcap:newWriter(pcapFileName, triggerWallTime)
				ruleSet[event.filter] = {pfFn = pf.compile_filter(event.filter), pcap = pcapWriter}
				--ruleSet[event.filter] = {pfFn = function() end, pcap = nil}
			elseif event.action == "delete" and ruleSet[event.filter] ~= nil then
				if ruleSet[event.filter].pcap then
					ruleSet[event.filter].pcap:close()
				end
				print("Dumper #" .. id .. ": rule deletion:", event.filter)
				ruleSet[event.filter] = nil
			end
			
			-- Update ruleList
			ruleList = {}
			for _, v in pairs(ruleSet) do
				ruleList[#ruleList+1] = v
			end
			print("Dumper #" .. id .. ": total number of rules:", #ruleList)
		end
		
		local storage = qq:dequeue()
		for i = 0, storage:size() - 1 do
			local pkt = storage:getPacket(i)
			local timestamp = pkt:getTimestamp()
			rxCtr:updateWithSize(1, pkt:getLength())
			
			for _, rule in ipairs(ruleList) do
				if rule.pfFn(pkt.data, pkt.len) then
-- 					print("Dumper #" .. id .. ": Got match!")
					if rule.pcap then
						rule.pcap:write(timestamp, pkt.data, pkt.len)
					end
				end
			end
		end
		storage:release()
	end
	rxCtr:finalize()
	for _, rule in ipairs(ruleSet) do
		if rule.pcap then
			rule.pcap:close()
		end
	end
end

