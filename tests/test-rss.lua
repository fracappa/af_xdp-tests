local mg     = require "moongen"
local memory = require "memory"
local device = require "device"
local stats  = require "stats"
local log    = require "log"

function configure(parser)
	parser:description("Generates traffic.")
	parser:argument("txDev", "Device to transmit from."):convert(tonumber)
	parser:argument("rxDev", "Device to receive from."):convert(tonumber)
	parser:option("-r --rate", "Transmit rate in Mbit/s."):default(0):convert(tonumber)
	parser:option("-p --packet-rate", "Transmit rate in Mpps."):default(0):convert(tonumber)
	parser:option("-s --size", "Packet size (incl. CRC)."):default(64):convert(tonumber)
	parser:option("-t --time", "Run time of the test."):default(60):convert(tonumber)
	parser:option("-o --output", "Output file.")
	parser:option("-c --core", "Number of cores."):default(1):convert(tonumber)
	parser:option("-n --dstnum", "Number of different dst addresses"):default(1):convert(tonumber)
	parser:option("-d --drop-share", "Share of packets to drop (based on last bit of dst mac addr)"):default(0):convert(tonumber)
end

function master(args)
	txDev = device.config({port = args.txDev, txQueues = args.core})
	if rxDev ~= txDev then
		rxDev = device.config({port = args.rxDev, rxQueues = 1})
	else
		rxDev = txDev
	end
	device.waitForLinks()

	if args.packet_rate > 0 then
		args.rate = args.packet_rate * (args.size - 4) * 8
	end 

	if args.rate > 0 then
		txDev.totalRate = nil
		for i=0,args.core-1 do
			txDev:getTxQueue(i):setRate(args.rate / args.core)
		end
	end

	for i=0,args.core-1 do
		mg.startTask("loadSlave", txDev:getTxQueue(i), args.size - 4,
		             args.dstnum, args.drop_share, i)
	end

	mg.setRuntime(args.time)

	local txCtr = stats:newDevTxCounter(txDev)
	local rxCtr = stats:newDevRxCounter(rxDev)
	
	while mg.running() do
		txCtr:update()
		rxCtr:update()

		mg.sleepMillisIdle(10)
	end

	txCtr:finalize()
	rxCtr:finalize()

	local txMpps, tmp1, tmp2, txPkts = txCtr:getStats()
	local rxMpps, tmp1, tmp2, rxPkts = rxCtr:getStats()

	log:info("RESULTS:")
	log:info("TX %.02f Mpps, %d pkts", txMpps.avg, txPkts)
	log:info("RX %.02f Mpps, %d pkts", rxMpps.avg, rxPkts)
	log:info("LOSS %.02f%%", (txPkts - rxPkts) / txPkts * 100)

	if args.output then
		file = io.open(args.output , "w")
		file:write("tx-mpps;tx-pkts;rx-mpps;rx-pkts\n")
		file:write(string.format("%.02f;%d;%.02f;%d\n", txMpps.avg, txPkts,
		                         rxMpps.avg, rxPkts))
		file:close()
	end
end

function loadSlave(txQueue, size, dstnum, drop_share, seed)
	math.randomseed(seed)
	minIp = parseIPAddress("10.0.0.0")
	redirMac = parseMacAddress("3c:fd:fe:af:ec:30", false)
	dropMac = parseMacAddress("3d:fd:fe:af:ec:30", false)
 
	local mem = memory.createMemPool(function(buf)
		buf:getUdpPacket():fill({
			ethSrc="3c:fd:fe:af:ec:48",
			-- ethDst="76:fe:57:28:4e:30",
			ethDst="3c:fd:fe:af:ec:30",
			ip4Src="10.0.0.0",
			ip4Dst="172.0.0.0",
			udpSrc=5000,
			udpDst=80,
			pktLength=size
		})
	end)
	local bufs = mem:bufArray()

	while mg.running() do
		bufs:alloc(size)

		for i, buf in ipairs(bufs) do
			local pkt = buf:getUdpPacket()
			-- pkt.udp.src = math.random(0, 0xffff)
			-- pkt.udp.dst = math.random(0, 0xffff)
			if dstnum > 1 then
				pkt.ip4.src:set(minIp + math.random(0, dstnum - 1))
				-- pkt.ip4.dst:set(minIp + math.random(0, dstnum - 1))
			end
			if drop_share > 0 then
				if math.random() < drop_share then
					pkt.eth.dst = dropMac
				else
					pkt.eth.dst = redirMac
				end
			end
		end

		bufs:offloadUdpChecksums()

		txQueue:send(bufs)
	end
end
