try:
    f = open("firewallrules2.json","r")
    y = json.load(f)
    f.close()
    if("ListOfBannedIpAddr" in y):
        if(type(y["ListOfBannedIpAddr"])==list):
            ListOfBannedIpAddr = y["ListOfBannedIpAddr"]
        else:
            print("Invalid ListOfBannedIpAddr in rule file. Defaulting to []")
            ListOfBannedIpAddr = []
    else:
        print("ListOfBannedIpAddr missing in rule file. Defaulting to []")
        ListOfBannedIpAddr = []
            
    if("ListOfBannedPorts" in y):
        if(type(y["ListOfBannedPorts"])==list):
            ListOfBannedPorts = y["ListOfBannedPorts"]
        else:
            print("Invalid ListOfBannedPorts in rule file. Defaulting to []")
            ListOfBannedPorts = []
    else:
        print("ListOfBannedPorts missing in rule file. Defaulting to []")
        ListOfBannedPorts = []
            
    if("ListOfBannedPrefixes" in y):
        if(type(y["ListOfBannedPrefixes"])==list):
            ListOfBannedPrefixes = y["ListOfBannedPrefixes"]
        else:
            print("Invalid ListOfBannedPrefixes in rule file. Defaulting to []")
            ListOfBannedPrefixes = []
    else:
        print("ListOfBannedPrefixes missing in rule file. Defaulting to []")
        ListOfBannedPrefixes = []

    if("TimeThreshold" in y):
        if(type(y["TimeThreshold"])==int):
            TimeThreshold = y["TimeThreshold"]
        else:
            print("Invalid TimeThreshold in rule file. Defaulting to 10")
            TimeThreshold = 10
    else:
        print("TimeThreshold missing in rule file. Defaulting to 10")
        TimeThreshold = 10

    if("PacketThreshold" in y):
        if(type(y["PacketThreshold"])==int):
            PacketThreshold = y["PacketThreshold"]
        else:
            print("Invalid PacketThreshold in rule file. Defaulting to 100")
            PacketThreshold = 100
    else:
        print("PacketThreshold missing in rule file. Defaulting to 100")
        PacketThreshold = 100

    if("BlockPingAttacks" in y):
        if(y["BlockPingAttacks"]=="True" or y["BlockPingAttacks"]=="False"):
            BlockPingAttacks = eval(y["BlockPingAttacks"])
        else:
            print("Invalid BlockPingAttacks in rule file. Defaulting to True")
            BlockPingAttacks = True
    else:
        print("BlockPingAttacks missing in rule file. Defaulting to True")
        BlockPingAttacks = True

except FileNotFoundError:
    print("Rule file (firewallrules.json) not found, setting default values")
    ListOfBannedIpAddr = [] 
    ListOfBannedPorts = []
    ListOfBannedPrefixes = []
    TimeThreshold = 10 #sec
    PacketThreshold = 100    
    BlockPingAttacks = True

def firewall(pkt):
	DictOfPackets={}
	sca = IP(pkt.get_payload())

	if any (sca.src.startswith(prefix) for prefix in ListOfBannedPrefixes):
		print("Prefix of " + sca.src + " is banned by the firewall.")
		pkt.drop()
		return
	
	
	if(sca.src in ListOfBannedIpAddr):
		print(sca.src, "is a incoming IP address that is banned by the firewall.")
		pkt.drop()
		return 

	if(sca.haslayer(TCP)):
		t = sca.getlayer(TCP)
		if(t.dport in ListOfBannedPorts):
			print(t.dport, "is a destination port that is blocked by the firewall.")
			pkt.drop()
			return 

	if(sca.haslayer(UDP)):
		t = sca.getlayer(UDP)
		if(t.dport in ListOfBannedPorts):
			print(t.dport, "is a destination port that is blocked by the firewall.")
			pkt.drop()
			return 
	if BlockPingAttacks and sca.haslayer(ICMP):
		t=sca.getlayer(ICMP)
		if t.type == 8:
			if sca.src in DictOfPackets:
				packet_times=DictOfPackets[sca.src]
				packet_times.append(time.time())
				packet_times=[t for t in packet_times if time.time() - t <= TimeThreshold]
				if len(packet_times) > PacketThreshold:
					print(f"Ping by {sca.src} blocked by firewall(thresholdcrossed)")			
					pkt.drop()
					return
				DictOfPackets[sca.src]=packet_times
			else:
				DictOfPackets[sca.src]=[time.time()]
	pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(1,firewall)

try:
    nfqueue.run()
except KeyboardInterrupt:
	pass

nfqueue.unbind()
