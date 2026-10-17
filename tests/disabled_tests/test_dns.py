from scapy.all import sniff, DNS, IP, get_if_list


def packet_callback(pkt):
    if DNS in pkt:
        print("=" * 60)
        print("🔴 DNS PACKET DETECTED!")
        print(f"Summary: {pkt.summary()}")

        dns = pkt[DNS]
        if dns.qd:
            for q in dns.qd:
                try:
                    domain = q.qname.decode()
                    if domain.endswith('.'):
                        domain = domain[:-1]
                    print(f"📌 Domain: {domain}")
                except Exception:
                    print(f"📌 Domain: {q.qname}")

        if pkt.haslayer(IP):
            print(f"📌 Source IP: {pkt[IP].src}")
            print(f"📌 Dest IP: {pkt[IP].dst}")

        print("=" * 60)
        print()


print("=" * 60)
print("🔍 FINDING WORKING INTERFACE")
print("=" * 60)

# Get all interfaces
interfaces = get_if_list()
print(f"\n📡 Available interfaces: {interfaces}")

# 🔥 Use the NPF device from previous test
working_iface = r"\Device\NPF_{21E3D564-E338-43C0-8D92-0084857F625F}"

print(f"\n📡 Testing: {working_iface}")
print("Waiting for ANY packets... (timeout 15 seconds)")
print("Generate traffic: ping google.com or open websites")
print("-" * 60)

try:
    sniff(
        iface=working_iface,
        prn=packet_callback,
        count=5,
        timeout=15,
    )
    print(f"\n✅ Test completed on {working_iface}")
except Exception as e:
    print(f"\n❌ Failed: {e}")
