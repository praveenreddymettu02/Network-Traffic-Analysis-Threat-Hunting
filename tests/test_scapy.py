from scapy.all import sniff, get_if_list


def packet_callback(pkt):
    print(pkt.summary())


print("=" * 60)
print("SCAPY CAPTURE TEST")
print("=" * 60)

# Show available interfaces
print("\nAvailable interfaces:")
interfaces = get_if_list()
for i, iface in enumerate(interfaces):
    print(f"  {i}: {iface}")

print("\n" + "=" * 60)
print("Testing capture on interface: Wi-Fi")
print("Waiting for packets... (timeout 15 seconds)")
print("Generate traffic by pinging or browsing websites")
print("=" * 60)

try:
    sniff(iface="Wi-Fi", prn=packet_callback, count=10, timeout=15)
    print("\n[OK] Capture test completed!")
except Exception as e:
    print(f"\n[ERROR] Error: {e}")
    print("\nTry changing interface name to one from the list above")
