from scapy.all import sniff


def packet_callback(packet):
    print(packet.summary())


print("Capturing 10 packets...")
print("Open Google or YouTube in your browser...")

sniff(count=10, prn=packet_callback, store=False)

print("Capture completed!")
