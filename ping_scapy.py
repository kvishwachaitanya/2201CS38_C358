from scapy.all import *

def ping(dest_ip, count=4, ttl=64, size=64, timeout=1):
    try:
        rtts = []
        for i in range(count):
            packet = IP(dst=dest_ip, ttl=ttl)/ICMP()/Raw(load='X'*size)
            reply = sr1(packet, timeout=timeout)
            if reply:
                rtts.append(reply.time)
                print(f"{reply.src} is online, RTT={reply.time*1000:.2f} ms")
            else:
                print(f"{dest_ip} is offline")
        
        if rtts:
            print(f"Packet loss: {100 - len(rtts) * 100 / count:.2f}%")
            print(f"RTT min/avg/max: {min(rtts)*1000:.2f}/{sum(rtts)/len(rtts)*1000:.2f}/{max(rtts)*1000:.2f} ms")
    
    except Exception as e:
        print(f"Error: {e}")

# Example usage:
ping("8.8.8.8")
