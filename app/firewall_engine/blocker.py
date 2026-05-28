blocked_ips = set()

def block_ip(ip_address):

    if ip_address not in blocked_ips:

        blocked_ips.add(ip_address)

        print("\n=================================")
        print(f"BLOCKED IP: {ip_address}")
        print("Reason: Suspicious activity detected")
        print("=================================\n")

def is_blocked(ip_address):

    return ip_address in blocked_ips