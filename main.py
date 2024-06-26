import pydivert

# This list stores the blocked IP Addresses we detect, and we drop data from coming from those addresses
blocked_networks = []

# This dict stores counters of how many packets each address has sent in the past 20 packets received by the localhost
dos_stats = {}

# This list stores the previous 50 packets received by the localhost.
dos_packets_history = []


# Main function
def main():
    # Init WinDivert Object
    windi = pydivert.WinDivert()

    # We start diverting packets to our WinDivert instance
    windi.open()

    while True:
        # Current packet read by the WinDivert
        p = windi.recv()

        p_src_addr = None

        # If the p.direction is 1, it means the packet were received from the outer internet to localhost
        if p.direction == 1:
            # We extract the source address from the IPV4/IPV6 Header
            try:
                if p.ipv4 is None:
                    p_src_addr = p.ipv6.src_addr
                else:
                    p_src_addr = p.ipv4.src_addr

            # If no header, the packet is corrupted/modified and we drop it
            except AttributeError as e:
                print(f'Packet has no header, dropping packet')
                continue

            # We check for DOS behaviour of the packet and the sender
            sender_is_suspicious = check_dos_behaviour(p, p_src_addr)

            # If suspicious, we mark the address as blocked
            if sender_is_suspicious:
                blocked_networks.append(p_src_addr)

        # For each packet, we check if it comes from a blocked address. If so - we drop the packet.
        if p_src_addr in blocked_networks and p.direction == 1:
            continue

        # If we reached here, it means the packet seems OK and we let it continue
        windi.send(p)


# This function checks for DOS patterns in the packets flow
def check_dos_behaviour(p, p_src_addr):
    try:
        # If the address is already in the dos_stats object - it means we already encountered it
        if p_src_addr in dos_stats:
            # If so - we increment the counter by one
            dos_stats[p_src_addr] += 1
        else:
            # If it is the first time we encounter data from this address, we initiate a counter
            dos_stats[p_src_addr] = 1

        # We also push the address to the dos_packets_history
        dos_packets_history.append(p_src_addr)

        # If the dos_packets_history has more than 50 packets, we need to get rid of the oldest one
        if len(dos_packets_history) > 50:

            # If the address's counter is bigger than 1, we decrement the counter by 1
            if dos_stats[dos_packets_history[0]] > 1:
                dos_stats[dos_packets_history[0]] -= 1

            # If the address's counter is 1, that means we need to remove it completely
            else:
                dos_stats.pop(dos_packets_history[0])
            # Of course, we discard the first element in the list (which is the oldest packet)
            dos_packets_history.pop(0)
        """
        In anytime, if some address has sent over 60% of packets in the last 50 packets,
        We assume it might be DOSing. In that case, the function will return True. If not, it returns False.
        """
        print(dos_stats)
        if dos_stats[p_src_addr] >= 30:
            print(f"{p_src_addr} is probably DOSing, dropping packet")
            return True
        return False
    except AttributeError as e:
        print(e)
        return False


if __name__ == '__main__':
    main()
