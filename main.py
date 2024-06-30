import random

import pydivert
import time
from prettytable import PrettyTable

# Global Variables

# This list stores the blocked IP Addresses we detect, and we drop data from those addresses
blocked_networks = []

# This dict stores counters of how many packets each address has sent in the past 50 packets received by the localhost
dos_stats = {}

# This list stores the previous 50 packets received by the localhost.
packets_history = []

# This float stores the time it took the last 50 packets to be received on the localhost
sum_time_delta = 0

# This float stores the time the previous packet was received at
last_packet_recv_time = 0

# This float stores the average time between packets that is randomly checked for DDOS detection
random_time_interval = 0


class PotentialAttacker:
    """
    The PotentialAttacker class is used to store information regarding the data packets source machines flowing through
    """

    def __init__(self, ip_address=''):
        self.ip_address = ip_address
        self.packets_sent = 1
        self.last_packet_from_host_time = time.time()
        self.time_since_own_packet = 0
        self.time_since_global_packet = 0

    def __str__(self):
        # Create a PrettyTable object
        table = PrettyTable()
        table.field_names = ["Attribute", "Value"]

        # Add rows to the table
        table.add_row(["IP Address", self.ip_address])
        table.add_row(["Packets Sent", self.packets_sent])
        table.add_row(["Time Since Last Packet", self.time_since_own_packet])

        # Return the string representation of the table
        return str(table)


def initiate_win_divert():
    """
    The function is responsible for initiating the packet inspection process using WinDivert
    :return: WinDivert Object
    """
    # Init WinDivert Object
    win_divert = pydivert.WinDivert()

    # We start diverting packets to our WinDivert instance
    win_divert.open()

    # We return the WinDivert object
    return win_divert


# Main function
def main():
    """
    The function is responsible for the firewall main action which is to inspect each packet and drop it if needed
    :return: None
    """
    # Initiating the packet inspection process
    win_divert = initiate_win_divert()

    while True:
        # Current packet read by the WinDivert
        p = win_divert.recv()

        # We extract the source address from the IPV4/IPV6 Header
        try:
            if p.ipv4 is None:
                packet_source_address = p.ipv6.src_addr
            else:
                packet_source_address = p.ipv4.src_addr

            # For each packet, we check if it comes from a blocked address. If so - we drop the packet.
            if packet_source_address in blocked_networks:
                print(f'Received packet from {packet_source_address} which is blocked, dropping packet')
                continue

        # If no IP header, the packet is corrupted/modified and we drop it
        except AttributeError:
            print(f'Packet has no header, dropping packet')
            continue

        # If the p.direction is 1, it means the packet were received from the outer internet to localhost
        is_incoming_packet = p.direction == 1

        if is_incoming_packet:

            # We check for DOS behaviour of the packet and the sender
            sender_is_suspicious = check_dos_behaviour(packet_source_address)

            # If suspicious, we mark the address as blocked and drop the packet
            if sender_is_suspicious:
                blocked_networks.append(packet_source_address)
                continue
        # If we have reached here, it means the packet seems OK and we let it continue its journey
        win_divert.send(p)


def check_dos_behaviour(packet_source_address):
    """
    The function is responsible for detecting DOS patterns and alerting the packet inspection process
    :param packet_source_address:
    :return: Boolean
    """
    global sum_time_delta
    global last_packet_recv_time
    global random_time_interval

    # If it is the first package inspected, we store the current time as the last packet receive time
    if last_packet_recv_time == 0:
        last_packet_recv_time = time.time()
    else:
        # If it is not the first packet, we add the time since the last packet to the total time.
        # The total time represents the time it took all the packets received until now to be received.
        sum_time_delta += time.time() - last_packet_recv_time

        # We update the last packet receive time to the current packet
        last_packet_recv_time = time.time()

    try:
        # If the address is already in the dos_stats object - it means we already encountered it
        if packet_source_address in dos_stats:
            # If so - we increment the packet counter by one
            dos_stats[packet_source_address].packets_sent += 1

            # We update the time since we got a packet from the same address
            dos_stats[packet_source_address].time_since_own_packet = time.time() - dos_stats[
                packet_source_address].last_packet_from_host_time

            # We update the time since we got a packet from any address
            dos_stats[packet_source_address].time_since_global_packet = time.time() - last_packet_recv_time

            # We update the time of the recent packet we got from the host (which is the current packet)
            dos_stats[packet_source_address].last_packet_from_host_time = time.time()

        else:
            # If it is the first time we encounter data from this address, we initiate a PotentialAttacker Object
            dos_stats[packet_source_address] = PotentialAttacker(packet_source_address)

        # We also push the address to the packets history list
        packets_history.append(dos_stats[packet_source_address])

        # If the packets_history has more than 50 packets, we need to get rid of the oldest one
        if len(packets_history) > 50:

            # If the PotentialAttacker's packet counter is bigger than 1, we decrement the counter by 1
            if packets_history[0].packets_sent > 1:
                packets_history[0].packets_sent -= 1

            # If the PotentialAttacker's packet counter is 1, that means we need to remove it completely
            else:
                dos_stats.pop(packets_history[0].ip_address)

            # We subtract the time since global packet to keep the average time delta updated
            sum_time_delta -= packets_history[0].time_since_global_packet

            # Of course, we discard the first element in the list (which is the oldest packet)
            packets_history.pop(0)

        """
        In anytime, if some address has sent over 60% of packets in the last 50 packets, and the time intervals between packets
        is very fast,  it might be DOSing. In that case, the function will return True. If not, it returns False.
        """

        # DOS Check
        if dos_stats[packet_source_address].packets_sent >= 30 and dos_stats[
            packet_source_address].time_since_own_packet * 2 <= sum_time_delta / len(packets_history):
            print(dos_stats[packet_source_address])
            print(f'Average time between packets {sum_time_delta / len(packets_history)}')
            print(f"{packet_source_address} is probably DOSing, blocking address...")
            return True

        # DDOS Check
        # We look for extreme changes in incoming data rate, regardless of the identity of the source machine
        # If the random average time between packets is unreasonably higher, we might be experiencing a DDOS attack
        if random_time_interval <= sum_time_delta / len(packets_history) * 2 and random_time_interval != 0:
            print("DDOS pattern detected")
            return True

        # Every 3 packets (average) which test and store the current average of time between packets
        if random.randint(1, 3) == 3:
            random_time_interval = sum_time_delta / len(packets_history)

        return False

    except AttributeError as e:
        print(e)
        return False


if __name__ == '__main__':
    main()
