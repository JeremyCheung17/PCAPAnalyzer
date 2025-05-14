import dpkt
import sys
import socket

SENDER_IP = '130.245.145.12'
RECEIVER_IP = '128.208.2.198'

def parse_pcap(file):
    f = open(file, 'rb')
    pcap = dpkt.pcap.Reader(f)
    flows = {}
    first_two_transactions = {}
    retransmissions = {}  # Tracker for retransmissions
    ack_tracker = {}  # Tracker for ACK counts
    stage = 0
    scale = 0
    i = 1
    acks = []
    cwnd_sizes = {}
    sent_packets = {}
    acked_packets = {}
    last_ack_time = {}
    estimated_rtt = {}
    
    # Start parsing
    for timestamp, buf in pcap:
        # Sets tcp
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        # Get Flow
        if ((tcp.flags & 0x02) and not (tcp.flags & 0x10)):
            flows[tcp.sport] = []
            flows[tcp.sport].append((socket.inet_ntoa(ip.src), tcp.dport, socket.inet_ntoa(ip.dst), timestamp))
            flows[tcp.sport].append(0)
            scale = pow(2, int.from_bytes(next(s for opt, s in dpkt.tcp.parse_opts(tcp.opts) if opt == 3)))
            retransmissions[tcp.sport] = {"seen": set(), "triple_ack": 0, "total": 0}
            ack_tracker[tcp.sport] = {}
        # Checks if stage 2 of handshake
        if (tcp.flags & 0x02) and (tcp.flags & 0x10):
            stage = 1
            continue
        # Checks if stage 3 of handshake + creates transaction
        if (tcp.flags & 0x10) and not (tcp.flags & 0x02) and (stage == 1):
            first_two_transactions[tcp.sport] = []
            stage = 2
        # Fills in transaction
        if (tcp.sport in first_two_transactions) and (stage == 2):
            if tcp.data:
                first_two_transactions[tcp.sport].append((tcp.seq, tcp.ack, (tcp.win * scale)))
        # Add to total bytes sent
        if tcp.sport in flows:
            flows[tcp.sport][1] += len(tcp)
            
            # Record sent packets for cwnd estimation
            if tcp.data and socket.inet_ntoa(ip.src) == SENDER_IP:
                if tcp.sport not in sent_packets:
                    sent_packets[tcp.sport] = []
                sent_packets[tcp.sport].append((tcp.seq, len(tcp.data), timestamp))
                
        # Track retransmissions and track packets for cwnd estimation
        if (socket.inet_ntoa(ip.dst) == SENDER_IP):
            acks.append(tcp.ack)
            
            # Record ACK times for RTT estimation
            if tcp.sport in flows:
                if tcp.dport not in acked_packets:
                    acked_packets[tcp.dport] = []
                
                if tcp.ack not in acked_packets[tcp.dport]:
                    acked_packets[tcp.dport].append(tcp.ack)
                    
                    # Estimate RTT if possible
                    if tcp.dport in last_ack_time:
                        if tcp.dport not in estimated_rtt:
                            estimated_rtt[tcp.dport] = timestamp - last_ack_time[tcp.dport]
                    
                    last_ack_time[tcp.dport] = timestamp
                
        if tcp.data:
            if tcp.sport in retransmissions:
                # Check if this sequence number has been seen before
                if tcp.seq in retransmissions[tcp.sport]["seen"]:
                    retransmissions[tcp.sport]["total"] += 1  # Total retransmissions

                    # Track duplicate ACKs for the same sequence number
                    ack = tcp.ack
                    if ack not in ack_tracker[tcp.sport]:
                        ack_tracker[tcp.sport][ack] = 1
                    else:
                        ack_tracker[tcp.sport][ack] += 1

                    # Check for triple duplicate ACKs
                    if ack_tracker[tcp.sport][ack] == 3:
                        retransmissions[tcp.sport]["triple_ack"] += 1
                else:
                    retransmissions[tcp.sport]["seen"].add(tcp.seq)
            
        # Check for FIN flag
        if (tcp.flags & 0x01) and (tcp.dport in flows):
            stage = 3
            continue
            
        # Calculate throughput and resets stage
        if (stage == 3):
            duration = timestamp - flows[tcp.sport][0][3]
            flows[tcp.sport].append(flows[tcp.sport][1] / duration)
            
            # Estimate congestion window sizes
            if tcp.sport in sent_packets and len(sent_packets[tcp.sport]) > 0:
                # Basic RTT estimation if not already done
                if tcp.sport not in estimated_rtt:
                    # Default RTT estimation if we couldn't measure it
                    estimated_rtt[tcp.sport] = 0.1  # 100ms as fallback
                
                # Sort sent packets by timestamp
                sorted_packets = sorted(sent_packets[tcp.sport], key=lambda x: x[2])
                
                # Group packets by RTT intervals
                rtt = estimated_rtt.get(tcp.sport, 0.1)
                rtt_groups = []
                current_group = []
                base_time = sorted_packets[0][2]
                
                for seq, size, time in sorted_packets:
                    if time - base_time <= rtt:
                        current_group.append((seq, size))
                    else:
                        if current_group:
                            rtt_groups.append(current_group)
                            current_group = [(seq, size)]
                        base_time = time
                
                # Add the last group if not empty
                if current_group:
                    rtt_groups.append(current_group)
                
                # Calculate congestion window sizes in MSS units
                # Assuming standard MSS of 1460 bytes
                MSS = 1460
                cwnd_sizes[tcp.sport] = [sum(size for _, size in group) // MSS for group in rtt_groups]
            
            stage = 0
            
    # Print results
    for flow in flows:
        print(f"Flow {i}: ({flow}, {flows.get(flow)[0][0]}, {flows.get(flow)[0][1]}. {flows.get(flow)[0][2]})")
        i += 1
        print(f"Throughput: {flows.get(flow)[2]}")
        print("Transaction 1:")
        print(f"Sequence Number: {first_two_transactions.get(flow)[0][0]} ACK Number: {first_two_transactions.get(flow)[0][1]} Receive Window Size: {first_two_transactions.get(flow)[0][2]}")
        print("Transaction 2:")
        print(f"Sequence Number: {first_two_transactions.get(flow)[1][0]} ACK Number: {first_two_transactions.get(flow)[1][1]} Receive Window Size: {first_two_transactions.get(flow)[1][2]}")
        print(f"Total Retransmissions: {retransmissions.get(flow, {}).get('total', 0)}")
        print(f"Triple Duplicate ACK Retransmissions: {retransmissions.get(flow, {}).get('triple_ack', 0)}")
        print(f"Timeout Retransmissions: {retransmissions.get(flow, {}).get('total', 0) - retransmissions.get(flow, {}).get('triple_ack', 0)}")
        
        # Print congestion window sizes
        print("Estimated Congestion Window Sizes (in MSS units, at roughly RTT intervals):")
        if flow in cwnd_sizes and cwnd_sizes[flow]:
            window_count = min(3, len(cwnd_sizes[flow]))
            for j in range(window_count):
                print(f"Window {j+1}: {cwnd_sizes[flow][j]} MSS")
        else:
            print("No congestion window data available for this flow.")
            
        print("-----------------------------------------------------------------------------------------")

# Take pcap file as argument
if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(1)
    parse_pcap(sys.argv[1])