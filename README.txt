High Level Summary:
The analysis_pcap_tcp.py code analyzes a pcap file and extracts certain information regarding amount of flows, as well as the source port, source IP, destination port, destination IP and throughput of each flow. It also determines the sequence numbers, acknowledgement numbers, and window size of the first two transactions of each flow. In addition it keeps track of the first 3 congestion window sizes, the number of retransmissions due to triple duplicate ACKS, and the number of retransmisisons due to timeouts. 

Instructions:
Ensure the desired pcap file is in an accessible location the program can access 
Run the code with the file location passed as an argument
EX (For Terminal): python analysis_pcap_tcp.py assignment2.pcap 
assignment2.pcap can be replaced with any desired pcap file. 

Estimations for Part A:

Code uses flags for SYN and ACK to determine when a flow starts, where if the TCP is flagged with SYN and not ACK, it knows the flow starts there. It then records the details of the flow regarding its source ip/port, destination ip/port, timestamp, and adds a variable to track throughput. It will also determine the window scale using dpkt.tcp.parse_opts(tcp.opts).
Code uses flags for SYN and ACK to determine when the second part of the handshake is done (If both are flagged)
Code uses flags for SYN and ACK to determine when the third part of the handshake is done. If the second part of handshake has been marked, it will set it to the third part if it also detects the ACK being flagged with the SYN not being flagged. 
Once the third part of the handshake is determined, the code will make room for a record of the next 2 transactions identified by the source port.
If the program determines that the handshake is on the third part, and the current tcp data has data, it will add information regarding its sequence number, acknowledgement number, and window size based on the scale to the already made record for the source port.
If the program encounters the FIN flag, it will then change the stage and prepare the code to calculate the throughput and then move onto the next move.
For each transaction, including the handshake, the code will record the amount of bytes sent for that flow
The throughput is calculated by taking the total bytes for that flow, and divide it by the difference between the current timestamp and the original timestamp marked at the beginning of the flow. 

Estimations for Part B:

Code calculates RTT by measuring time between ACK packets
Sorts packets by timestamp
Groups packets into RTT intervals
Calculates the congestion window size as the sum of data bytes within each RTT interval
We see that the congestion windows grow as more packets are viewed in a flow
Code looks for same sequence number appearing twice, while keeping track of acks.
If same sequence number appears, and past 3 acks are the same, cause is triple duplicate, otherwise timeout.
