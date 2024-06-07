import simpy
import random

def file_transfer(env, file_size, bandwidth, transfer_id, network, packet_loss_rate, delay_prob, max_delay):
    """
    Simulate the file transfer over a network with potential packet loss and delays.
    """
    initial_file_size =file_size
    transfer_time = file_size / bandwidth
    start_time = env.now
    print(f"Transfer {transfer_id} starting at {start_time:.2f}")

    while file_size > 0:
        # Simulate packet loss
        if random.uniform(0, 1) < packet_loss_rate:
            print(f"Transfer {transfer_id}: Packet lost at {env.now:.2f}")
            # Simulate retransmission delay
            retransmission_delay = transfer_time/2 # 模拟每次网络中断已经传输了一半
            # file_size = initial_file_size
            yield env.timeout(retransmission_delay)
        else:
            # Simulate potential network delay
            if random.uniform(0, 1) < delay_prob:
                delay = random.uniform(0, max_delay)
                print(f"Transfer {transfer_id}: Network delay of {delay:.2f} seconds at {env.now:.2f}")
                # file_size = initial_file_size
                yield env.timeout(delay)

            # Transfer packet
            transfer_chunk_time = 1  # Simulating the transfer of 1MB at a time
            file_size -= bandwidth
            # yield env.timeout(transfer_chunk_time)

    end_time = env.now
    print(f"Transfer {transfer_id} completed at {end_time:.2f}")

# process function
def network(env, num_transfers, file_size, bandwidth, packet_loss_rate, delay_prob, max_delay):
    """
    Simulate multiple file transfers over a network.
    """
    for i in range(num_transfers):
        env.process(file_transfer(env, file_size, bandwidth, i, network, packet_loss_rate, delay_prob, max_delay))
        yield env.timeout(random.expovariate(1.0))  # Simulate random start times

# Simulation parameters
totoal_bandwidth =2.5 # Bandwidth in MB/s  such as 2.5MBps 20Mbps 6.5MBps 50Mbps

num_transfers = 400 # Number of simultaneous file transfers
bandwidth = totoal_bandwidth/num_transfers  # Bandwidth in MB/s for each device

file_size = 32.1 # Size of each file in MB
packet_loss_rate = 0.01  # Probability of packet loss
delay_prob = 0.01  # Probability of network delay
max_delay = 2  # Maximum network delay in seconds

# Create the SimPy environment and run the simulation
env = simpy.Environment()
env.process(network(env, num_transfers, file_size, bandwidth, packet_loss_rate, delay_prob, max_delay))
env.run()
