import simpy
import random

# 定义全局变量
reset_number = 0

def file_transfer(env, file_size, bandwidth, transfer_id, packet_loss_rate, delay_prob, max_delay, monitor_event):
    global reset_number
    """
    Simulate the file transfer over a network with potential packet loss and delays.
    """
    initial_file_size = file_size
    transfer_time = file_size / bandwidth + 0.1  # 模拟双向通信延迟100ms 0.1s
    reload_rate = packet_loss_rate / transfer_time  # 每次传输都有机会传错，近似模拟概率
    start_time = env.now
    print(f"Transfer {transfer_id} starting at {start_time:.2f}")

    while file_size > 0:
        # Simulate packet loss
        if random.uniform(0, 1) < reload_rate:
            print(f"Transfer {transfer_id}: Packet lost at {env.now:.2f}")
            # Simulate retransmission delay
            retransmission_delay = transfer_time / 2  # 模拟每次网络中断已经传输了一半
            file_size = initial_file_size
            reset_number += 1
            yield env.timeout(retransmission_delay)
        else:
            # Simulate potential network delay
            if random.uniform(0, 1) < delay_prob:
                delay = random.uniform(0, max_delay)
                print(f"Transfer {transfer_id}: Network delay of {delay:.2f} seconds at {env.now:.2f}")
                yield env.timeout(delay)

            # Transfer packet
            transfer_chunk_time = 1  # Simulating the transfer of 1MB at a time
            yield env.timeout(transfer_chunk_time)
            file_size -= bandwidth * transfer_chunk_time

    end_time = env.now
    total_time = end_time - start_time
    print(f"Transfer {transfer_id} completed at {end_time:.2f}, total time: {total_time:.2f} seconds")

    # 传输完成，通知监控器进程
    monitor_event.succeed()

def network(env, num_transfers, file_size, bandwidth, packet_loss_rate, delay_prob, max_delay):
    """
    Simulate multiple file transfers over a network.
    """
    # 创建一个监控器事件列表，用于追踪所有传输任务的完成状态
    monitor_events = []
    for i in range(num_transfers):
        monitor_event = env.event()
        monitor_events.append(monitor_event)
        env.process(file_transfer(env, file_size, bandwidth, i, packet_loss_rate, delay_prob, max_delay, monitor_event))
        yield env.timeout(random.expovariate(1.0))  # Simulate random start times

    # 等待所有传输任务完成
    for event in monitor_events:
        yield event

    # 所有传输任务完成后输出reset_number
    print(f"Total number of resets: {reset_number}")

def monitor(env, monitor_event):
    """
    Monitor all processes and print the reset number once all processes are done.
    """
    yield monitor_event
    print(f"Total number of resets: {reset_number}")

# Simulation parameters
totoal_bandwidth = 6.5  # Bandwidth in MB/s  such as 2.5MBps 20Mbps 6.5MBps 50Mbps
num_transfers = 1000  # Number of simultaneous file transfers
bandwidth = totoal_bandwidth / num_transfers  # Bandwidth in MB/s for each device
file_size = 32.1  # Size of each file in MB
reload_rate = 0.05  # Probability of packet loss
delay_prob = 0.01  # Probability of network delay
max_delay = 2  # Maximum network delay in seconds

# Create the SimPy environment and run the simulation
env = simpy.Environment()
env.process(network(env, num_transfers, file_size, bandwidth, reload_rate, delay_prob, max_delay))

# Start the monitor process
env.process(monitor(env, env.timeout(0)))  # 使用一个超时事件作为初始的监控器事件
env.run()
