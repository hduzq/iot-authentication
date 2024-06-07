import simpy
import random

# 定义全局变量
reset_number = 0


def file_transfer(env, file_size, bandwidth, transfer_id, network, reload_rate, monitor_event):
    """
    Simulate the file transfer over a network with potential packet loss and delays.
    """
    global reset_number
    initial_file_size = file_size
    # transfer_time = file_size / bandwidth + 0.1  # 模拟双向通信延迟100ms 0.1s
    transfer_time = file_size / bandwidth
    reload_rate = reload_rate / transfer_time  # 每次传输都有机会传错，近似模拟概率
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

        transfer_chunk_time = 1  # Simulating the transfer of one bandwidth at a time
        file_size -= bandwidth * transfer_chunk_time
        yield env.timeout(transfer_chunk_time)

    end_time = env.now
    print(f"Transfer {transfer_id} completed at {end_time:.2f} s")
    # 传输完成，通知监控器进程
    monitor_event.succeed()


def network(env, num_transfers, file_size, bandwidth, reload_rate):
    """
    Simulate multiple file transfers over a network.
    """

    # 创建一个监控器事件列表，用于追踪所有传输任务的完成状态
    monitor_events = []

    for i in range(num_transfers):
        monitor_event = env.event()
        monitor_events.append(monitor_event)
        env.process(file_transfer(env, file_size, bandwidth, i, network,reload_rate,monitor_event))
        yield env.timeout(random.expovariate(1.0))  # Simulate random start times
    print("total file trans number: " + str(num_transfers + reset_number))

    # 等待所有传输任务完成
    for event in monitor_events:
        yield event
    print(f"Total number of resets: {num_transfers + reset_number}")


def monitor(env, monitor_event):
    """
    Monitor all processes and print the reset number once all processes are done.
    """
    yield monitor_event
    # 所有传输任务完成后输出reset_number


# Simulation parameters
totoal_bandwidth = 6.5  # Bandwidth in MB/s  such as 2.5MBps 20Mbps 6.5MBps 50Mbps
num_transfers = 1000  # Number of simultaneous file transfers 100 300 500 1000
bandwidth = totoal_bandwidth / num_transfers  # Bandwidth in MB/s for each device
file_size = 32.1  # Size of each file in MB
reload_rate = 0.05  # Probability of packet loss

# Create the SimPy environment and run the simulation
env = simpy.Environment()
# monitor_event = env.event()
env.process(network(env, num_transfers, file_size, bandwidth, reload_rate))

# Start the monitor process
# Start the monitor process
env.process(monitor(env, env.timeout(0)))  # 使用一个超时事件作为初始的监控器事件
env.run()
