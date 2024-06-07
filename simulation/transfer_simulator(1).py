import simpy
import random

class NetworkMonitor:
    def __init__(self):
        self.total_bandwidth_used = 0
        self.end_time = 0
        self.start_time = 0xFFFFFFF
        self.complete_num = 0

    def update_bandwidth_usage(self, amount):
        self.total_bandwidth_used += amount

def file_transfer(transfer_id, file_size):
    global env, bandwidth_container, packet_loss_rate, delay_prob, max_delay, monitor, total_bandwidth
    
    start_time = env.now
    monitor.start_time = min(start_time, monitor.start_time)
    # print(f"Transfer {transfer_id} starting at {start_time:.2f}")
    remain_file_size = int(file_size)

    while remain_file_size > 0:
        # 这里表示获取带宽的量，和服务器的分配策略有关
        # 发送一个包发多久，和服务器的分配策略有关
        transfer_chunk_time = 5
        obtained_bandwith = min(total_bandwidth, 0.1)
        with bandwidth_container.get(obtained_bandwith) as req:
            yield req
        
            # Simulate packet loss
            # 单次传输失败率=总失败率/传输次数 固件大小/每次传输大小=传输次数
            if random.uniform(0, 1) < packet_loss_rate/(file_size/(obtained_bandwith*transfer_chunk_time)):
                # print(f"Transfer {transfer_id}: Packet lost at {env.now:.2f}")
                # Simulate retransmission delay
                # 这里假设，如果失败了，就立即全部重传
                remain_file_size = int(file_size)
                yield env.timeout(0)
            else:
                # Simulate potential network delay
                # 正常的网络波动
                if random.uniform(0, 1) < delay_prob:
                    delay = random.uniform(0, max_delay)
                    # print(f"Transfer {transfer_id}: Network delay of {delay:.2f} seconds at {env.now:.2f}")
                    yield env.timeout(delay)

                # Transfer packet
                # TODO: 这里应该是网速*传输时间
                transfer_amount = obtained_bandwith * transfer_chunk_time
                yield env.timeout(transfer_chunk_time)
                remain_file_size -= transfer_amount
                # Update bandwidth usage
                monitor.update_bandwidth_usage(transfer_amount)
            bandwidth_container.put(obtained_bandwith)

    end_time = env.now
    monitor.end_time = max(end_time, monitor.end_time)
    monitor.complete_num += 1
    # print(f"Transfer {transfer_id} completed at {end_time:.2f}, total time: {end_time - start_time:.2f} seconds")

def network():
    global env, file_size, bandwidth_container, packet_loss_rate, delay_prob, max_delay, num_transfers
    for i in range(num_transfers):
        env.process(file_transfer(i, int(file_size)))
        # 此处是各个设备发起传输请求的时刻
        yield env.timeout(random.expovariate(1.0))

monitor = NetworkMonitor()
file_size = 32.1
total_bandwidth = 6.5 
num_transfers = 1000
packet_loss_rate = 0.05 # 总的失败概率，1000份文件按照这个概率大约需要1050份传送
delay_prob = 0 
max_delay = 0
env = simpy.Environment()
bandwidth_container = simpy.Container(env, init=total_bandwidth, capacity=total_bandwidth)
env.process(network())
env.run()

assert(monitor.complete_num == num_transfers)
print(f"Total bandwidth used: {monitor.total_bandwidth_used:.2f} MB", f"Total time {monitor.end_time - monitor.start_time}")
