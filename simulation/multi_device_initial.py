import simpy
import random

# 设置基本参数
FILE_SIZE_MB = 30  # 文件大小，单位为MB
BANDWIDTH_MBPS = 2.5  # 带宽，单位为MB/s (20 Mbps)
RTT_S = 0.1  # 往返延迟时间，单位为秒 (100 ms)
LOSS_RATE = 0.05  # 丢包率 5%
NUM_CLIENTS = 100  # 同时传输的设备数量


# 网络传输过程模拟
def transfer_file(env, client_id):
    total_time = 0
    total_data = 0
    while True:
        start_time = env.now
        transmission_time = FILE_SIZE_MB / BANDWIDTH_MBPS
        yield env.timeout(transmission_time + RTT_S)  # 包括传输时间和延迟

        # 检查是否发生丢包
        if random.random() < LOSS_RATE:
            print(f"Client {client_id}: Packet lost at time {env.now:.2f}s, restarting...")
            continue  # 发生丢包，重新开始传输

        # 成功传输
        total_time = env.now - start_time
        total_data += FILE_SIZE_MB
        print(f"Client {client_id}: File successfully transferred in {total_time:.2f}s with total data {total_data}MB")
        break


# 创建并运行模拟
env = simpy.Environment()
for i in range(NUM_CLIENTS):
    env.process(transfer_file(env, i))
env.run()

