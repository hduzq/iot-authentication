from concurrent.futures import ThreadPoolExecutor
from device import start_client
import time

# 定义模拟设备的函数
def simulate_device(device_id):
    # 模拟设备活动
    print(f"Device {device_id} is starting.")
    start_client(device_id)
    # time.sleep(1)  # 模拟设备工作时间
    print(f"Device {device_id} has finished.")


def start_devices(device_count):
    with ThreadPoolExecutor(max_workers=2) as executor:  # 设置线程池大小
        for device_id in range(device_count):
            executor.submit(simulate_device, device_id)

# 启动10000个模拟设备
start_devices(100000)
# for _ in range(10):  # 比如启动10个客户端
#     start_client(_)
