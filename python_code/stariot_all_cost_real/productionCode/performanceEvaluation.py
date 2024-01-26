import threading

from device import start_client


def run_client_thread():
    # 这个函数用于在一个线程中启动客户端
    start_client()

# 启动多个线程
for i in range(1000):  # 假设你想启动5个线程
    t = threading.Thread(target=run_client_thread)
    t.start()
