import socket

# 创建一个 socket 对象
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 连接到本地的 12345 端口
s.connect(('127.0.0.1', 12345))

# 发送一些数据
s.sendall(b'Hello, World!')

# 接收一些数据
data = s.recv(1024)

# 打印收到的数据
print('Received', repr(data))

# 关闭连接
s.close()