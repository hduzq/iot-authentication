import pandas as pd

# 读取性能数据
df = pd.read_csv('performance_data.csv')

# 显示数据的前几行
print(df.head())

# 基本的数据分析，例如计算每个事件的平均CPU和内存使用率
average_usage = df.groupby('After connectionMade').mean()
print(average_usage)


import matplotlib.pyplot as plt

# 绘制每个事件的平均CPU使用率
average_usage['cpu_usage'].plot(kind='bar')
plt.title('Average CPU Usage by Event')
plt.xlabel('Event')
plt.ylabel('Average CPU Usage (%)')
plt.show()

# 绘制每个事件的平均内存使用率
average_usage['memory_usage'].plot(kind='bar', color='orange')
plt.title('Average Memory Usage by Event')
plt.xlabel('Event')
plt.ylabel('Average Memory Usage (%)')
plt.show()
