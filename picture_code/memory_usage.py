# Creating a plot with a linear scale on the x-axis, set specifically to the requested maximum of 10000
from matplotlib import pyplot as plt

devices = [1, 10, 500, 1000, 3000, 5000, 8000, 10000]
memory_usage = [1.8, 3.3, 16.4, 37.9, 103.3, 176.4, 254.7, 434.2]

plt.figure(figsize=(10, 5))
plt.plot(devices, memory_usage, marker='o', color='blue')
plt.title('Average Memory Usage vs. Number of Devices (Linear Scale)')
plt.xlabel('Number of Devices')
plt.ylabel('Average Memory Usage (MB)')
plt.grid(True)
plt.xticks([1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000])  # Setting ticks at every 1000 units

plt.show()
