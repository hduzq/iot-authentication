import matplotlib.pyplot as plt

# Bandwidth scenarios in Mbps
bandwidth_scenarios_mbps = [15, 30, 50]

# Each device communicates at a rate of 2KB per second, which is equivalent to 16Kbps (2KB * 8 bits per KB)
device_comm_rate_kbps = 16  # 2KB/s converted to Kbps

# Calculate the maximum number of devices for each bandwidth scenario
max_devices_scenarios = [(bandwidth * 1000) / device_comm_rate_kbps for bandwidth in bandwidth_scenarios_mbps]

# Creating the plot for maximum number of devices for each bandwidth scenario
fig, ax = plt.subplots()
bars = ax.bar(['15 Mbps', '30 Mbps', '50 Mbps'], max_devices_scenarios, color='red')

# Adding text for labels, title and custom x-axis tick labels, etc.
ax.set_ylabel('Maximum Number of Devices')
ax.set_title('Max Devices Supported by Different Bandwidths')
ax.set_xticks(range(len(bandwidth_scenarios_mbps)))
ax.set_xticklabels(['15 Mbps', '30 Mbps', '50 Mbps'])
ax.bar_label(bars, fmt='%.0f')

plt.show()
