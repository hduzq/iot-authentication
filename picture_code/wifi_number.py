import matplotlib.pyplot as plt

# Data
wifi_standards = [
    '802.11a', '802.11b', '802.11g', '802.11n (WiFi 4)',
    '802.11ac (WiFi 5)', '802.11ax (WiFi 6)'
]
max_speeds_mbps = [
    54, 11, 54, 600, 3470, 9600  # Converting Gbps to Mbps for uniformity
]

updated_wifi_standards = wifi_standards[2:]
updated_max_speeds_mbps = max_speeds_mbps[2:]
# Given each device communicates at a rate of 2KB per second
device_comm_rate_kbps = 2 * 8  # Convert KB to Kb (1 KB = 8 Kb)

# Calculate the maximum number of devices that each WiFi standard can theoretically handle
max_devices_per_standard = [speed / device_comm_rate_kbps for speed in updated_max_speeds_mbps]

# Creating the plot for maximum number of devices per WiFi standard
fig, ax = plt.subplots()
bars = ax.bar(updated_wifi_standards, max_devices_per_standard, color='yellow')

# Adding text for labels, title and custom x-axis tick labels, etc.
ax.set_ylabel('Maximum Number of Devices (K)')
ax.set_title('Max Devices Supported per Second by WiFi Standard')
ax.set_xticklabels(updated_wifi_standards, rotation=45, ha='right')
ax.bar_label(bars, fmt='%.0f')

plt.show()
