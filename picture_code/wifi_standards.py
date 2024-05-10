import matplotlib.pyplot as plt

# Data
wifi_standards = [
    '802.11a', '802.11b', '802.11g', '802.11n (WiFi 4)',
    '802.11ac (WiFi 5)', '802.11ax (WiFi 6)'
]
max_speeds_mbps = [
    54, 11, 54, 600, 3470, 9600  # Converting Gbps to Mbps for uniformity
]

# Removing the first two entries from the data for 802.11a and 802.11b
updated_wifi_standards = wifi_standards[2:]
updated_max_speeds_mbps = max_speeds_mbps[2:]

# Creating the updated plot
fig, ax = plt.subplots()
bars = ax.bar(updated_wifi_standards, updated_max_speeds_mbps, color='teal')

# Adding text for labels, title and custom x-axis tick labels, etc.
ax.set_ylabel('Maximum Speed (Mbps)')
ax.set_title('Maximum Theoretical Bandwidth of WiFi Standards (Updated)')
ax.set_xticklabels(updated_wifi_standards, rotation=45, ha='right')
ax.bar_label(bars)

plt.show()
