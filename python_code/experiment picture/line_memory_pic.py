import matplotlib.pyplot as plt

# Define the data
x = [100, 300, 500, 1000]
line1 = [100, 300, 500, 1000]
line2 = [3366.9, 10184.2, 16957, 33811.6]
line3 = [3300.5, 9876.9, 16487.2, 32966.7]
line4 = [715.6, 2155.1, 3586.5, 7183.5]
line5 = [613.6, 1845.3, 3071.7, 6119.1]

# Create the plot
plt.figure(figsize=(10, 6))

# Plot each line with thicker lines
plt.plot(x, line1, marker='o', label='Our Scheme', linewidth=2.5)
plt.plot(x, line2, marker='o', label='BL_1', linewidth=2.5)
plt.plot(x, line4, marker='o', label='BL_2', linewidth=2.5)
plt.plot(x, line3, marker='o', label='BL_3', linewidth=2.5)
plt.plot(x, line5, marker='o', label='BL_4', linewidth=2.5)

# Customize the plot
plt.xlabel('Number of devices', fontsize=20)
plt.ylabel('Total Data Transfer Volume (MB)', fontsize=20)
plt.legend(fontsize=15)
plt.grid(True)

# Set larger tick labels
plt.xticks(fontsize=15)
plt.yticks(fontsize=15)

# Adjust the y-axis limits
plt.ylim(0, 35000)  # Adjust this range as needed to highlight differences

plt.savefig('line_memory_pic.pdf', format='pdf')
# Show the plot
plt.show()
