import matplotlib.pyplot as plt

# Define the data
x = [100, 300, 500, 1000]
line1 = [101.3, 304.5, 507.2, 1014.8]
line2 = [794.0554, 1894.825, 2954.472, 5596.422]
line3 = [636.912, 1641.898, 2697.864, 5227.868]
line4 = [191.474, 419.362, 644.6358, 1186.628]
line5 = [181.358, 382.514, 575.772, 1079.09]

add_values = [100, 300, 500, 1000]
line4 = [l4 + av for l4, av in zip(line4, add_values)]
line5 = [l5 + av for l5, av in zip(line5, add_values)]

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
plt.ylabel('Update Time (seconds)', fontsize=20)
plt.legend()
plt.grid(True)


# Set larger tick labels
plt.xticks(fontsize=15)
plt.yticks(fontsize=15)
# Show the plot
plt.savefig('line_pic_time.pdf', format='pdf')
plt.show()
