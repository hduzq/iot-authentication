import matplotlib.pyplot as plt
import numpy as np

# Define the data
categories = ['OTA-Key', 'Scheme 1', 'Scheme 2', 'Scheme 3', 'Scheme 4']
group1 = [1.47, 1.52, 1.42, 1.53]
group2 = [11.1676, 33.6574, 176.866, 78.2342]
group3 = [11.1366, 33.1772, 175.77474, 76.9358]
group4 = [2.9436, 6.9728, 35.7854, 15.7054]
group5 = [3.04244, 6.73072, 35.8326, 15.9902]

# Combine all groups into a list for easier plotting
all_groups = [group1, group2, group3, group4, group5]

# Set the positions and width for the bars
bar_width = 0.15
r = np.arange(len(categories))

# Create the plot
plt.figure(figsize=(10, 6))

# Plot each set of bars within each category
for i in range(len(group1)):
    bar_positions = [x + i * bar_width for x in r]
    plt.bar(bar_positions, [group[i] for group in all_groups], width=bar_width, edgecolor='grey', label=f'f{i+1}')

# Customize the plot
# plt.xlabel('Schemes', fontsize=20)
plt.ylabel('Update time (Seconds)', fontsize=20)
# plt.title('Comparison of Different Schemes', fontsize=20)
plt.xticks([r + 2 * bar_width for r in range(len(categories))], categories, fontsize=20)
plt.yticks(fontsize=15)
plt.legend(fontsize=15)
plt.grid(True)

# Save the plot as a PDF
plt.savefig('bar_chart.pdf', format='pdf')

# Show the plot
plt.show()
