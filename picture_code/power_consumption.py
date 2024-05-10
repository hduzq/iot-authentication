import matplotlib.pyplot as plt
import numpy as np

# Data
categories = ['Without Encryption', 'With Encryption']
values_min = [0.76, 0.80]  # Min values for each category
values_max = [0.78, 0.82]  # Max values for each category
mean_values = [np.mean([0.76, 0.78]), np.mean([0.80, 0.82])]  # Mean values

# Calculate percentage increase based on mean values
percentage_increase = ((mean_values[1] - mean_values[0]) / mean_values[0]) * 100

# Creating the plot
fig, ax = plt.subplots()
bars = ax.bar(categories, mean_values, color=['#FFD700', '#4682B4'])  # Gold and Steel Blue colors
ax.errorbar(categories, mean_values,
            yerr=[np.subtract(mean_values, values_min), np.subtract(values_max, mean_values)],
            fmt='none', capsize=5, ecolor='gray', elinewidth=2)  # Error bars to show the range

# Adding text for labels, title and custom x-axis tick labels, etc.
ax.set_ylabel('Power Consumption (W)')
ax.set_title('Power Consumption Comparison')
ax.set_xticks(np.arange(len(categories)))
ax.set_xticklabels(categories)
ax.bar_label(bars, fmt='%.2fW')

# Highlighting the increase in percentage
plt.figtext(0.5, 0.85, f'Increase: {percentage_increase:.2f}%', ha='center', fontsize=12, color='#4682B4')

plt.show()
