import matplotlib.pyplot as plt
import numpy as np

# Data
categories = ['Without Protocol', 'With Protocol']
values = [923188, 945736]

# Calculate percentage increase
percentage_increase = ((values[1] - values[0]) / values[0]) * 100

# Creating the plot
fig, ax = plt.subplots()
bars = ax.bar(categories, values, color=['blue', 'green'])

# Adding text for labels, title and custom x-axis tick labels, etc.
ax.set_ylabel('Bytes')
ax.set_title('Communication Cost Comparison')
ax.set_xticks(np.arange(len(categories)))
ax.set_xticklabels(categories)
ax.bar_label(bars)

# Highlighting the increase in percentage
plt.figtext(0.5, 0.85, f'Increase: {percentage_increase:.2f}%', ha='center', fontsize=12, color='green')

plt.show()
