import matplotlib.pyplot as plt

# Preparing the new data based on the user's updated specifications
categories = ['OTA Key', 'Akkaoui et al.', 'Asokan, N. et al (ASSURED)', 'Wang et al.', 'Xu et al.', 'Langiu et al.(Upkit)']
values = [60, 3, 40, 2, None, 2]  # Using average for ranges

# Creating a bar chart, setting None values to 0 for plotting but not labeling them
cleaned_values = [0 if v is None else v for v in values]

plt.figure(figsize=(10, 10))

# Assigning unique styles for each bar
bars = plt.bar(categories, cleaned_values, width=0.5)

# Define styles and colors
styles = ['//', None, None, None, None, None]
colors = ['#66CDAA', '#F1C40F', '#F1C40F', '#F1C40F', '#F1C40F', '#F1C40F']


# Apply styles and colors to each bar
for bar, style, color in zip(bars, styles, colors):
    if style:
        bar.set_hatch(style)
    bar.set_facecolor(color)

# Adding values on top of the bars, skipping None values
for bar, val in zip(bars, values):
    if val is not None:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval, f'{val}', ha='center', va='bottom', fontsize=20)

plt.ylabel('Number of Devices Handled per Mbps', fontsize=20)
plt.xticks(rotation=45, ha='right', fontsize=14)  # Adjust the fontsize for categories here
plt.yticks(fontsize=16)  # Adjust the fontsize for y-axis values here
plt.grid(axis='y', linestyle='--', alpha=0.7)

# Adjusting the top margin to make sure labels fit within the figure
plt.subplots_adjust(top=0.85)  # Adjust the top margin here

# Show the plot
plt.tight_layout()
plt.show()
