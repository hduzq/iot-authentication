import matplotlib.pyplot as plt

# Preparing the data based on the user's specifications
categories = ['OTA Key', 'Akkaoui et al.', 'Asokan, N. et al (ASSURED)', 'Wang et al.', 'Xu et al.', 'Langiu et al.(Upkit)']
values = [41, None, 58.4, 64, None, 100]

# Creating a bar chart, setting None values to 0 for plotting but not labeling them
cleaned_values = [0 if v is None else v for v in values]

plt.figure(figsize=(12, 6))
bars = plt.bar(categories, cleaned_values, color='skyblue')

# Adding values on top of the bars, skipping None values
for bar, val in zip(bars, values):
    if val is not None:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval, f'{val}KB', ha='center', va='bottom')

plt.xlabel('Related Work')
plt.ylabel('Increase in Firmware Memory Size (KB)')
plt.title('Comparison of Firmware Memory Size Increase')
plt.xticks(rotation=45, ha='right')
plt.grid(axis='y', linestyle='--', alpha=0.7)

# Show the plot
plt.tight_layout()
plt.show()
