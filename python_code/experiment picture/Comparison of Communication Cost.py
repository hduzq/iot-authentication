import matplotlib.pyplot as plt

# Preparing the new data based on the user's updated specifications
categories = ['OTA Key', 'Akkaoui et al.', 'Asokan, N. et al (ASSURED)', 'Wang et al.', 'Xu et al.', 'Langiu et al.(Upkit)']
values = [1863, (200+900)/2 * 1000, 2647, 64000, None, 100000]  # Convert KB to bytes for consistency

# Creating a bar chart, setting None values to 0 for plotting but not labeling them
cleaned_values = [0 if v is None else v for v in values]

plt.figure(figsize=(10, 12))
bars = plt.bar(categories, cleaned_values, color='skyblue',width=0.6)

# Adding values on top of the bars, skipping None values
for bar, val in zip(bars, values):
    if val is not None:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval, f'{val}B' if val < 1024 else f'{val/1000}KB', ha='center', va='bottom', fontsize=20)

# plt.xlabel('Related Work',fontsize=30)
plt.ylabel('Communication Cost(B)',fontsize=20)
# plt.title('Comparison of Communication Cost for Key Update',fontsize=25)
plt.xticks(rotation=45, ha='right')
plt.grid(axis='y', linestyle='--', alpha=0.7)

plt.xticks(rotation=45, ha='right', fontsize=14)  # Adjust the fontsize for categories here
plt.yticks(fontsize=16)  # Adjust the fontsize for y-axis values here
plt.subplots_adjust(top=0.70) # Adjust the top margin here
# Show the plot
plt.tight_layout()
plt.show()
