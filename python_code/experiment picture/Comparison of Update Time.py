import matplotlib.pyplot as plt

# Preparing the new data based on the user's updated specifications
categories = ['OTA Key', 'Akkaoui et al.', 'Asokan, N. et al (ASSURED)', 'Wang et al.', 'Xu et al.', 'Langiu et al.(Upkit)']
values = [0.203, (150+350)/2, 2.3, 20, 15, 128]  # Converting all to seconds for consistency
special_index = 3  # Index for the special '>20s' case

# Creating a bar chart
plt.figure(figsize=(12, 6))
bars = plt.bar(categories, values, color=['skyblue' if i != special_index else 'orange' for i in range(len(values))])

# Adding values on top of the bars, with a special label for the '>20s' case
for bar, val, cat in zip(bars, values, categories):
    yval = bar.get_height()
    label = f'>{val}s' if cat == 'Wang et al.' else f'{val}s'
    plt.text(bar.get_x() + bar.get_width()/2, yval, label, ha='center', va='bottom')

plt.xlabel('Related Work')
plt.ylabel('Update Time (s)')
plt.title('Comparison of Update Time')
plt.xticks(rotation=45, ha='right')
plt.grid(axis='y', linestyle='--', alpha=0.7)

# Show the plot
plt.tight_layout()
plt.show()
