import matplotlib.pyplot as plt

# Provided data
time = list(range(1, 63))
power_aes = [
    0.91333216, 0.91333216, 0.91338682, 0.91279446, 0.91279446, 0.9122932, 0.91283088, 0.91190108, 0.78291955,
    0.91002938, 0.90801729, 0.90839184, 0.9084462, 0.90851868, 0.9124024, 0.91264687, 0.91362368, 0.9131864,
    0.91321329, 0.71309034, 0.91108014, 0.91097112, 0.91091661, 0.91091661, 0.91093478, 0.82398093, 0.8475519,
    0.8907528, 0.91137086, 0.83882547, 0.91614915, 0.91561118, 0.8574966, 0.87356074, 0.91460832, 0.91416158,
    0.91466304, 0.91375122, 0.91459008, 0.9145536, 0.82575639, 0.91299477, 0.91401574, 0.91431648, 0.91453536,
    0.86334192, 0.91283088, 0.9128673, 0.91845488, 0.9173607, 0.91808171, 0.91696915, 0.91700573, 0.91704231,
    0.85281336, 0.91301298, 0.9150915, 0.91360546, 0.9151645, 0.91421627, 0.89675352, 0.9126852
]
average_aes = 0.898911516

power_normal = [
    0.90401267, 0.90401267, 0.907488, 0.90610131, 0.90649766, 0.90529176, 0.77754237, 0.9061718, 0.79597498,
    0.79009025, 0.87723812, 0.6894202, 0.75949825, 0.90476573, 0.90464022, 0.90336249, 0.8997604, 0.73316496,
    0.9035264, 0.7462752, 0.90349056, 0.70239239, 0.9025359, 0.90799216, 0.907488, 0.9065516, 0.90608334,
    0.9064617, 0.90559708, 0.90653362, 0.90608334, 0.68605288, 0.90683992, 0.86425022, 0.90793731, 0.905688,
    0.90469401, 0.90466038, 0.90439128, 0.9049313, 0.90440922, 0.90550728, 0.90649766, 0.90991855, 0.90891033,
    0.90833414, 0.70429755, 0.907434, 0.90698384, 0.9049313, 0.90647968, 0.90617402, 0.90577785, 0.90615522,
    0.90602943, 0.90552524, 0.90574076, 0.90570484, 0.90466205, 0.90430158, 0.90428364, 0.9048236
]
average_normal = 0.878853403

# Plot the data
plt.figure(figsize=(10, 6))
plt.plot(time, power_aes, label=f'Implement OTA-Key Power (Avg: {average_aes:.6f})')
plt.plot(time, power_normal, label=f'Normal Power (Avg: {average_normal:.6f})')
plt.xlabel('Time (s)', fontsize=20)
plt.ylabel('Power (w)', fontsize=20)
plt.xticks(fontsize=15)
plt.yticks(fontsize=15)
plt.legend(loc='lower right', fontsize='large')
plt.grid(True)
plt.savefig('power_process.pdf', format='pdf')
plt.show()
