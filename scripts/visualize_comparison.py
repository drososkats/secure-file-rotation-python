import numpy as np
import matplotlib.pyplot as plt

# Metrics for comparison: 1=Low, 10=High
labels = ['Speed', 'Integrity', 'Confidentiality', 'HW-Agility', 'Robustness']
num_vars = len(labels)

# Mode 1: AES-CTR (Fast, no integrity)
mode1 = [10, 1, 10, 5, 3] 
# Mode 2: HMAC-SHA256 (Integrity only)
mode2 = [7, 10, 1, 10, 7]
# Mode 3: AEAD (The Gold Standard)
mode3 = [9, 10, 10, 8, 10]

angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist()
angles += angles[:1]

def add_to_radar(data, label, color):
    values = data + data[:1]
    ax.plot(angles, values, color=color, linewidth=2, label=label)
    ax.fill(angles, values, color=color, alpha=0.1)

fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))

add_to_radar(mode1, 'Mode 1: AES-CTR', '#d62728')
add_to_radar(mode2, 'Mode 2: HMAC-SHA256', '#1f77b4')
add_to_radar(mode3, 'Mode 3: AEAD (GCM/ChaCha)', '#2ca02c')

ax.set_theta_offset(np.pi / 2)
ax.set_theta_direction(-1)
ax.set_thetagrids(np.degrees(angles[:-1]), labels)

plt.legend(loc='upper right', bbox_to_anchor=(1.3, 1.1))
plt.title("Cryptographic Modes: Security vs Performance", size=16, y=1.1, fontweight='bold')

# Save the result
plt.tight_layout()
plt.savefig('cryptographic_comparison.png', dpi=300)
print("[+] Comparison chart generated: cryptographic_comparison.png")
plt.show()