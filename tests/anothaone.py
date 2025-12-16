import numpy as np
import matplotlib.pyplot as plt

# ==========================================
# 1. PARAMETERS & MATH
# ==========================================
R0_MBPS = 13.7
ALPHA = 0.2
L_KEY_BITS = 256
T_DATA_GBPS = 1.0

# Unit conversions
R0_BPS = R0_MBPS * 1e6
T_DATA_BPS = T_DATA_GBPS * 1e9

d = np.linspace(0, 100, 200)

# --- Calculate Key Rate R(d) ---
R_bps = R0_BPS * 10 ** (-(ALPHA * d) / 10)

# --- Calculate Rotation Size P_rot in KB (Not MB) ---
# Formula: P_rot >= T_data * (L_key / R(d))
P_rot_bits = T_DATA_BPS * (L_KEY_BITS / R_bps)
P_rot_KB = P_rot_bits / (8 * 1000)  # Convert to Kilobytes

# --- Calculate Proxy for Secrecy (Qualitative) ---
# Inverse of rotation size: Smaller rotation = Higher Secrecy
secrecy_score = 1.0 / P_rot_KB
# Normalize to 0-1 for plotting
secrecy_normalized = (secrecy_score - secrecy_score.min()) / (secrecy_score.max() - secrecy_score.min())

# ==========================================
# 2. PLOTTING
# ==========================================
fig, ax1 = plt.subplots(figsize=(9, 5))

# --- Left Axis: Rotation Size (KB) ---
color_rot = 'tab:blue'
ax1.set_xlabel('Fiber Distance (km)', fontsize=12)
# Change label to KB
ax1.set_ylabel('Required Rotation Size ($P_{rot}$) [KB]\n(Log Scale - To Maintain 1 Gbps)', color=color_rot, fontsize=11, fontweight='bold')

# Plot Blue Line
line1 = ax1.plot(d, P_rot_KB, color=color_rot, linewidth=3, label='Rotation Size (Availability)')
ax1.tick_params(axis='y', labelcolor=color_rot)

# Set Log Scale and Limits for KB
ax1.set_yscale('log')
ax1.set_ylim(1, 1000) # Range: 1 KB to 1000 KB (1 MB)
ax1.set_yticks([1, 10, 100, 1000])
ax1.set_yticklabels(['1 KB', '10 KB', '100 KB', '1 MB'])

# --- Right Axis: Forward Secrecy ---
ax2 = ax1.twinx()
color_sec = 'tab:red'
ax2.set_ylabel('Relative Forward Secrecy\n(Qualitative)', color=color_sec, fontsize=11, fontweight='bold')

# Plot Red Line
line2 = ax2.plot(d, secrecy_normalized, color=color_sec, linewidth=3, linestyle='--', label='Forward Secrecy (Security)')
ax2.tick_params(axis='y', labelcolor=color_sec)
ax2.set_ylim(-0.1, 1.1)
ax2.set_yticks([0, 0.5, 1])
ax2.set_yticklabels(['Low\n(High Risk)', 'Medium', 'High\n(Low Risk)'])

# --- Styling ---
plt.title("The Security-Availability Trade-off", fontsize=14)
plt.grid(True, linestyle=':', alpha=0.6)

# Combine Legends
lns = line1 + line2
labs = [l.get_label() for l in lns]
ax1.legend(lns, labs, loc='center left') # Moved legend to not block the curve

plt.tight_layout()
plt.savefig('rotation_tradeoff_corrected.png', dpi=300)
print("Generated 'rotation_tradeoff_corrected.png'")