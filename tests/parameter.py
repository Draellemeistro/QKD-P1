import numpy as np
import matplotlib.pyplot as plt

# ==========================================
# 1. PARAMETERS (Based on Thesis Assumptions)
# ==========================================
R0_MBPS = 13.7       # Source Rate at 0km (Mbps)
ALPHA = 0.2          # Attenuation (dB/km)
DATA_SIZE_GB = 50.0  # Dataset size (GB)
AES_BW_GBPS = 1.0    # AES Network Bandwidth (Gbps)

# Convert units for calculation
R0_BPS = R0_MBPS * 1_000_000
DATA_BITS = DATA_SIZE_GB * 8 * 1_000_000_000
AES_BW_BPS = AES_BW_GBPS * 1_000_000_000

# Distance range (0 to 120 km)
d = np.linspace(0, 120, 100)

# ==========================================
# 2. PHYSICS MODEL: Key Rate R(d)
# ==========================================
# Formula: R(d) = R0 * 10^(-alpha * d / 10)
R_bps = R0_BPS * 10 ** (-(ALPHA * d) / 10)
R_mbps = R_bps / 1_000_000

# Plot 1: Theoretical Key Rate vs Distance
plt.figure(figsize=(8, 5))
plt.plot(d, R_mbps, color='blue', linewidth=2, label=r'Key Rate $R(d)$')
plt.title(f"Theoretical Secure Key Rate vs. Distance\n(Source: {R0_MBPS} Mbps, Attenuation: {ALPHA} dB/km)")
plt.xlabel("Fiber Distance (km)")
plt.ylabel("Secret Key Rate (Mbps)")
plt.grid(True, which='both', linestyle='--', alpha=0.7)
plt.axhline(y=1.3, color='red', linestyle=':', label='50km Marker (~1.3 Mbps)')
plt.axvline(x=50, color='red', linestyle=':')
plt.legend()
plt.tight_layout()
plt.savefig('qkd_key_rate.png', dpi=300)
print("Generated 'qkd_key_rate.png'")

# ==========================================
# 3. COMPARATIVE ANALYSIS: OTP vs AES Time
# ==========================================
# Calculate Time for OTP: T = Data / R(d)
# We limit the max time to avoid infinite spikes on graph for very long distances
otp_time_sec = DATA_BITS / R_bps
otp_time_hours = otp_time_sec / 3600

# Calculate Time for AES: T = Data / Bandwidth (Constant)
aes_time_sec = np.full_like(d, DATA_BITS / AES_BW_BPS)
aes_time_min = aes_time_sec / 60

# Plot 2: Transfer Time Comparison (Dual Axis)
fig, ax1 = plt.subplots(figsize=(8, 5))

# Axis 1: OTP (Hours) - Log Scale usually better, but linear shows the wall clearly
color = 'tab:red'
ax1.set_xlabel('Distance (km)')
ax1.set_ylabel('OTP Transfer Time (Hours)', color=color, fontweight='bold')
ax1.plot(d, otp_time_hours, color=color, linewidth=2, label='OTP (Left Axis)')
ax1.tick_params(axis='y', labelcolor=color)
ax1.set_yscale('log') # Log scale is essential because it goes from 8 hours to 1000+ hours
ax1.set_ylim(1, 10000) # Limit y-axis to keep graph readable

# Axis 2: AES (Minutes)
ax2 = ax1.twinx()
color = 'tab:green'
ax2.set_ylabel('AES Transfer Time (Minutes)', color=color, fontweight='bold')
ax2.plot(d, aes_time_min, color=color, linewidth=3, linestyle='--', label='AES (Right Axis)')
ax2.tick_params(axis='y', labelcolor=color)
ax2.set_ylim(0, 20) # 0 to 20 minutes scale

# Title and Annotations
plt.title(f"Transfer Time for {DATA_SIZE_GB} GB Dataset: OTP vs. AES")
fig.tight_layout()
plt.grid(True, linestyle='--', alpha=0.5)

# Add text box for the specific 50km data point
otp_50km = otp_time_hours[np.abs(d - 50).argmin()]
plt.text(55, 6.7, f"AES: ~6.7 min (Constant)", color='green', fontweight='bold')
plt.text(55, 12, f"OTP @ 50km: {otp_50km:.1f} hours", color='red')

plt.savefig('otp_vs_aes.png', dpi=300)
print("Generated 'otp_vs_aes.png'")