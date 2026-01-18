# Hardware Vulnerabilities

## Side Channels Attacks vs Bit-Flip Attacks

Side-channel attacks (SCAs) exploit **physical leakage** (power, timing, EM) to infer data, targeting the implementation, while bit-flip attacks (BFAs) are a type of **fault injection**, directly corrupting data (like model weights) to disrupt functionality or extract secrets, often using hardware faults like laser or RowHammer to flip 0s to 1s (or vice versa). SCAs are stealthier, analyzing *how* a system works, while BFAs are more direct, altering *what* the system processes.

### Side-Channel Attacks (SCAs)

- **Goal:** Steal confidential information by observing physical emanations.
- **Mechanism:** Analyzes indirect signals like power consumption, timing variations, electromagnetic radiation, or acoustic emissions.
- **Target:** The physical implementation of algorithms, not the math itself.
- **Examples:** Power analysis (DPA), timing attacks, electromagnetic attacks (SEMA).
- **Nature:** Stealthy, often remote, exploiting unintentional information leakage.

### Bit-Flip Attacks (BFAs)

- **Goal:** Cause computational errors or modify model parameters to disrupt or compromise a system.
- **Mechanism:** Maliciously flips bits (0 to 1, 1 to 0) in memory or registers.
- **Target:** Memory locations holding weights, biases, or other critical data, especially in deep learning.
- **Examples:** RowHammer, voltage/frequency scaling (VFS), clock glitching, laser injection.
- **Nature:** A form of fault injection, often requiring physical access or specific hardware vulnerabilities.

### **Key Differences**

- **Information vs. Corruption:** SCAs *read* information from side effects; BFAs *write* errors into the data/code.
- **Stealth vs. Disruption:** SCAs are covert; BFAs are often disruptive (though can be subtle for data extraction).
- **Focus:** SCAs focus on *implementation behavior*; BFAs focus on *data integrity*

---