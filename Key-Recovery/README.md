# 🔑 Key Recovery & Dependency Tracking

Welcome to the **Key Recovery** branch of this repository. This branch contains the automated tools and scripts used to evaluate the key recovery phase of our boomerangcryptanalysis, with a specific focus on calculating exact key-bit dependencies.

---

## 📁 Branch Structure

Below is an overview of the scripts included in this directory and their respective roles in the attack complexity evaluation:

| File | Description |
|---|---|
| `Master key bit propagation.py` | Automates bitwise dependency tracking to calculate exactly which master key bits are required for partial encryption/decryption. |
| `LTLBC Key Schedule.cpp` | Traces the cipher's key schedule to map the exact dependencies between the 128-bit master key and the 64-bit round keys across all rounds. Essential for translating required round-key bits (e.g., $RK_8$) back to their original master-key indices.  |


---

## 🧠`Master key bit propagation.py`

When extending a distinguisher by appending rounds at the top or bottom of an SPN cipher, attackers must guess subsets of the key to partially encrypt or decrypt the data. This script programmatically tracks the diffusion of individual key bits through the cipher's round function to calculate the exact bounds of required key bits.

### How it Works
1. **Single-Bit Activation:** The algorithm initializes 64 separate states. In each state, exactly **one** bit of the 64-bit master key is activated (flipped). 
2. **Full S-box Diffusion Assumption:** To ensure strict and mathematically safe bounds, the non-linear layer (S-box) is modeled as fully diffusing. If an active bit enters a 4-bit S-box nibble, the script assumes the difference spreads to all 4 bits of the output nibble. 
3. **Collision Detection:** After propagating the active key bit through the key schedule and the first round, the script outputs an "infected" state mask. If these infected bits intersect with the **target active bits** (i.e., the boundaries of the distinguisher), the key bit is flagged as necessary.

> **Example:** In our analysis, we require exactly **9 specific active bits** at the input of the forward distinguisher. Running this script reveals that due to backward diffusion, exactly **51 bits** of the master key are required to evaluate those 9 state bits. 

---

## 🚀 Usage

### Prerequisites
* Python 3


### Running the Dependency Tracker
To calculate the key bit dependencies for the forward/backward extensions, simply execute the main script:

```bash
python "Master key bit propagation.py"
```



## 🧠 `LTLBC Key Schedule.cpp`
To successfully execute the lower key-recovery extension, we must partially decrypt the final round using $RK_8$. This C++ script evaluates the LTLBC key schedule equations from Round 0 (initial $K_0$ layer) up to Round $R$. By inputting a target bit index in a specific round key, the script outputs the exact subset of the 128 master-key bits required to derive it. This confirms the heavy overlap within $K_0$ that dictates our exhaustive search complexity.
