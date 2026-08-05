# 🔬 Experimental Verification of Boomerang Cryptanalysis on LTLBC

This repository contains the source code for the experimental evaluation of the boomerang success probability for the lightweight block cipher **LTLBC**. The provided scripts are intended to support the findings presented in our paper, ensuring the reproducibility of the reported distinguisher probabilities.

## Project Overview

The primary focus of this experimental framework is to calculate the success probability of the middle 4 rounds ($E_m$) of our 6-round boomerang distinguisher. In our analysis, we utilize a 1-4-1 round split. While the outer rounds are analyzed via differential trails, the middle piece is evaluated through direct simulation to ensure technical accuracy.

## Experimental Methodology

Instead of relying on a purely theoretical summation of individual differential trails, we use an **experimental evaluation** to estimate the success probability. This approach treats the middle rounds as a "black box," which offers several advantages:

1.  **Clustering Effect**: The simulation naturally accounts for the clustering effect (the summation of all compatible differential trails between fixed boundary differences) without requiring an explicit analytical aggregation formula.
2.  **Dependency Tracking**: Any potential dependencies between the upper and lower differentials (often referred to as the "sandwich" effect) are automatically captured by the experimental results.
3.  **Statistical Significance**: The success probability $r$ is estimated by running the boomerang algorithm independently 10 times. In each iteration, $2^{20}$ random plaintext pairs are tested, totaling $10 \cdot 2^{20}$ samples. To change the number of samples you will need to change the variables: n , N1 , N2 , N3. 

## 📏 Measured Results

The simulation targets the following boundary differences for the middle 4 rounds:
- **Input Difference ($\alpha$):** `0x0000280000000800`
- **Output Difference ($\beta$):** `0x0000000008000000`

Based on our experimental evaluation, the measured conditional probability for this segment is:
**$r = 2^{-10.44}$**

## Requirements

The scripts are written in Python and do not require any external libraries.
- **🐍Python 3**

## Usage

To run the experimental simulation and verify the success probability of the middle piece, execute the following command:

```bash
python3 LTLBC-Experimental-Verification.py
