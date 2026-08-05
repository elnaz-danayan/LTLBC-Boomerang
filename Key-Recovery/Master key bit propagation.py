import math

class CryptoCipher:
    rounds = 2  # Default number of rounds

    permute_decryption = [
        0x12, 0x16, 0x1E, 0x1A, 0x11, 0x15, 0x1D, 0x19, 0x10, 0x14, 0x1C, 0x18, 0x13, 0x17,
        0x1F, 0x1B, 0x36, 0x3A, 0x3E, 0x32, 0x35, 0x39, 0x3D, 0x31, 0x34, 0x38, 0x3C, 0x30,
        0x37, 0x3B, 0x3F, 0x33, 0x02, 0x06, 0x0E, 0x0A, 0x01, 0x05, 0x0D, 0x09, 0x00, 0x04,
        0x0C, 0x08, 0x03, 0x07, 0x0F, 0x0B, 0x26, 0x2A, 0x2E, 0x22, 0x25, 0x29, 0x2D, 0x21,
        0x24, 0x28, 0x2C, 0x20, 0x27, 0x2B, 0x2F, 0x23, 0x3A, 0x36, 0x32, 0x3C, 0x39, 0x35, 0x31, 0x3D
    ]

    permute_encryption = [
        0x28, 0x24, 0x20, 0x2C, 0x29, 0x25, 0x21, 0x2D,
        0x2B, 0x27, 0x23, 0x2F, 0x2A, 0x26, 0x22, 0x2E,
        0x08, 0x04, 0x00, 0x0C, 0x09, 0x05, 0x01, 0x0D,
        0x0B, 0x07, 0x03, 0x0F, 0x0A, 0x06, 0x02, 0x0E,
        0x3B, 0x37, 0x33, 0x3F, 0x38, 0x34, 0x30, 0x3C,
        0x39, 0x35, 0x31, 0x3D, 0x3A, 0x36, 0x32, 0x3E,
        0x1B, 0x17, 0x13, 0x1F, 0x18, 0x14, 0x10, 0x1C,
        0x19, 0x15, 0x11, 0x1D, 0x1A, 0x16, 0x12, 0x1E
    ]
    sbox = [0x0,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF]

    def __init__(self, rounds):
        self.rounds = rounds

    def _permute(self, state_list, mapping):
        temp = [0]*64
        for i in range(64):
            idx = mapping[i]
            if not (0 <= idx < 64):
                raise IndexError("permute mapping out of range")
            temp[i] = state_list[idx]
        return temp

    def upper_permutation(self, state_list):
        return self._permute(state_list, self.permute_encryption)

    def lower_permutation(self, state_list):
        return self._permute(state_list, self.permute_decryption)

    def mixing_layer(self, state_list):
        # Apply mixing operations to the state
        y = [0] * 64
        for bit in range(16):
            a0 = (bit + 5) % 16
            # First block (bits 0-15 and 16-31)
            y[bit] = self.xor(state_list[a0], state_list[16 + a0], state_list[bit])
            y[bit + 16] = self.xor(state_list[a0], state_list[16 + a0], state_list[bit + 16])

            a1 = (bit + 9) % 16
            # Second block (bits 32-47 and 48-63)
            y[bit + 32] = self.xor(state_list[32 + a1], state_list[48 + a1], state_list[bit + 32])
            y[bit + 48] = self.xor(state_list[32 + a1], state_list[48 + a1], state_list[bit + 48])
        return y

    def xor(self, a, b, c):
        ai, bi, ci = int(a), int(b), int(c)
        # sanity checks
        if ai not in (0, 1) or bi not in (0, 1) or ci not in (0, 1):
            raise ValueError("Arguments must be bits (0 or 1) or booleans.")
        if (ai+bi+ci>0):
            return 1
        else:
            return 0

    def subcell(self, state_list):
        """Apply S-box to each 4-bit nibble of a 64-bit state list."""
        if len(state_list) != 64:
            raise ValueError("subcell expects a 64-bit state list")
        output = []
        for nib in range(16):
            start = nib * 4
            nib_bits = [int(state_list[start + i]) for i in range(4)]
            nib_num = (nib_bits[0] << 3) | (nib_bits[1] << 2) | (nib_bits[2] << 1) | nib_bits[3]
            new_val = self.sbox[nib_num]
            bin_str = format(new_val, '04b')
            output.extend(int(ch) for ch in bin_str)
        return output

    def binary_encrypt(self, xu):
        """Performs encryption for the configured number of rounds.
           Returns a list of 64-bit strings, one per round (round outputs after subcell).
        """
        if len(xu) != 64:
            raise ValueError("Input must be 64 bits")
        state = [int(bit) for bit in xu]
        round_outputs = []

        print(f"Initial: {''.join(str(b) for b in state)}")
        for i in range(self.rounds):
            state = self.upper_permutation(state)
            print(f"x {i}: {''.join(str(b) for b in state)}")
            state = self.mixing_layer(state)
            print(f"y {i}: {''.join(str(b) for b in state)}")
            state = self.subcell(state)
            round_str = ''.join(str(b) for b in state)
            # Print round output as 64-bit string
            print(f"Round {i + 1}: {round_str}")
            round_outputs.append(round_str)
        return round_outputs

    def binary_decrypt(self, bin64):
        if len(bin64) != 64:
            raise ValueError("decrypt_bin expects a 64-bit string")
        state = [int(x) for x in bin64]
        round_outputs = []
        for i in range(self.rounds):
            state = self.subcell(state)
            print(f"x {i}: {''.join(str(b) for b in state)}")
            state = self.mixing_layer(state)
            print(f"y {i}: {''.join(str(b) for b in state)}")
            state = self.lower_permutation(state)
            round_str = ''.join(str(b) for b in state)
            # Print round output as 64-bit string
            print(f"Round {i + 1}: {round_str}")
            round_outputs.append(round_str)
        return round_outputs


# Example usage and collision-checking
if __name__ == "__main__":
    cipher = CryptoCipher(rounds=2)


################################################################################################
    #Enter the target below in hex format
    TARGET=(format(0x8242008402020004, '064b'))
    # Validate TARGET format
    if len(TARGET) != 64 or any(ch not in "01" for ch in TARGET):
        raise ValueError("TARGET must be a 64-character string of '0' and '1'.")

    target_int = int(TARGET, 2)

    collisions = []  # store indices (1-based) that collide
    counter=0
    for i in range(64):
        active_index = i + 1
        print("Active Bit=", active_index)
        input_bits = bin(1 << i)[2:].zfill(64)  # single 1 at position i (LSB = i=0)



####################################################################################################
        #Based on the Decryption or Encryption Path choose one of the lines below and comment the other one
        round_outputs = cipher.binary_encrypt(input_bits)
        #round_outputs = cipher.binary_decrypt(input_bits)
        round1 = round_outputs[0]  # "Round 1" output as string
        # Convert to integer and check bitwise AND with the target
        round1_int = int(round1, 2)
        if (round1_int & target_int) != 0:
            print(f"--> Collision found with TARGET for active bit {active_index}")
            collisions.append(active_index)
            counter+=1
        else:
            print(f"--> No collision for active bit {active_index}")
        print()  # blank line for readability

    # Summary
    if collisions:
        print("Active bits that collided with TARGET:", collisions)
        print("Number of Activated bits=", counter)
    else:
        print("No collisions found with TARGET for any active bit.")
