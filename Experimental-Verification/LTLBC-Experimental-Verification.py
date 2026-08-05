import time, math, secrets, random
from multiprocessing import Pool, cpu_count

# ------------------- Bitwise cipher implementation -------------------
class CryptoCipher:
    # Permutation tables and S-box taken from your Python skeleton
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

    sbox_encryption = [0x9, 0x8, 0xA, 0xC, 0xB, 0x0, 0xE, 0x5, 0x1, 0x2, 0x3, 0x6, 0x7, 0x4, 0xF, 0xD]
    sbox_decryption = [5, 8, 9, 0xa, 0xd, 7, 0xb, 0xc, 1, 0, 2, 4, 3, 0xf, 6, 0xe]

    def __init__(self, rounds=6):
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

    def xor_bit(self, a,b,c):
        return (a ^ b ^ c) & 1

    def mixing_layer(self, state_list):
        y = [0]*64
        for bit in range(16):
            a0 = (bit + 5) % 16
            y[bit]       = self.xor_bit(state_list[a0], state_list[16 + a0], state_list[bit])
            y[bit + 16]  = self.xor_bit(state_list[a0], state_list[16 + a0], state_list[bit + 16])
            a1 = (bit + 9) % 16
            y[bit + 32]  = self.xor_bit(state_list[32 + a1], state_list[48 + a1], state_list[bit + 32])
            y[bit + 48]  = self.xor_bit(state_list[32 + a1], state_list[48 + a1], state_list[bit + 48])
        return y

    def subcell_encryption(self, state_list):
        out = []
        for nib in range(16):
            start = 4*nib
            nib_val = (state_list[start]<<3)|(state_list[start+1]<<2)|(state_list[start+2]<<1)|(state_list[start+3])
            v = self.sbox_encryption[nib_val] & 0xF
            out.extend([(v>>3)&1,(v>>2)&1,(v>>1)&1,v&1])
        return out

    def subcell_decryption(self, state_list):
        out = []
        for nib in range(16):
            start = 4*nib
            nib_val = (state_list[start]<<3)|(state_list[start+1]<<2)|(state_list[start+2]<<1)|(state_list[start+3])
            v = self.sbox_decryption[nib_val] & 0xF
            out.extend([(v>>3)&1,(v>>2)&1,(v>>1)&1,v&1])
        return out

    # These two functions operate on 64-bit binary strings (e.g. '010101...')
    def encrypt_bin(self, bin64):
        if len(bin64) != 64:
            raise ValueError("encrypt_bin expects a 64-bit string")
        state = [int(x) for x in bin64]
        for _ in range(self.rounds):
            state = self.upper_permutation(state)
            state = self.mixing_layer(state)
            state = self.subcell_encryption(state)
        return ''.join(str(x) for x in state)

    def decrypt_bin(self, bin64):
        if len(bin64) != 64:
            raise ValueError("decrypt_bin expects a 64-bit string")
        state = [int(x) for x in bin64]
        for _ in range(self.rounds):
            state = self.subcell_decryption(state)
            state = self.mixing_layer(state)
            state = self.lower_permutation(state)
        return ''.join(str(x) for x in state)

# ------------------- Boomerang worker: does N2 bunches × N3 trials -------------------
def boomerang_worker(args):
    dp_int, dc_int, R, N2, N3, seed_offset, worker_id = args
    rng = random.Random()
    seed_val = int(time.time()*10) + seed_offset + worker_id
    rng.seed(seed_val)
    cipher = CryptoCipher(rounds=R)
    successes = 0
    for _ in range(N2):
        for _ in range(N3):
            p1_int = rng.getrandbits(64)
            p2_int = p1_int ^ dp_int
            c1_bin = cipher.encrypt_bin(format(p1_int, '064b'))
            c2_bin = cipher.encrypt_bin(format(p2_int, '064b'))
            c1_int = int(c1_bin, 2)
            c2_int = int(c2_bin, 2)
            c3_int = c1_int ^ dc_int
            c4_int = c2_int ^ dc_int
            p3_bin = cipher.decrypt_bin(format(c3_int, '064b'))
            p4_bin = cipher.decrypt_bin(format(c4_int, '064b'))
            p3_int = int(p3_bin, 2)
            p4_int = int(p4_bin, 2)
            if (p3_int ^ p4_int) & ((1<<64)-1) == dp_int:
                successes += 1
    return successes

# ------------------- Driver: mirrors verify() and the n-loop in main -------------------
def run_experiment(dp_hex, dc_hex, R=6, N1=12, deg1=5, deg2=5, n_repeats=10, parallel=True):
    N2 = 1 << deg1
    N3 = 1 << deg2
    dp_int = int(dp_hex, 16)
    dc_int = int(dc_hex, 16)

    print(f"#Rounds: {R} rounds")
    print(f"#Total Queries = (#Parallel threads) * (#Bunches per thread) * (#Queries per bunch) = {N1} * {N2} * {N3} = 2^({math.log2(N1*N2*N3):.6f})")

    total_success_sum = 0
    seed_offset = secrets.randbelow(1000000)

    for run in range(n_repeats):
        t0_proc = time.process_time()
        t0_wall = time.time()

        if parallel:
            processes = min(N1, max(1, cpu_count()))
            args = [(dp_int, dc_int, R, N2, N3, seed_offset, wid) for wid in range(N1)]
            with Pool(processes=processes) as pool:
                partials = pool.map(boomerang_worker, args)
            run_sum = sum(partials)
        else:
            run_sum = 0
            for wid in range(N1):
                run_sum += boomerang_worker((dp_int, dc_int, R, N2, N3, seed_offset, wid))

        t_proc = time.process_time() - t0_proc
        t_wall = time.time() - t0_wall
        total_success_sum += run_sum

        print(f" time on process_time(): {t_proc:.6f}")
        print(f" time on wall: {t_wall:.6f}")
        print(f"sum = {run_sum}")
        if run_sum == 0:
            print("2^(-inf)  (no successes observed in this run)")
        else:
            X = math.log2((N1 * N2 * N3) / run_sum)
            print(f"2^(-{X:.6f})")
        print("#####################################")

    # final average as C++ main printed:
    if total_success_sum == 0:
        print("\nAverage = 2^(-inf)  (no successes observed across all runs)")
    else:
        avg_exponent = (math.log(n_repeats) + math.log(N1) + math.log(N2) + math.log(N3) - math.log(total_success_sum)) / math.log(2)
        print(f"\nAverage = 2^(-{avg_exponent:.6f})")

    return total_success_sum

# ------------------- Main: parameters same as C++ main -------------------
if __name__ == "__main__":
    dp_str = "0x0000280000000800"
    dc_str = "0x0000000008000000"
    R = 4
    N1 = 16
    deg1 = 8
    deg2 = 8
    n = 10

    # Warning about run time
    print("WARNING: this runs n * N1 * N2 * N3 total boomerang queries.")
    print("Adjust N1 / deg1 / deg2 / n if your machine is small.")

    run_experiment(dp_str, dc_str, R=R, N1=N1, deg1=deg1, deg2=deg2, n_repeats=n, parallel=True)
