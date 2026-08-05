// key_influence_ltlbc_with_initial.cpp
// Tracks which master-key bits (0..127) affect which bits of the 64-bit round-keys
// for rounds 0..R (round 0 == initial K0 used as initial layer).
//
//
// which_half: "low" -> capture bits[64..127] as RK_i (default: low)
//             "high" -> capture bits[0..63] as RK_i (you can choose convention)

#include <bits/stdc++.h>
using namespace std;

//static const uint8_t DEFAULT_SBOX[16] = {0x9, 0x8, 0xA, 0xC, 0xB, 0x0, 0xE, 0x5, 0x1, 0x2, 0x3, 0x6, 0x7, 0x4, 0xF, 0xD};
static const uint8_t DEFAULT_SBOX[16] = {0x0,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF};
static vector<uint8_t> make_default_rc(int rounds) {
    vector<uint8_t> rc(rounds);
    //if you want the real RC instead of zero in line below just write (i+1)
    for (int i = 0; i < rounds; ++i) rc[i] = (uint8_t)((0) & 0xF);
    return rc;
}

// rotate left a 64-bit segment inside 128-bit array
static void rotate_left_segment(array<uint8_t,128>& bits, int base, int rot) {
    rot %= 64;
    if (rot == 0) return;
    array<uint8_t,64> tmp;
    for (int i = 0; i < 64; ++i) tmp[i] = bits[base + (i + rot) % 64];
    for (int i = 0; i < 64; ++i) bits[base + i] = tmp[i];
}

// rotate whole 128 left by 64 (swap halves) safely
static void rotate128_left64_safe(array<uint8_t,128>& bits) {
    array<uint8_t,64> lower, upper;
    for (int i = 0; i < 64; ++i) lower[i] = bits[i];
    for (int i = 0; i < 64; ++i) upper[i] = bits[64 + i];
    for (int i = 0; i < 64; ++i) bits[i] = upper[i];
    for (int i = 0; i < 64; ++i) bits[64 + i] = lower[i];
}

static void apply_sbox_to_4bits(array<uint8_t,128>& bits, int pos, const uint8_t sbox[16]) {
    int v = (bits[pos] << 3) | (bits[pos + 1] << 2) | (bits[pos + 2] << 1) | (bits[pos + 3]);
    uint8_t out = sbox[v] & 0xF;
    bits[pos + 0] = (out >> 3) & 1;
    bits[pos + 1] = (out >> 2) & 1;
    bits[pos + 2] = (out >> 1) & 1;
    bits[pos + 3] = (out >> 0) & 1;
}

static void xor_4bits(array<uint8_t,128>& bits, int pos, uint8_t r4) {
    r4 &= 0xF;
    bits[pos + 0] ^= (r4 >> 3) & 1;
    bits[pos + 1] ^= (r4 >> 2) & 1;
    bits[pos + 2] ^= (r4 >> 1) & 1;
    bits[pos + 3] ^= (r4 >> 0) & 1;
}

// Pack bits[base..base+63] to uint64_t with MSB-first mapping: bits[base+0] -> bit63
static uint64_t pack64_from_bits_msbf(const array<uint8_t,128>& bits, int base) {
    uint64_t v = 0;
    for (int i = 0; i < 64; ++i) {
        int bitpos = 63 - i;
        v |= (uint64_t(bits[base + i] & 1) << bitpos);
    }
    return v;
}

// Unpack uint64 to bits[base..base+63] MSB-first
static void unpack64_to_bits_msbf(array<uint8_t,128>& bits, int base, uint64_t x) {
    for (int i = 0; i < 64; ++i) {
        int bitpos = 63 - i;
        bits[base + i] = (x >> bitpos) & 1ULL;
    }
}

int main(int argc, char** argv) {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
/*
#########
#        #
#        #
#########
#       #
#        #
#         #
*/
    int rounds_to_apply =8;
    string half = "low";
    string out_prefix = "influence";
    if (argc >= 2) rounds_to_apply = stoi(argv[1]);
    if (argc >= 3) half = argv[2];
    if (argc >= 4) out_prefix = argv[3];

    if (rounds_to_apply < 0 || rounds_to_apply > 14) {
        cerr << "rounds_to_apply must be in [0,14] (0 means only initial K0). Using 1.\n";
        rounds_to_apply = 1;
    }
    if (half != "low" && half != "high") {
        cerr << "which half must be 'low' or 'high'. Using 'low'.\n";
        half = "low";
    }

    const uint8_t* S = DEFAULT_SBOX;
    auto RC = make_default_rc(14);

    // result: for each master bit (0..127) store vector of uint64 round-keys for rounds 0..rounds_to_apply
    vector<vector<uint64_t>> result(128, vector<uint64_t>(rounds_to_apply + 1, 0ULL));
    vector<vector<vector<int>>> result_bitlist(128, vector<vector<int>>(rounds_to_apply + 1));

    // For each master bit
    for (int mbit = 0; mbit < 128; ++mbit) {
        // init key bits
        array<uint8_t,128> bits;
        bits.fill(0);
        bits[mbit] = 1;

        // Round 0: K0 is the initial layer (bits[0..63])
        uint64_t K0 = pack64_from_bits_msbf(bits, 0);
        uint64_t K0_view = (half == "low") ? pack64_from_bits_msbf(bits, 64) /*bits[64..127]*/ : K0;
        // NOTE: many specs treat K0 as bits[0..63]. We present both: we store K0 as the 'high' or 'low' depending on user choice.
        // Here we follow: round0 key we record is the half user chose: if "low" we record bits[64..127] (initially K1), if "high" bits[0..63] (K0).
        // To match the phrase "K0 is used for initial layer", user should pick "high" to see K0.
        uint64_t round0 = (half == "low") ? pack64_from_bits_msbf(bits, 64) : pack64_from_bits_msbf(bits, 0);
        result[mbit][0] = round0;
        // record bit indices
        for (int b = 0; b < 64; ++b) if ((round0 >> (63 - b)) & 1ULL) result_bitlist[mbit][0].push_back(b);

        // Now apply schedule rounds; for r=1..rounds_to_apply generate RK_r and record
        for (int r = 1; r <= rounds_to_apply; ++r) {
            // Step 1: rotate bits[0..63] left by 21
            rotate_left_segment(bits, 0, 21);
            // Step 2: apply S to bits[0..3]
            apply_sbox_to_4bits(bits, 0, S);
            // Step 3: XOR RC[r-1] into bits[60..63]
            xor_4bits(bits, 60, RC[r-1] & 0xF);
            // Capture RK_r: we capture bits[64..127] (the half that becomes RK) before half-rotation
            uint64_t rk_low = pack64_from_bits_msbf(bits, 64);
            uint64_t rk_high = pack64_from_bits_msbf(bits, 0);
            uint64_t captured = (half == "low") ? rk_low : rk_high;
            result[mbit][r] = captured;
            for (int b = 0; b < 64; ++b) if ((captured >> (63 - b)) & 1ULL) result_bitlist[mbit][r].push_back(b);
            // Step 4: rotate full 128 left by 64
            rotate128_left64_safe(bits);
        }
    }

    // Write a compact output file: each line = master_bit, round0_hex, round1_hex, ..., roundR_hex
    string txt = out_prefix + "_per_master_keys.txt";
    ofstream fout(txt);
    if (!fout) { cerr << "cannot write " << txt << "\n"; return 1; }
    // header
    fout << "# master_bit";
    for (int r = 0; r <= rounds_to_apply; ++r) fout << " RK" << r;
    fout << "\n";
    for (int i = 0; i < 128; ++i) {
        fout << setw(3) << i;
        for (int r = 0; r <= rounds_to_apply; ++r) {
            fout << "  0x" << hex << setw(16) << setfill('0') << result[i][r] << dec << setfill(' ');
        }
        fout << "\n";
    }
    fout.close();
    cout << "Wrote " << txt << "\n";

    // Also write CSV: master_bit,round,comma separated bit indices
    string csv = out_prefix + "_per_master_bits.csv";
    ofstream fc(csv);
    if (!fc) { cerr << "cannot write " << csv << "\n"; return 1; }
    fc << "master_bit,round,affected_bits\n";
    for (int i = 0; i < 128; ++i) {
        for (int r = 0; r <= rounds_to_apply; ++r) {
            fc << i << "," << r << ",";
            for (size_t idx = 0; idx < result_bitlist[i][r].size(); ++idx) {
                if (idx) fc << " ";
                fc << result_bitlist[i][r][idx];
            }
            fc << "\n";
        }
    }
    fc.close();
    cout << "Wrote " << csv << "\n";

    // Short stdout summary for first 8 master bits
    cout << "Sample summary (first 8 master bits):\n";
    for (int i = 0; i < min(8,128); ++i) {
        cout << setw(3) << i << ":";
        for (int r = 0; r <= rounds_to_apply; ++r) {
            cout << " 0x" << hex << setw(16) << setfill('0') << result[i][r] << dec << setfill(' ');
        }
        cout << "\n";
    }

    return 0;
}
