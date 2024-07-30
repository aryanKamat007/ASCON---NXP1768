#include "mbed.h"
#include "mbed_stats.h"
#include <cstdio>

typedef uint64_t bit64;

bit64 state[5] = {0}, t[5] = {0};
bit64 constants[16] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f};

BufferedSerial pc(USBTX, USBRX); // tx, rx

const uint32_t CLOCK_FREQUENCY_HZ = 96000000; // Set the clock frequency in Hz (e.g., 96 MHz for LPC1768)

int str_length(const char* str) {
    int length = 0;
    while (str[length] != '\0') {
        length++;
    }
    return length;
}

void print_state(bit64 state[5]){
    char buffer[50];
    for(int i = 0; i < 5; i++){
        sprintf(buffer, "%016llx\n", state[i]);
        pc.write(buffer, str_length(buffer));
    } 
}

bit64 rotate(bit64 x, int l) {
    return (x >> l) | (x << (64 - l));
}

void add_constant(bit64 state[5], int i, int a) {
    state[2] ^= constants[12 - a + i];
}

void sbox(bit64 x[5]) {
    x[0] ^= x[4];
    x[4] ^= x[3];
    x[2] ^= x[1];
    t[0] = x[0];
    t[1] = x[1];
    t[2] = x[2];
    t[3] = x[3];
    t[4] = x[4];
    t[0] = ~t[0];
    t[1] = ~t[1];
    t[2] = ~t[2];
    t[3] = ~t[3];
    t[4] = ~t[4];
    t[0] &= x[1];
    t[1] &= x[2];
    t[2] &= x[3];
    t[3] &= x[4];
    t[4] &= x[0];
    x[0] ^= t[1];
    x[1] ^= t[2];
    x[2] ^= t[3];
    x[3] ^= t[4];
    x[4] ^= t[0];
    x[1] ^= x[0];
    x[0] ^= x[4];
    x[3] ^= x[2];
}

void linear(bit64 state[5]) {
    bit64 temp0, temp1;
    temp0 = rotate(state[0], 19);
    temp1 = rotate(state[0], 28);
    state[0] ^= temp0 ^ temp1;
    temp0 = rotate(state[1], 61);
    temp1 = rotate(state[1], 39);
    state[1] ^= temp0 ^ temp1;
    temp0 = rotate(state[2], 1);
    temp1 = rotate(state[2], 6);
    state[2] ^= temp0 ^ temp1;
    temp0 = rotate(state[3], 10);
    temp1 = rotate(state[3], 17);
    state[3] ^= temp0 ^ temp1;
    temp0 = rotate(state[4], 7);
    temp1 = rotate(state[4], 41);
    state[4] ^= temp0 ^ temp1;
}

void p(bit64 state[5], int a){
    for (int i = 0; i < a; i++){
        add_constant(state, i, a);
        sbox(state);
        linear(state);
    }
}

void initialization(bit64 state[5], bit64 key[2]) {
    p(state, 12);
    state[3] ^= key[0];
    state[4] ^= key[1];
}

void associated_data(bit64 state[5], int length, bit64 associated_data_text[]) {
    for (int i = 0; i < length; i++){
        state[0] ^= associated_data_text[i];
        p(state, 6);
    }
    state[4] ^= 0x0000000000000001;
}

void finalization(bit64 state[5], bit64 key[2]) {
    state[1] ^= key[0];
    state[2] ^= key[1];
    p(state, 12);
    state[3] ^= key[0];
    state[4] ^= key[1];
}

void encrypt(bit64 state[5], int length, bit64 plaintext[], bit64 ciphertext[]) {
    for (int i = 0; i < length; i++){
        ciphertext[i] = plaintext[i] ^ state[0];
        state[0] = ciphertext[i];
        if (i < length - 1) {
            p(state, 6);
        }
    }
}

void decrypt(bit64 state[5], int length, bit64 plaintext[], bit64 ciphertext[]){
    for (int i = 0; i < length; i++){
        plaintext[i] = ciphertext[i] ^ state[0];
        state[0] = ciphertext[i];
        if (i < length - 1) {
            p(state, 6);
        }
    }
}

// Initialize DWT for cycle counting
void init_cycle_counter() {
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk; // Enable DWT
    DWT->CYCCNT = 0; // Clear cycle counter
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk; // Enable cycle counter
}

uint32_t get_cycle_count() {
    return DWT->CYCCNT;
}

int main() {
    // Initialize nonce, key and IV
    bit64 nonce[2] = {0x0000000000000001, 0x0000000000000002};
    bit64 key[2] = {0};
    bit64 IV = 0x80400c0600000000;
    bit64 plaintext[] = {0x123456789abcdef, 0x1234567890abcdef};
    bit64 ciphertext[2] = {0};
    bit64 associated_data_text[] = {0x787878, 0x878787, 0x09090};

    // Encryption
    // Initialize state
    state[0] = IV;
    state[1] = key[0];
    state[2] = key[1];
    state[3] = nonce[0];
    state[4] = nonce[1];
    initialization(state, key);
    associated_data(state, 3, associated_data_text);

    // Measure encryption time and memory usage
    init_cycle_counter();
    uint32_t start_cycles = get_cycle_count();
    mbed_stats_heap_t heap_stats;
    mbed_stats_stack_t stack_stats;

    mbed_stats_heap_get(&heap_stats);
    uint32_t start_heap = heap_stats.current_size;
    mbed_stats_stack_get(&stack_stats);
    uint32_t start_stack = stack_stats.max_size - stack_stats.reserved_size;

    encrypt(state, 2, plaintext, ciphertext);

    uint32_t end_cycles = get_cycle_count();
    mbed_stats_heap_get(&heap_stats);
    uint32_t end_heap = heap_stats.current_size;
    mbed_stats_stack_get(&stack_stats);
    uint32_t end_stack = stack_stats.max_size - stack_stats.reserved_size;

    uint32_t encryption_cycles = end_cycles - start_cycles;
    uint32_t encryption_heap = end_heap - start_heap;
    uint32_t encryption_stack = end_stack - start_stack;

    char buffer[100];
    sprintf(buffer, "\nciphertext: %016llx %016llx\n", ciphertext[0], ciphertext[1]);
    pc.write(buffer, str_length(buffer));
    
    finalization(state, key);
    
    sprintf(buffer, "tag: %016llx %016llx\n", state[3], state[4]);
    pc.write(buffer, str_length(buffer));

    // Decryption
    bit64 plaintextdecrypt[2] = {0};

    // Re-initialize state for decryption
    state[0] = IV;
    state[1] = key[0];
    state[2] = key[1];
    state[3] = nonce[0];
    state[4] = nonce[1];

    initialization(state, key);
    associated_data(state, 3, associated_data_text);

    // Measure decryption time and memory usage
    start_cycles = get_cycle_count();
    mbed_stats_heap_get(&heap_stats);
    start_heap = heap_stats.current_size;
    mbed_stats_stack_get(&stack_stats);
    start_stack = stack_stats.max_size - stack_stats.reserved_size;

    decrypt(state, 2, plaintextdecrypt, ciphertext);

    end_cycles = get_cycle_count();
    mbed_stats_heap_get(&heap_stats);
    end_heap = heap_stats.current_size;
    mbed_stats_stack_get(&stack_stats);
    end_stack = stack_stats.max_size - stack_stats.reserved_size;

    uint32_t decryption_cycles = end_cycles - start_cycles;
    uint32_t decryption_heap = end_heap - start_heap;
    uint32_t decryption_stack = end_stack - start_stack;

    sprintf(buffer, "\nplaintext: %016llx %016llx\n", plaintextdecrypt[0], plaintextdecrypt[1]);
    pc.write(buffer, str_length(buffer));
    
    finalization(state, key);
    
    sprintf(buffer, "tag: %016llx %016llx\n", state[3], state[4]);
    pc.write(buffer, str_length(buffer));
    
    double encryption_time_sec = (double)encryption_cycles / CLOCK_FREQUENCY_HZ;
    double decryption_time_sec = (double)decryption_cycles / CLOCK_FREQUENCY_HZ;

    uint32_t total_encryption_memory = encryption_heap + encryption_stack;
    uint32_t total_decryption_memory = decryption_heap + decryption_stack;

    sprintf(buffer, "\nEncryption Time: %lu cycles\n", encryption_cycles, encryption_time_sec);
    pc.write(buffer, str_length(buffer));

    sprintf(buffer, "Decryption Time: %lu cycles\n", decryption_cycles, decryption_time_sec);
    pc.write(buffer, str_length(buffer));

    return 0;
}
