import random
import secrets
import os


FLAG = os.getenv("FLAG", "flag{test_flag}")


def xor(a: bytes, b: bytes, strict = True) -> bytes:
    if strict:
        assert len(a) == len(b), f"strict xor but {len(a)} != {len(b)}"
    b *= (len(a) + len(b) - 1) // len(b)
    return bytes(x ^ y for x, y in zip(a, b))


def gen_sbox() -> list[bytes]:
    rng = random.Random(1234)
    cols = [list(range(256)) for _ in range(8)]
    for col in cols:
        rng.shuffle(col)
    sbox = [bytes(cols[j][i] for j in range(8)) for i in range(256)]
    return sbox


SBOX = gen_sbox()


def reduce(x: int) -> int:
    assert x >= 0
    MOD = 0b100011011
    while x.bit_length() >= MOD.bit_length():
        x ^= MOD << (x.bit_length() - MOD.bit_length())
    return x


def mul(x: int, y: int) -> int:
    assert x >= 0
    assert y >= 0
    x = reduce(x)
    y = reduce(y)
    res = 0
    while x > 0:
        if x & 1 == 1:
            res ^= y
        x >>= 1
        y = reduce(y << 1)

    return res


def F(block: bytes, k: int) -> bytes:
    val = 0
    for c in block:
        val = reduce(mul(val ^ c, k))
    return SBOX[val]


def decrypt_block(key: bytes, block: bytes, iv: bytes, n_rounds = 16):
    assert len(block) == 16
    assert len(key) == n_rounds

    block = xor(block, key, strict = False)
    L, R = block[:8], block[8:]

    for i in range(n_rounds - 1, -1, -1):
        K = F(R, key[i] ^ iv[i])
        L, R = R, xor(L, K)

    block = L + R
    block = xor(block, key, strict = False)

    return block


def decrypt(key, ct):
    assert len(ct) % 16 == 0
    ct_blocks = [ct[i:i + 16] for i in range(0, len(ct), 16)]
    iv = ct_blocks[0]
    
    pt_blocks = []
    for ct_block in ct_blocks[1:]:
        pt_block = decrypt_block(key, ct_block, iv)
        pt_blocks.append(pt_block)
        iv = ct_block

    ct = b"".join(pt_blocks)
    return ct


key = secrets.token_bytes(16)

print("Polyphemus 3000")
print("Enter hex to decrypt, or press Enter to continue.")

while True:
    ct = bytes.fromhex(input("> "))
    if not ct:
        break
    ct = decrypt(key, ct)
    print(f"dec: {ct.hex()}")

key_guess = bytes.fromhex(input("Enter key (hex): "))
if key == key_guess:
    print(f"Okay, that was impressive, here's the flag: {FLAG}")
else:
    print("Hmm? That's incorrect. Try again.")
