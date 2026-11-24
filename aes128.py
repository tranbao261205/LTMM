"""AES-128 một khối 16 byte. State lưu theo cột: index = 4*c+r."""

def gf_mul(a, b):
    """Nhân trong GF(2^8), modulo x^8+x^4+x^3+x+1 (0x11B)."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = ((a << 1) ^ (0x11B if a & 0x80 else 0)) & 0xFF
        b >>= 1
    return result

def gf_pow(a, n):
    result = 1
    while n:
        if n & 1:
            result = gf_mul(result, a)
        a = gf_mul(a, a)
        n >>= 1
    return result

def rol8(x, n):
    return ((x << n) | (x >> (8-n))) & 0xFF

def make_sbox():
    # Nghịch đảo trong trường hữu hạn, sau đó biến đổi affine.
    s = []
    for x in range(256):
        y = gf_pow(x, 254) if x else 0
        s.append(y ^ rol8(y,1) ^ rol8(y,2) ^ rol8(y,3) ^ rol8(y,4) ^ 0x63)
    inv = [0]*256
    for i, v in enumerate(s):
        inv[v] = i
    return s, inv

SBOX, INV_SBOX = make_sbox()

def hx(data):
    return bytes(data).hex().upper()

def key_expansion(key, log=lambda _: None):
    if len(key) != 16:
        raise ValueError('AES-128 requires a 16-byte key')
    w = [list(key[i:i+4]) for i in range(0,16,4)]
    rcon = 1
    for i in range(4,44):
        t = w[i-1][:]
        if i % 4 == 0:
            rot = t[1:] + t[:1]
            sub = [SBOX[x] for x in rot]
            t = sub[:]
            t[0] ^= rcon
            log(f'  w{i:02d} RotWord={hx(rot)} SubWord={hx(sub)} Rcon={rcon:02X} g={hx(t)}')
            rcon = gf_mul(rcon, 2)
        w.append([a^b for a,b in zip(w[i-4], t)])
        log(f'  w{i:02d} = {hx(w[-1])}')
    keys = [sum(w[i:i+4], []) for i in range(0,44,4)]
    for i,k in enumerate(keys):
        log(f'RoundKey[{i:02d}] = {hx(k)}')
    return keys

def add_round_key(state, key):
    return [a^b for a,b in zip(state,key)]

def sub_bytes(state, inverse=False):
    table = INV_SBOX if inverse else SBOX
    return [table[x] for x in state]

def shift_rows(state, inverse=False):
    # Mỗi hàng r dịch trái r vị trí; giải mã dịch phải.
    sign = -1 if inverse else 1
    return [state[4*((c+sign*r)%4)+r] for c in range(4) for r in range(4)]

MIX = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]
INV_MIX = [[14,11,13,9],[9,14,11,13],[13,9,14,11],[11,13,9,14]]

def mix_columns(state, inverse=False):
    matrix = INV_MIX if inverse else MIX
    out = []
    for c in range(4):
        col = state[4*c:4*c+4]
        for row in matrix:
            out.append(gf_mul(row[0],col[0]) ^ gf_mul(row[1],col[1]) ^ gf_mul(row[2],col[2]) ^ gf_mul(row[3],col[3]))
    return out

def show(log, label, state):
    log(f'{label:<18} = {hx(state)}')
    for r in range(4):
        log('    ' + ' '.join(f'{state[4*c+r]:02X}' for c in range(4)))

def crypt(block, key, decrypt=False, log=lambda _: None):
    if len(block) != 16 or len(key) != 16:
        raise ValueError('AES-128 requires a 16-byte block and key')
    log(f'AES-128 {"DECRYPT" if decrypt else "ENCRYPT"}: input={hx(block)}, key={hx(key)}')
    keys = key_expansion(key, log)
    state = list(block)
    show(log, 'Input', state)
    if not decrypt:
        log('Round 00')
        state = add_round_key(state, keys[0]); show(log,'AddRoundKey',state)
        for i in range(1,11):
            log(f'Round {i:02d}')
            state = sub_bytes(state); show(log,'SubBytes',state)
            state = shift_rows(state); show(log,'ShiftRows',state)
            if i != 10:
                state = mix_columns(state); show(log,'MixColumns',state)
            else:
                log('MixColumns skipped in final round')
            state = add_round_key(state, keys[i]); show(log,'AddRoundKey',state)
    else:
        log('Inverse initial round: key 10')
        state = add_round_key(state, keys[10]); show(log,'AddRoundKey',state)
        for i in range(9,-1,-1):
            log(f'Inverse round: key {i:02d}')
            state = shift_rows(state, True); show(log,'InvShiftRows',state)
            state = sub_bytes(state, True); show(log,'InvSubBytes',state)
            state = add_round_key(state, keys[i]); show(log,'AddRoundKey',state)
            if i != 0:
                state = mix_columns(state, True); show(log,'InvMixColumns',state)
            else:
                log('InvMixColumns skipped in final inverse round')
    show(log,'Output',state)
    return bytes(state)
