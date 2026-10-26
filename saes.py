"""S-AES 分组加解密、多重加密、CBC 与中间相遇攻击；整数按高位在前、半字节按列排列。"""
from functools import lru_cache
import secrets

SBOX = (9, 4, 10, 11, 13, 1, 8, 5, 6, 2, 0, 3, 12, 14, 15, 7)
INV_SBOX = tuple(SBOX.index(value) for value in range(16))


def check_word(value, bits=16):
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise ValueError(f"数值必须是 {bits} bit 无符号整数")
    return value


def parse_bits(text, bits=16):
    text = ''.join(text.split())
    if len(text) != bits or set(text) - {'0', '1'}:
        raise ValueError(f"请输入恰好 {bits} 位二进制数据")
    return int(text, 2)


def gf_multiply(left, right):
    """GF(2^4) 乘法，模 x^4+x+1（0x13）。"""
    result = 0
    for _ in range(4):
        if right & 1:
            result ^= left
        right >>= 1
        left <<= 1
        if left & 0x10:
            left ^= 0x13
    return result


def substitute(state, box=SBOX):
    return sum(box[(state >> shift) & 15] << shift for shift in (12, 8, 4, 0))


def shift_rows(state):
    return (state & 0xF0F0) | ((state & 0x0F00) >> 8) | ((state & 0x000F) << 8)


def mix_columns(state, inverse=False):
    diagonal, off_diagonal = (9, 2) if inverse else (1, 4)
    result = 0
    for shift in (8, 0):
        upper, lower = (state >> (shift + 4)) & 15, (state >> shift) & 15
        result |= (gf_multiply(diagonal, upper) ^ gf_multiply(off_diagonal, lower)) << (shift + 4)
        result |= (gf_multiply(off_diagonal, upper) ^ gf_multiply(diagonal, lower)) << shift
    return result


@lru_cache(maxsize=65536)
def expand_key(key):
    check_word(key)
    words = [key >> 8, key & 255]
    for constant in (0x80, 0x30):
        previous = words[-1]
        rotated = ((previous & 15) << 4) | (previous >> 4)
        transformed = (SBOX[rotated >> 4] << 4) | SBOX[rotated & 15]
        words.append(words[-2] ^ constant ^ transformed)
        words.append(words[-1] ^ previous)
    return tuple((words[index] << 8) | words[index + 1] for index in (0, 2, 4))


def encrypt_block(plaintext, key):
    check_word(plaintext)
    initial, first, final = expand_key(key)
    state = mix_columns(shift_rows(substitute(plaintext ^ initial))) ^ first
    return shift_rows(substitute(state)) ^ final


def decrypt_block(ciphertext, key):
    check_word(ciphertext)
    initial, first, final = expand_key(key)
    state = substitute(shift_rows(ciphertext ^ final), INV_SBOX)
    state = mix_columns(state ^ first, inverse=True)
    return substitute(shift_rows(state), INV_SBOX) ^ initial


def split_key(key, count):
    check_word(key, 16 * count)
    return tuple((key >> (16 * index)) & 65535 for index in reversed(range(count)))


def multiple_encrypt(plaintext, key, count=2):
    if count not in (2, 3):
        raise ValueError("仅支持双重或三重 EEE 加密")
    for subkey in split_key(key, count):
        plaintext = encrypt_block(plaintext, subkey)
    return plaintext


def multiple_decrypt(ciphertext, key, count=2):
    if count not in (2, 3):
        raise ValueError("仅支持双重或三重 EEE 加密")
    for subkey in reversed(split_key(key, count)):
        ciphertext = decrypt_block(ciphertext, subkey)
    return ciphertext


def meet_in_the_middle(pairs, progress=None, cancelled=None):
    """完整枚举两侧 16-bit 密钥；保存碰撞列表，并用其余明密文对过滤。"""
    pairs = list(pairs)
    if not pairs:
        raise ValueError("至少需要一组明文、密文")
    for plain, cipher in pairs:
        check_word(plain)
        check_word(cipher)
    table = {}
    candidates = []
    for stage in range(2):
        for key in range(65536):
            if key % 1024 == 0:
                if cancelled and cancelled():
                    raise InterruptedError("攻击已取消")
                if progress:
                    progress(stage * 65536 + key, 131072)
            if stage == 0:
                middle = encrypt_block(pairs[0][0], key)
                table.setdefault(middle, []).append(key)
            else:
                middle = decrypt_block(pairs[0][1], key)
                for first_key in table.get(middle, ()):
                    combined = (first_key << 16) | key
                    if all(multiple_encrypt(plain, combined) == cipher for plain, cipher in pairs[1:]):
                        candidates.append(combined)
    if progress:
        progress(131072, 131072)
    return candidates


def pad(data):
    length = 2 - len(data) % 2
    return data + bytes([length]) * length


def unpad(data):
    if not data or len(data) % 2 or data[-1] not in (1, 2) or data[-data[-1]:] != bytes([data[-1]]) * data[-1]:
        raise ValueError("PKCS#7 填充无效（可能密钥、IV 或密文错误）")
    return data[:-data[-1]]


def transform_bytes(data, key, decrypt=False):
    """字符串扩展使用独立 2-byte 分组和 PKCS#7 填充。"""
    check_word(key)
    if decrypt:
        if not data or len(data) % 2:
            raise ValueError("密文字节数必须为正偶数")
    else:
        data = pad(data)
    operation = decrypt_block if decrypt else encrypt_block
    result = b''.join(operation(int.from_bytes(data[i:i+2], 'big'), key).to_bytes(2, 'big') for i in range(0, len(data), 2))
    return unpad(result) if decrypt else result


def new_iv():
    return secrets.randbits(16)


def cbc_encrypt(data, key, iv):
    check_word(key)
    check_word(iv)
    previous = iv
    output = bytearray()
    data = pad(data)
    for index in range(0, len(data), 2):
        previous = encrypt_block(int.from_bytes(data[index:index+2], 'big') ^ previous, key)
        output.extend(previous.to_bytes(2, 'big'))
    return bytes(output)


def cbc_decrypt(data, key, iv, remove_padding=True):
    check_word(key)
    check_word(iv)
    if not data or len(data) % 2:
        raise ValueError("CBC 密文字节数必须为正偶数")
    previous = iv
    output = bytearray()
    for index in range(0, len(data), 2):
        block = int.from_bytes(data[index:index+2], 'big')
        output.extend((decrypt_block(block, key) ^ previous).to_bytes(2, 'big'))
        previous = block
    return unpad(bytes(output)) if remove_padding else bytes(output)
