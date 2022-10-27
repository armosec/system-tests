import math
from collections import Counter


def compute_entropy(data, unit='shannon'):
    base = {
        'shannon': 2.,
        'natural': math.exp(1),
        'hartley': 10.
    }

    if len(data) <= 1:
        return 0

    counts = Counter()

    for d in data:
        counts[d] += 1

    ent = 0

    probs = [float(c) / len(data) for c in counts.values()]
    for p in probs:
        if p > 0.:
            ent -= p * math.log(p, base[unit])

    return ent


def get_file_data(file_name=None, fileobj=None):
    if file_name and fileobj:
        raise Exception('Only exactly one file parameter should be provided')
    if not file_name and not fileobj:
        raise Exception('No file parameter was provided')

    if file_name:
        fileobj = open(file_name, 'rb')

    fileobj.seek(0)

    data = fileobj.read()

    if file_name:
        fileobj.close()

    return data


def is_file_repeated(file_name=None, fileobj=None, repeat_factor=16):
    if file_name and fileobj:
        raise Exception('Only exactly one file parameter should be provided')
    if not file_name and not fileobj:
        raise Exception('No file parameter was provided')
    if file_name:
        fileobj = open(file_name, 'rb')
    fileobj.seek(0)
    data = fileobj.read()

    if file_name:
        fileobj.close()
    first_bytes = data[:repeat_factor]
    for i in range((len(data) // repeat_factor) - 2):
        for j in range(len(first_bytes)):
            if first_bytes[j] != data[i * repeat_factor + j]:
                return False
    return True


def is_ecb_bypass(data):
    sample = data[0:16]
    for i in range(16, 256, 16):
        if sample != data[i:i + 16]:
            return False
    return True


def is_file_encrypted(file_name=None, fileobj=None, ent=6.5, ecb_bypass=False):
    data = get_file_data(file_name, fileobj)
    e = compute_entropy(data)
    encrypted = e > ent
    if not encrypted and ecb_bypass:
        encrypted = is_ecb_bypass(data)

    return encrypted


def is_file_decrypted(file_name=None, fileobj=None, ent=6.5):
    data = get_file_data(file_name, fileobj)
    e = compute_entropy(data)

    return e <= ent
