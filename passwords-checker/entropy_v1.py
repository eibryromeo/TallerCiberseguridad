import math
import sys

def pool_size(password):
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    return pool


def entropy_bits(password):
    pool = pool_size(password)
    return len(password) * math.log2(pool) if pool else 0


if __name__ == "__main__":
    password = sys.argv[1]
    print(f"{entropy_bits(password):.1f} bits")