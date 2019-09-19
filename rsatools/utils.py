# -*- coding: utf-8 -*-
import base64
import math
import random
import sys

import pyasn1.codec.der.encoder  # pip install pyasn1
import pyasn1.type.univ
import requests

PEM_TEMPLATE = '-----BEGIN RSA PRIVATE KEY-----\n{}-----END RSA PRIVATE KEY-----\n'
FACTORDBAPI_URL = "http://factordb.com/api"


def generate_large_prime(bits=1024):
    while True:
        num = random.randrange(2 ** (bits - 1), 2 ** bits)
        if is_prime(num):
            return num


def is_prime(n, k=5):
    """
    miller-rabin algorithm
    SRC: https://stackoverflow.com/questions/36522167/checking-primality-of-very-large-numbers-in-python
    :param n: Number to test
    :param k: random trials
    :return: boolean
    """
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61):
        if n % p == 0:
            return n == p
    s, d = 0, n - 1
    while d % 2 == 0:
        s, d = s + 1, d // 2
    for trials in range(k):
        x = pow(random.randint(2, n - 1), d, n)
        if x == 1 or x == n - 1:
            continue
        for r in range(1, s):
            x = (x * x) % n
            if x == 1:
                return False
            if x == n - 1:
                break
        else:
            return False
    return True


def egcd(a, b):
    """SRC: https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
    return (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
    if a == 0:
        return b, 0, 1
    else:
        g, x, y = egcd(b % a, a)
        return g, y - (b // a) * x, x


def modinv(a, m):
    sys.setrecursionlimit(1000000)  # long type,32bit OS 4B,64bit OS 8B(1bit for sign)
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None
    else:
        return x % m


def invpow(x, n):
    """Finds the integer component of the n'th root of x,
    an integer such that y ** n <= x < (y + 1) ** n.
    """

    def is_exact(x, y, n):
        return x == y ** n

    high = 1
    while high ** n <= x:
        high *= 2
    low = high / 2
    while low < high:
        mid = (low + high) // 2
        if low < mid and mid ** n < x:
            low = mid
        elif high > mid and mid ** n > x:
            high = mid
        else:
            return int(mid), is_exact(x, mid, n)
    return int(mid) + 1, is_exact(x, int(mid) + 1, n)


def calc_phi(p, q):
    if p != q:
        return (p - 1) * (q - 1)
    return (p ** 2) - p


def factor_modulus(n, d, e):
    """
    Efficiently recover non-trivial factors of n

    See: Handbook of Applied Cryptography
    8.2.2 Security of RSA -> (i) Relation to factoring (p.287)

    http://www.cacr.math.uwaterloo.ca/hac/
    """
    t = (e * d - 1)  # e*d = t+1    e*d = k*n + 1  when ed = 1 (mod n)
    s = 0
    maxit = 2000

    while True:
        quotient, remainder = divmod(t, 2)  # return (t//2, t%2)

        if remainder != 0:  # if t is odd then break
            break

        s += 1
        t = quotient

    if s == 0:
        return None, None
    found = False
    c1 = 0
    while not found and maxit > 0:
        i = 1
        a = random.randint(1, n - 1)
        while i <= s and not found:
            c1 = pow(a, pow(2, i - 1, n) * t, n)
            c2 = pow(a, pow(2, i, n) * t, n)
            found = c1 != 1 and c1 != (-1 % n) and c2 == 1
            i += 1
            maxit -= 1
    if maxit == 0:
        return None, None
    p = math.gcd(c1 - 1, n)
    q = n // p
    return p, q


def derpempriv(n, e, d, p, q, dP, dQ, qInv):
    """SRC: http://crypto.stackexchange.com/questions/25498/how-to-create-a-pem-file-for-storing-an-rsa-key/25499#25499
    """
    seq = pyasn1.type.univ.Sequence()
    i = 0
    for x in [0, n, e, d, p, q, dP, dQ, qInv]:
        seq.setComponentByPosition(i, pyasn1.type.univ.Integer(x))
        i += 1
    der = pyasn1.codec.der.encoder.encode(seq)
    return der, PEM_TEMPLATE.format(base64.encodebytes(der).decode('ascii')).encode()


def brute_force(n, c, e):
    k = 1
    while 1:
        x = (c + k * n)
        y, ok = invpow(x, e)
        # print('k={}, x={}, n={}, y={}'.format(k, x, e, y))
        if ok:
            return y
        k = k + 1
        if k % 10000 == 0:
            print('k={}'.format(k), flush=True)


def factor_online(n):
    result = requests.get(FACTORDBAPI_URL, params={"query": str(n)})
    status = result.json().get('status')
    if status != 'FF':
        return []
    factors = result.json().get('factors')
    if not factors:
        return []
    ml = [[int(x)] * y for x, y in factors]
    return [y for x in ml for y in x]
