# -*- coding: utf-8 -*-
import optparse
from argparse import ArgumentError

from rsatools import utils

DEFAULT_EXP = 65537


def main():
    parser = optparse.OptionParser()

    parser.add_option('-g', dest='generate', help='generate key with # of bits', type='int')
    parser.add_option('--hex', help='display values in hex', action='store_true', default=False)
    parser.add_option('-p', dest='p', help='prime p', type='int')
    parser.add_option('-q', dest='q', help='prime q', type='int')
    parser.add_option('-n', dest='n', help='modulus', type='int')
    parser.add_option('-d', dest='d', help='private exponent', type='int')
    parser.add_option('-e', dest='e', help='public exponent (default: {})'.format(DEFAULT_EXP), type='int',
                      default=DEFAULT_EXP)
    parser.add_option('-o', dest='filename', help='output filename')
    parser.add_option('-f', dest='format', help='output format (RAW, CSV, DER, PEM) (default: RAW)',
                      type='choice', choices=['RAW', 'CSV', 'DER', 'PEM'], default='RAW')
    parser.add_option('-v', dest='verbose', help='also display CRT-RSA representation (RAW or CSV)',
                      action='store_true', default=False)
    parser.add_option('-m', dest='m', help='message to crypt (RAW or CSV)', type='int', default=None)
    parser.add_option('-c', dest='c', help='ciphertext to decrypt (RAW or CSV)', type='int', default=None)

    try:
        (options, args) = parser.parse_args()
        e = options.e
        p = options.p
        q = options.q
        n = options.n
        d = options.d
        c = options.c
        m = options.m
        bits = options.generate
        inhex = options.hex
        ofmt = options.format
        filename = options.filename
        if bits:
            # Generate RSA key
            while True:
                p = utils.generate_large_prime(bits)
                q = utils.generate_large_prime(bits)
                phi = utils.calc_phi(p, q)
                d = utils.modinv(e, phi)
                if d is not None:
                    break
        elif p and q:
            assert utils.is_prime(p), 'p is not prime'
            assert utils.is_prime(q), 'q is not prime'
        elif n and d:
            print('Factoring n with d and e')
            p, q = utils.factor_modulus(n, d, e)
            if p is None or e is None:
                raise ArgumentError(None, 'Impossible to calculate p and q')
        elif n and c:
            if e >= 5:
                raise ArgumentError(None, 'To try brute force, e must be really small (<6)')
            print('Applying brute force attack in the ciphertext')
            m = utils.brute_force(n, c, e)
            if inhex:
                m = hex(m)
            print('m = {}'.format(m))
            # TODO how calc others params?
            return
        elif n:
            print('Trying to factor n online')
            factors = utils.factor_online(n)
            if len(factors) != 2:
                raise ArgumentError(None, 'Impossible to factor online')
            p, q = factors
        else:
            parser.print_usage()
            return

        phi = utils.calc_phi(p, q)
        n = p * q
        d = utils.modinv(e, phi)
        if d is None:
            raise ArgumentError(None, 'Modular inverse does not exist')
        # CRT-RSA precomputation
        # to accelerate the calculation
        dP = d % (p - 1)
        dQ = d % (q - 1)
        qInv = utils.modinv(q, p)
        if qInv is None:
            raise ArgumentError(None, 'Modular inverse does not exist')

        if m is not None:
            c = pow(m, e, n)
        elif c is not None:
            m = pow(c, d, n)

        output = ''
        if ofmt in ('RAW', 'CSV'):
            dvars = ['e', 'p', 'q', 'n', 'd']
            if options.verbose:
                dvars += ['phi', 'dP', 'dQ', 'qInv']
            if m is not None:
                dvars += ['m']
            if c is not None:
                dvars += ['c']
            for name in dvars:
                val = eval(name)
                if val is None:
                    continue
                val = hex(val) if inhex else str(val)
                if ofmt == 'RAW':
                    output += '{} = {}\n'.format(name, val)
                else:
                    output += val
                    if name != dvars[-1]:
                        output += ','
        elif ofmt in ('DER', 'PEM'):
            der, pem = utils.derpempriv(n, e, d, p, q, dP, dQ, qInv)
            if ofmt == 'PEM':
                output = pem
            else:
                output = der
        if filename:
            if type(output) is str:
                output = output.encode()
            fp = open(filename, 'wb')
            fp.write(output)
            fp.close()
        else:
            if type(output) is bytes:
                output = output.decode('ascii')
            print(output)

    except optparse.OptionValueError as ex:
        parser.print_help()
        parser.error(ex.msg)


if __name__ == '__main__':
    main()
