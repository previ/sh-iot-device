from third_party import logging
from third_party import warnings

from third_party.rsa._compat import range
import third_party.rsa.prime
import third_party.rsa.pem
import third_party.rsa.common
import third_party.rsa.randnum
import third_party.rsa.core


log = logging.getLogger(__name__)
DEFAULT_EXPONENT = 65537


class AbstractKey(object):
    #--

    __slots__ = ('n', 'e')

    def __init__(self, n, e):
        self.n = n
        self.e = e

    @classmethod
    def _load_pkcs1_pem(cls, keyfile):
        """
        """

    @classmethod
    def _load_pkcs1_der(cls, keyfile):
        """
        """

    def _save_pkcs1_pem(self):
        """
        """

    def _save_pkcs1_der(self):
        """
        """

    @classmethod
    def load_pkcs1(cls, keyfile, format='PEM'):
        """
        """

        methods = {
            'PEM': cls._load_pkcs1_pem,
            'DER': cls._load_pkcs1_der,
        }

        method = cls._assert_format_exists(format, methods)
        return method(keyfile)

    @staticmethod
    def _assert_format_exists(file_format, methods):
        #--

        try:
            return methods[file_format]
        except KeyError:
            formats = ', '.join(sorted(methods.keys()))
            raise ValueError('Unsupported format: %r, try one of %s' % (file_format,
                                                                        formats))

    def save_pkcs1(self, format='PEM'):
        #--

        methods = {
            'PEM': self._save_pkcs1_pem,
            'DER': self._save_pkcs1_der,
        }

        method = self._assert_format_exists(format, methods)
        return method()

    def blind(self, message, r):
        #--
        return (message * third_party.rsa.core.fast_pow(r, self.e, self.n)) % self.n

    def unblind(self, blinded, r):
        #--

        return (third_party.rsa.common.inverse(r, self.n) * blinded) % self.n


class PublicKey(AbstractKey):
    #--

    __slots__ = ('n', 'e')

    def __getitem__(self, key):
        return getattr(self, key)

    def __repr__(self):
        return 'PublicKey(%i, %i)' % (self.n, self.e)

    def __getstate__(self):
        #--
        return self.n, self.e

    def __setstate__(self, state):
        #--
        self.n, self.e = state

    def __eq__(self, other):
        if other is None:
            return False

        if not isinstance(other, PublicKey):
            return False

        return self.n == other.n and self.e == other.e

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash((self.n, self.e))

    @classmethod
    def _load_pkcs1_der(cls, keyfile):
        #--

        from pyasn1.codec.der import decoder
        from third_party.rsa.asn1 import AsnPubKey

        (priv, _) = decoder.decode(keyfile, asn1Spec=AsnPubKey())
        return cls(n=int(priv['modulus']), e=int(priv['publicExponent']))

    def _save_pkcs1_der(self):
        #--

        from pyasn1.codec.der import encoder
        from third_party.rsa.asn1 import AsnPubKey

        ##

        asn_key = AsnPubKey()
        asn_key.setComponentByName('modulus', self.n)
        asn_key.setComponentByName('publicExponent', self.e)

        return encoder.encode(asn_key)

    @classmethod
    def _load_pkcs1_pem(cls, keyfile):
        #--

        der = third_party.rsa.pem.load_pem(keyfile, 'RSA PUBLIC KEY')
        return cls._load_pkcs1_der(der)

    def _save_pkcs1_pem(self):
        #--

        der = self._save_pkcs1_der()
        return third_party.rsa.pem.save_pem(der, 'RSA PUBLIC KEY')

    @classmethod
    def load_pkcs1_openssl_pem(cls, keyfile):
        #--

        der = third_party.rsa.pem.load_pem(keyfile, 'PUBLIC KEY')
        return cls.load_pkcs1_openssl_der(der)

    @classmethod
    def load_pkcs1_openssl_der(cls, keyfile):
        #--

        from third_party.rsa.asn1 import OpenSSLPubKey
        from pyasn1.codec.der import decoder
        from pyasn1.type import univ

        (keyinfo, _) = decoder.decode(keyfile, asn1Spec=OpenSSLPubKey())

        if keyinfo['header']['oid'] != univ.ObjectIdentifier('1.2.840.113549.1.1.1'):
            raise TypeError("This is not a DER-encoded OpenSSL-compatible public key")

        return cls._load_pkcs1_der(keyinfo['key'][1:])


class PrivateKey(AbstractKey):
    #--

    __slots__ = ('n', 'e', 'd', 'p', 'q', 'exp1', 'exp2', 'coef')

    def __init__(self, n, e, d, p, q):
        AbstractKey.__init__(self, n, e)
        self.d = d
        self.p = p
        self.q = q

        ##

        self.exp1 = int(d % (p - 1))
        self.exp2 = int(d % (q - 1))
        self.coef = third_party.rsa.common.inverse(q, p)

    def __getitem__(self, key):
        return getattr(self, key)

    def __repr__(self):
        return 'PrivateKey(%(n)i, %(e)i, %(d)i, %(p)i, %(q)i)' % self

    def __getstate__(self):
        #--
        return self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef

    def __setstate__(self, state):
        #--
        self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef = state

    def __eq__(self, other):
        if other is None:
            return False

        if not isinstance(other, PrivateKey):
            return False

        return (self.n == other.n and
                self.e == other.e and
                self.d == other.d and
                self.p == other.p and
                self.q == other.q and
                self.exp1 == other.exp1 and
                self.exp2 == other.exp2 and
                self.coef == other.coef)

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash((self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef))

    def blinded_decrypt(self, encrypted):
        #--

        blind_r = third_party.rsa.randnum.randint(self.n - 1)
        blinded = self.blind(encrypted, blind_r)  ##

        decrypted = third_party.rsa.core.decrypt_int(blinded, self.d, self.n)

        return self.unblind(decrypted, blind_r)

    def blinded_encrypt(self, message):
        #--

        blind_r = third_party.rsa.randnum.randint(self.n - 1)
        blinded = self.blind(message, blind_r)  ##

        encrypted = third_party.rsa.core.encrypt_int(blinded, self.d, self.n)
        return self.unblind(encrypted, blind_r)

    @classmethod
    def _load_pkcs1_der(cls, keyfile):
        #--

        from pyasn1.codec.der import decoder
        (priv, _) = decoder.decode(keyfile)

        if priv[0] != 0:
            raise ValueError('Unable to read this file, version %s != 0' % priv[0])

        as_ints = map(int, priv[1:6])
        key = cls(*as_ints)

        exp1, exp2, coef = map(int, priv[6:9])

        if (key.exp1, key.exp2, key.coef) != (exp1, exp2, coef):
            warnings.warn(
                'You have provided a malformed keyfile. Either the exponents '
                'or the coefficient are incorrect. Using the correct values '
                'instead.',
                UserWarning,
            )

        return key

    def _save_pkcs1_der(self):
        #--

        from pyasn1.type import univ, namedtype
        from pyasn1.codec.der import encoder

        class AsnPrivKey(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('version', univ.Integer()),
                namedtype.NamedType('modulus', univ.Integer()),
                namedtype.NamedType('publicExponent', univ.Integer()),
                namedtype.NamedType('privateExponent', univ.Integer()),
                namedtype.NamedType('prime1', univ.Integer()),
                namedtype.NamedType('prime2', univ.Integer()),
                namedtype.NamedType('exponent1', univ.Integer()),
                namedtype.NamedType('exponent2', univ.Integer()),
                namedtype.NamedType('coefficient', univ.Integer()),
            )

        asn_key = AsnPrivKey()
        asn_key.setComponentByName('version', 0)
        asn_key.setComponentByName('modulus', self.n)
        asn_key.setComponentByName('publicExponent', self.e)
        asn_key.setComponentByName('privateExponent', self.d)
        asn_key.setComponentByName('prime1', self.p)
        asn_key.setComponentByName('prime2', self.q)
        asn_key.setComponentByName('exponent1', self.exp1)
        asn_key.setComponentByName('exponent2', self.exp2)
        asn_key.setComponentByName('coefficient', self.coef)

        return encoder.encode(asn_key)

    @classmethod
    def _load_pkcs1_pem(cls, keyfile):

        der = third_party.rsa.pem.load_pem(keyfile, b'RSA PRIVATE KEY')
        return cls._load_pkcs1_der(der)

    def _save_pkcs1_pem(self):
        #--

        der = self._save_pkcs1_der()
        return third_party.rsa.pem.save_pem(der, b'RSA PRIVATE KEY')


def find_p_q(nbits, getprime_func=third_party.rsa.prime.getprime, accurate=True):
    total_bits = nbits * 2
    shift = nbits // 16
    pbits = nbits + shift
    qbits = nbits - shift

    log.debug('find_p_q(%i): Finding p', nbits)
    p = getprime_func(pbits)
    log.debug('find_p_q(%i): Finding q', nbits)
    q = getprime_func(qbits)

    def is_acceptable(p, q):

        if p == q:
            return False

        if not accurate:
            return True

        ##

        found_size = third_party.rsa.common.bit_size(p * q)
        return total_bits == found_size

    ##

    change_p = False
    while not is_acceptable(p, q):
        ##

        if change_p:
            p = getprime_func(pbits)
        else:
            q = getprime_func(qbits)

        change_p = not change_p

    return max(p, q), min(p, q)


def calculate_keys_custom_exponent(p, q, exponent):

    phi_n = (p - 1) * (q - 1)

    try:
        d = third_party.rsa.common.inverse(exponent, phi_n)
    except third_party.rsa.common.NotRelativePrimeError as ex:
        raise third_party.rsa.common.NotRelativePrimeError(
            exponent, phi_n, ex.d,
            msg="e (%d) and phi_n (%d) are not relatively prime (divider=%i)" %
                (exponent, phi_n, ex.d))

    if (exponent * d) % phi_n != 1:
        raise ValueError("e (%d) and d (%d) are not mult. inv. modulo "
                         "phi_n (%d)" % (exponent, d, phi_n))

    return exponent, d


def calculate_keys(p, q):
    #--

    return calculate_keys_custom_exponent(p, q, DEFAULT_EXPONENT)


def gen_keys(nbits, getprime_func, accurate=True, exponent=DEFAULT_EXPONENT):

    while True:
        (p, q) = find_p_q(nbits // 2, getprime_func, accurate)
        try:
            (e, d) = calculate_keys_custom_exponent(p, q, exponent=exponent)
            break
        except ValueError:
            pass

    return p, q, e, d


def newkeys(nbits, accurate=True, poolsize=1, exponent=DEFAULT_EXPONENT):

    if nbits < 16:
        raise ValueError('Key too small')

    if poolsize < 1:
        raise ValueError('Pool size (%i) should be >= 1' % poolsize)

    if poolsize > 1:
        from rsa import parallel
        import functools

        getprime_func = functools.partial(parallel.getprime, poolsize=poolsize)
    else:
        getprime_func = third_party.rsa.prime.getprime

    (p, q, e, d) = gen_keys(nbits, getprime_func, accurate=accurate, exponent=exponent)

    n = p * q

    return (
        PublicKey(n, e),
        PrivateKey(n, e, d, p, q)
    )


__all__ = ['PublicKey', 'PrivateKey', 'newkeys']

if __name__ == '__main__':
    import doctest

    try:
        for count in range(100):
            (failures, tests) = doctest.testmod()
            if failures:
                break

            if (count % 10 == 0 and count) or count == 1:
                print('%i times' % count)
    except KeyboardInterrupt:
        print('Aborted')
    else:
        print('Doctests done')
