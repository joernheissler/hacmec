"""
Implementation of JSON Web Signature.
https://tools.ietf.org/html/rfc7515 etc.
"""
from __future__ import annotations

import base64
import json
import sys
from abc import ABCMeta, abstractmethod
from typing import ByteString, cast, Any, Dict, Mapping, Optional
from cryptokey.public.key import AsymmetricAlgorithm, PrivateKey
from cryptokey.public import rsa, ecdsa, ecc
from cryptokey.backend.hashlib import sha2_256
from cryptokey import hashes


def b64_url_enc(data: ByteString) -> str:
    """
    Encode Base64url.
    https://tools.ietf.org/html/rfc7515#section-2
    """
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def b64_url_dec(data: str) -> bytes:
    """
    Decode Base64url.
    https://tools.ietf.org/html/rfc7515#section-2
    """
    return base64.urlsafe_b64decode((data + -len(data) % 4 * '=').encode())


def b64_url_uint_enc(num: int) -> str:
    """
    Encode Base64urlUInt.
    https://tools.ietf.org/html/rfc7518#section-2
    """
    return b64_url_enc(num.to_bytes(max(1, (num.bit_length() + 7) // 8), 'big'))


def b64_url_uint_dec(num: str) -> int:
    """
    Decode Base64urlUInt.
    https://tools.ietf.org/html/rfc7518#section-2
    """
    return int.from_bytes(b64_url_dec(num), 'big')


def json_encode(data: Mapping[str, Any]) -> bytes:
    """
    JSON encode `data`. Strings are sorted. Output is minimal to be compatible with rfc7638 §3.1
    """
    try:
        return json.dumps(data, sort_keys=True, separators=(',', ':')).encode()
    except Exception:
        print(data, file=sys.stderr)
        raise


def get_hash_suffix(alg: hashes.HashAlgorithm) -> str:
    """
    Get suffix by hash algorithm; used to create JWK algorithm name.
    """
    algos = {
        hashes.HashAlgorithmId.SHA2_256: '256',
        hashes.HashAlgorithmId.SHA2_384: '384',
        hashes.HashAlgorithmId.SHA2_512: '512',
    }
    return algos[alg.algorithm_id]


class Jwk(metaclass=ABCMeta):
    """
    JSON Web Key
    https://tools.ietf.org/html/rfc7517
    """
    @classmethod
    def load(cls, key: PrivateKey) -> Jwk:
        """
        Create specific JWK subclass from cryptokey PrivateKey.
        """
        if key.algorithm == AsymmetricAlgorithm.RSA:
            return JwkRsaKey(cast(rsa.RsaPrivateKey, key))

        if key.algorithm == AsymmetricAlgorithm.ECDSA:
            return JwkEcKey(cast(ecdsa.EccPrivateKey, key))

        raise NotImplementedError(f'Algorithm not supported: {key.algorithm}')

    async def sign(self, url: str, nonce: Optional[str], payload: Optional[Mapping[str, Any]] = None,
                   kid: Optional[str] = None) -> bytes:
        """
        Create JWS signature.
        """
        data: Dict[str, Any] = {
            'alg': self.alg,
            'url': url,
        }
        if kid:
            data['kid'] = kid
        else:
            data['jwk'] = self.jwk

        if nonce:
            data['nonce'] = nonce

        protected = b64_url_enc(json_encode(data))

        enc_payload = '' if payload is None else b64_url_enc(json_encode(payload))
        signature = await self._sign((protected + '.' + enc_payload).encode())

        return json_encode({
            'protected': protected,
            'payload': enc_payload,
            'signature': b64_url_enc(signature),
        })

    @property
    def thumb(self) -> str:
        """
        JSON Web Key (JWK) Thumbprint

        https://tools.ietf.org/html/rfc7638
        """
        return b64_url_enc(sha2_256(json_encode(self.jwk)).value)

    @property
    @abstractmethod
    def alg(self) -> str:
        """
        Algorithm: https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
        """

    @property
    @abstractmethod
    def jwk(self) -> Dict[str, Any]:
        """
        Key Parameters: https://www.iana.org/assignments/jose/jose.xhtml#web-key-parameters
        """

    @abstractmethod
    async def _sign(self, data: bytes) -> bytes:
        """
        Sign arbitrary data
        """


class JwkRsaKey(Jwk):
    """
    RSA key
    """
    def __init__(self, key: rsa.RsaPrivateKey) -> None:
        self._key = key

    @property
    def alg(self) -> str:
        meta = self._key.sig_meta
        if meta.scheme == rsa.RsaScheme.PSS:
            pss_meta = cast(rsa.RsaPssMetadata, meta)
            hash_alg = pss_meta.hash_alg
            if pss_meta.trailer_field != b'\xbc':
                raise NotImplementedError(f'Trailer field MUST be BC')
            if pss_meta.mgf_alg.algorithm_id != rsa.MgfAlgorithmId.MGF1:
                raise NotImplementedError(f'MGF {pss_meta.mgf_alg.algorithm_id} not supported')
            mgf_meta = cast(rsa.Mgf1Metadata, pss_meta.mgf_alg)
            if mgf_meta.hash_alg != hash_alg:
                raise NotImplementedError(
                    f'Conflicting hash algorithms. Outer uses {hash_alg} while MGF uses {mgf_meta.hash_alg}')
            return 'PS' + get_hash_suffix(hash_alg)

        if meta.scheme == rsa.RsaScheme.PKCS1v1_5:
            return 'RS' + get_hash_suffix(cast(rsa.RsaV15Metadata, meta).hash_alg)

        raise NotImplementedError(f'Scheme not implemented: {meta.scheme}')

    @property
    def jwk(self) -> Dict[str, Any]:
        pub = self._key.public

        return {
            'kty': 'RSA',
            'n': b64_url_uint_enc(pub.modulus),
            'e': b64_url_uint_enc(pub.public_exponent),
        }

    async def _sign(self, data: bytes) -> bytes:
        """
        Sign data
        """
        sig = await self._key.sign(data)
        return sig.bytes_value


class JwkEcKey(Jwk):
    """
    ECC key
    """
    _curve_map = {
        ecc.CurveId.NIST_P_256: ('P-256', 32, hashes.HashAlgorithmId.SHA2_256),
        ecc.CurveId.NIST_P_384: ('P-384', 48, hashes.HashAlgorithmId.SHA2_384),
        ecc.CurveId.NIST_P_521: ('P-521', 66, hashes.HashAlgorithmId.SHA2_512),
    }
    _key: ecdsa.EccPrivateKey
    _crv: str
    _size: int
    _valid_hash: hashes.HashAlgorithmId

    def __init__(self, key: ecdsa.EccPrivateKey) -> None:
        self._key = key
        self._crv, self._size, self._valid_hash = self._curve_map[self._key.curve_id]

    @property
    def alg(self) -> str:
        hash_alg = self._key.sig_meta.hash_alg
        if self._valid_hash != hash_alg:
            raise NotImplementedError(
                f'Curve {self._key.curve_id} needs to use hash algo {self._valid_hash}, not {hash_alg}')

        return 'ES' + get_hash_suffix(hash_alg)
        # XXX EdDSA   EdDSA signature algorithms  alg     Optional    [IESG]  [RFC8037, Section 3.1]  [RFC8032]

    @property
    def jwk(self) -> Dict[str, Any]:
        pub = self._key.public.point

        return {
            'kty': 'EC',
            'crv': self._crv,
            'x': b64_url_enc(pub.x.to_bytes(self._size, 'big')),
            'y': b64_url_enc(pub.y.to_bytes(self._size, 'big')),
        }

    async def _sign(self, data: bytes) -> bytes:
        """
        Sign data
        """
        sig = await self._key.sign(data)
        return sig.r.to_bytes(self._size, 'big') + sig.s.to_bytes(self._size, 'big')
