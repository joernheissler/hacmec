"""
"""

from __future__ import annotations

from dataclasses import dataclass
from .http import HttpException, HttpResponse, HttpClient
from . import problem
from typing import Optional, Any, Mapping, Sequence, List, Deque, Dict
from .jws import Jwk, b64_url_enc, sha2_256
from collections import deque
from cryptokey.public.key import PrivateKey
from .util import force
import json
import logging


MAX_NONCES = 10


class Hacmec:
    """
    """
    http: HttpClient
    _nonces: Deque[str]
    _directory: AcmeDirectory

    def __init__(self, http: HttpClient) -> None:
        """
        """
        self.http = http
        self._nonces = deque()

    async def load_directory(self, url: str) -> None:
        """
        """
        directory = AcmeDirectory(self, url)
        await directory.load()
        self._directory = directory

    @property
    def directory(self) -> AcmeDirectory:
        try:
            return self._directory
        except AttributeError:
            raise Exception('load_directory was not called')

    async def get(self, url: str) -> HttpResponse:
        """
        """
        return self._process_resp(await self.http.get(url))

    async def head(self, url: str) -> HttpResponse:
        """
        """
        return self._process_resp(await self.http.head(url))

    async def post(self, key: Jwk, url: str, payload: Optional[Mapping[str, Any]] = None,
                   kid: Optional[str] = None) -> HttpResponse:
        """
        """
        try:
            nonce = await self._get_nonce()
            body = await key.sign(url, nonce, payload, kid)
            return self._process_resp(await self.http.post(url, 'application/jose+json', body))
        except problem.AcmeProblemBadNonce as err:
            assert err.resp is not None
            # Try again with the nonce that was sent with the problem response; ACME § 6.5
            if not err.resp.headers('Replay-Nonce'):
                raise Exception('Got no nonce')

            nonce = self._nonces.pop()
            body = await key.sign(url, nonce, payload, kid)
            return self._process_resp(await self.http.post(url, 'application/jose+json', body))

    async def new_nonce(self) -> str:
        """
        Fetch a new nonce and return it.
        """
        resp = await self.head(self.directory.new_nonce)
        if not resp.headers('Replay-Nonce'):
            raise Exception('Got no nonce')
        return self._nonces.pop()

    def get_account(self, key: PrivateKey, kid: str) -> AcmeAccount:
        """
        Return AcmeAccount object for key and kid.
        """
        return AcmeAccount(self, Jwk.load(key), kid, {})

    async def find_account(self, key: PrivateKey) -> AcmeAccount:
        """
        Recover account URL.
        """
        return await AcmeAccount.find(self, Jwk.load(key))

    async def register_account(self, key: PrivateKey, contact: Optional[Sequence[str]] = None, tos_agreed: bool = False,
                               ext_kid: Optional[str] = None, ext_key: Optional[str] = None) -> AcmeAccount:
        """
        Register a new account.
        """
        return await AcmeAccount.register(self, Jwk.load(key), contact or [], tos_agreed, ext_kid, ext_key)

    def _process_resp(self, resp: HttpResponse) -> HttpResponse:
        """
        Process HTTP response. Check for errors, extract nonces.
        """
        for nonce in resp.headers('Replay-Nonce'):
            self._nonces.append(nonce)
            if len(self._nonces) > MAX_NONCES:
                self._nonces.popleft()

        if resp.type == problem.HttpProblem.MIME_TYPE:
            raise problem.HttpProblem.create(resp.json, resp)

        if resp.status // 100 != 2:
            raise HttpException(resp)

        return resp

    async def _get_nonce(self) -> str:
        """
        Retrieve a nonce, either from the cache or a fresh one.
        """
        try:
            return self._nonces.popleft()
        except IndexError:
            return await self.new_nonce()


class AcmeDirectory:
    """
    ACME Directory
    """
    _hacmec: Hacmec
    url: str
    _data: Mapping[str, Any]

    def __init__(self, hacmec: Hacmec, url: str) -> None:
        """
        hacmec: Parent object
        url: ACME directory URL
        """
        self._hacmec = hacmec
        self.url = url

    async def load(self) -> None:
        """
        Retrieve the directory.
        """
        self._data = force((await self._hacmec.get(self.url)).json, dict)

    def get_str(self, key: str) -> str:
        """
        Get a value and ensure that it's a str.
        """
        return force(self._data[key], str)

    @property
    def new_nonce(self) -> str:
        """
        New nonce
        """
        return self.get_str('newNonce')

    @property
    def new_account(self) -> str:
        """
        New account
        """
        return self.get_str('newAccount')

    @property
    def new_order(self) -> str:
        """
        New order
        """
        return self.get_str('newOrder')

    @property
    def new_authz(self) -> str:
        """
        New authorization
        """
        return self.get_str('newAuthz')

    @property
    def revoke_cert(self) -> str:
        """
        Revoke certificate
        """
        return self.get_str('revokeCert')

    @property
    def key_change(self) -> str:
        """
        Key change
        """
        return self.get_str('keyChange')

    @property
    def meta(self) -> Mapping[str, Any]:
        """
        Metadata object
        """
        return force(self._data.get('meta', {}), dict)

    @property
    def terms_of_service(self) -> str:
        """
        A URL identifying the current terms of service.
        """
        return force(self.meta['termsOfService'], str)

    @property
    def website(self) -> str:
        """
        An HTTP or HTTPS URL locating a website providing more information about the ACME server.
        """
        return force(self.meta['website'], str)

    @property
    def caa_identities(self) -> List[str]:
        """
        The hostnames that the ACME server recognizes as referring to itself for the purposes of CAA record
        validation.
        """
        value = force(self.meta.get('caaIdentities', []), list)
        for val in value:
            force(val, str)
        return value

    @property
    def external_account_required(self) -> bool:
        """
        If True, then the CA requires that all new-account requests include an "externalAccountBinding" field
        associating the new account with an external account.
        """
        return force(self.meta.get('externalAccountRequired', False), bool)


class AcmeAccount:
    """
    ACME account object.
    """
    _hacmec: Hacmec
    key: Jwk
    kid: str
    data: Mapping[str, Any]

    @classmethod
    async def find(cls, hacmec: Hacmec, key: Jwk) -> AcmeAccount:
        """
        Find account by key.

        hacmec: Parent object
        key: private key
        """

        logging.info('Retrieving account by key')
        resp = await hacmec.post(key, hacmec.directory.new_account, {
            'onlyReturnExisting': True,
        })
        return AcmeAccount(hacmec, key, resp.location, resp.json)

    @classmethod
    async def register(cls, hacmec: Hacmec, key: Jwk, contact: Sequence[str], tos_agreed: bool,
                       ext_kid: Optional[str], ext_key: Optional[str]) -> AcmeAccount:
        """
        Register new account.
        """
        params: Dict[str, Any] = {}
        if contact:
            params['contact'] = contact

        if tos_agreed:
            params['termsOfServiceAgreed'] = tos_agreed

        logging.info('Registering new account')
        resp = await hacmec.post(key, hacmec.directory.new_account, params)
        return AcmeAccount(hacmec, key, resp.location, resp.json)

    def __init__(self, hacmec: Hacmec, key: Jwk, kid: str, data: Mapping[str, Any]) -> None:
        """
        hacmec: Parent object
        """
        self._hacmec = hacmec
        self.key = key
        self.kid = kid
        self.data = data

    def __str__(self) -> str:
        return f'AcmeAccount(kid={self.kid}, status={self.status})'

    @property
    def contact(self) -> Sequence[str]:
        contacts = force(self.data.get('contact', []), list)
        for cont in contacts:
            force(cont, str)
        return contacts

    @property
    def status(self) -> str:
        return force(self.data['status'], str)

    @property
    def orders(self) -> str:
        return force(self.data['orders'], str)

    @property
    def tos_agreed(self) -> bool:
        return force(self.data['termsOfServiceAgreed'], bool)

    async def post(self, url: str, payload: Optional[Mapping[str, Any]] = None) -> HttpResponse:
        return await self._hacmec.post(self.key, url, payload, self.kid)

    async def update(self, updates: Optional[Mapping[str, Any]] = None) -> None:
        self.data = (await self.post(self.kid, updates or {})).json

    async def set_contacts(self, contacts: Sequence[str]) -> None:
        """
        Update account contacts.
        """
        await self.update({'contact': contacts})

    async def deactivate(self) -> None:
        """
        Deactivate account.
        """
        await self.update({'status': 'deactivated'})

    async def change_key(self, new_key: PrivateKey) -> None:
        """
        Account key rollover.
        """
        new_jwk = Jwk.load(new_key)
        url = self._hacmec.directory.key_change
        sig_new = await new_jwk.sign(url, None, {
            'account': self.kid,
            'oldKey': self.key.jwk,
        })

        resp = await self.post(url, json.loads(sig_new))
        self.key = new_jwk

    async def new_order(self, ids: Sequence[AcmeIdentifier], not_before: Optional[str] = None, not_after: Optional[str] = None) -> AcmeOrder:
        """
        Create new ACME order.
        """
        payload: Mapping[str, Any] = {
            'identifiers': [identifier.obj for identifier in ids],
        }
        if not_before:
            payload['notBefore'] = not_before
        if not_after:
            payload['notAfter'] = not_after

        resp = await self.post(self._hacmec.directory.new_order, payload)
        return AcmeOrder(self, resp.location, resp.json)

    async def load_order(self, url: str) -> AcmeOrder:
        return await AcmeOrder.load(self, url)


class AcmeOrder:
    """
    ACME Order object.
    """
    _acc: AcmeAccount
    _hacmec: Hacmec
    url: str
    data: Mapping[str, Any]
    _identifiers: List[AcmeIdentifier]
    _authorizations: List[AcmeAuthorization]

    @classmethod
    async def load(cls, account: AcmeAccount, url: str) -> AcmeOrder:
        """
        Load order by URL
        """
        resp = await account.post(url)
        return cls(account, url, resp.json)

    def __init__(self, account: AcmeAccount, url: str, data: Mapping[str, Any]) -> None:
        """
        """
        self._acc = account
        self._hacmec = account._hacmec
        self.url = url
        self.data = data

    @property
    def status(self) -> str:
        return force(self.data['status'], str)

    @property
    def expires(self) -> str:
        return force(self.data['expires'], str)

    @property
    def identifiers(self) -> List[AcmeIdentifier]:
        try:
            return self._identifiers
        except AttributeError:
            self._identifiers = [
                AcmeIdentifier(force(identifer['type'], str), force(identifer['value'], str))
                for identifer in force(self.data['identifiers'], list)
            ]
            return self._identifiers

    @property
    def not_before(self) -> str:
        return force(self.data['notBefore'], str)

    @property
    def not_after(self) -> str:
        return force(self.data['notAfter'], str)

    @property
    def error(self) -> problem.HttpError:
        raise NotImplementedError()

    @property
    def authorizations(self) -> List[AcmeAuthorization]:
        try:
            return self._authorizations
        except AttributeError:
            self._authorizations = [
                AcmeAuthorization(self, force(url, str), {})
                for url in force(self.data['authorizations'], list)
            ]
            return self._authorizations

    @property
    def finalize(self) -> str:
        return force(self.data['finalize'], str)

    async def send_csr(self, req: bytes) -> None:
        self.data = (await self._acc.post(self.finalize, {'csr': b64_url_enc(req)})).json

    @property
    def certificate(self) -> str:
        return force(self.data['certificate'], str)

    async def update(self) -> None:
        self.data = (await self._acc.post(self.url)).json

    async def download(self) -> bytes:
        return (await self._acc.post(self.certificate)).body



class AcmeAuthorization:
    _acc: AcmeAccount
    _hacmec: Hacmec
    order: AcmeOrder
    url: str
    data: Mapping[str, Any]

    def __init__(self, order: AcmeOrder, url: str, data: Mapping[str, Any]) -> None:
        self._acc = order._acc
        self._hacmec = self._acc._hacmec
        self.order = order
        self.url = url
        self.data = data

    async def update(self) -> None:
        self.data = (await self._acc.post(self.url)).json

    @property
    def challenges(self) -> Sequence[AcmeChallenge]:
        return [
            AcmeChallenge.create(self, force(chall, dict))
            for chall in force(self.data['challenges'], list)
        ]

    @property
    def status(self) -> str:
        return force(self.data['status'], str)

    @property
    def expires(self) -> str:
        return force(self.data['expires'], str)

    @property
    def identifier(self) -> AcmeIdentifier:
        iden = force(self.data['identifier'], dict)
        return AcmeIdentifier(force(iden['type'], str), force(iden['value'], str))

    @property
    def wildcard(self) -> bool:
        return force(self.data.get('wildcard', False), bool)


class AcmeChallenge:
    _acc: AcmeAccount
    _hacmec: Hacmec
    auth: AcmeAuthorization
    data: Mapping[str, Any]

    def __init__(self, auth: AcmeAuthorization, data: Mapping[str, Any]) -> None:
        self.auth = auth
        self.data = data
        self._acc = auth._acc
        self._hacmec = self._acc._hacmec

    @property
    def status(self) -> str:
        return force(self.data['status'], str)

    @property
    def url(self) -> str:
        return force(self.data['url'], str)

    @property
    def typ(self) -> str:
        return force(self.data['type'], str)

    @property
    def token(self) -> str:
        return force(self.data['token'], str)

    @property
    def error(self) -> problem.HttpError:
        raise NotImplementedError()

    @property
    def key_authorization(self) -> str:
        return self.token + '.' + self._acc.key.thumb

    async def respond(self) -> None:
        resp = await self._acc.post(self.url, {})

    @classmethod
    def create(cls, auth: AcmeAuthorization, data: Mapping[str, Any]) -> AcmeChallenge:
        typ = force(data['type'], str)
        for sub in cls.__subclasses__():
            if sub.TYPE == typ:
                return sub(auth, data)
        return cls(auth, data)
        

class AcmeChallengeHttp01(AcmeChallenge):
    TYPE = 'http-01'



class AcmeChallengeTlsAlpn01(AcmeChallenge):
    TYPE = 'tls-alpn-01'


class AcmeChallengeDns01(AcmeChallenge):
    TYPE = 'dns-01'

    @property
    def fqdn(self) -> str:
        return '_acme-challenge.' + self.auth.identifier.value.rstrip('.')

    @property
    def txt_record(self) -> str:
        return b64_url_enc(sha2_256(self.key_authorization.encode()).value)


@dataclass(frozen=True)
class AcmeIdentifier:
    typ: str
    value: str

    @property
    def obj(self) -> Mapping[str, str]:
        return {
            'type': self.typ,
            'value': self.value,
        }

    @classmethod
    def dns(cls, value: str):
        return cls('dns', value)
