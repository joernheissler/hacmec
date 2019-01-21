"""
Bindings for aiohttp
"""

from __future__ import annotations

from types import TracebackType
from typing import Any, Dict, Mapping, Optional, Sequence, Type

import async_timeout
from multidict import CIMultiDictProxy

from aiohttp import ClientSession
from aiohttp.http import SERVER_SOFTWARE

from . import HttpClient, HttpResponse


class AioHttpResponse(HttpResponse):
    """
    Response from AioHttpClient
    """
    _status: int
    _headers: CIMultiDictProxy[str]
    _body: bytes

    def __init__(self, status: int, headers: CIMultiDictProxy[str], body: bytes) -> None:
        self._status = status
        self._headers = headers
        self._body = body

    @property
    def status(self) -> int:
        """
        HTTP status code, e.g. 200 or 418.
        """
        return self._status

    @property
    def body(self) -> bytes:
        """
        The raw HTTP body, with any transport encoding (Chunked, Compression, etc.) already removed.
        """
        return self._body

    def headers(self, key: str) -> Sequence[str]:
        """
        Get response headers for a case insensitive key.
        If key isn't found, return [].
        E.g. resp.header('ConTENt-TyPe') should return ['application/json'].
        """
        return self._headers.getall(key, [])


class AioSession:
    """
    Wrapper around aiohttp.ClientSession to make the context manager easier to use.
    """
    _session: Optional[ClientSession] = None
    _usage = 0

    async def __aenter__(self) -> ClientSession:
        """
        Enter
        """
        assert self._usage >= 0
        assert (self._usage == 0) == (not self._session)
        if self._usage == 0:
            session = ClientSession()
            self._session = await session.__aenter__()
        self._usage += 1
        assert self._session
        return self._session

    async def __aexit__(self, exc_type: Optional[Type[BaseException]], exc: Optional[BaseException],
                        trace: Optional[TracebackType]) -> Any:
        """
        Exit
        """
        assert self._usage > 0 and self._session

        self._usage -= 1
        if self._usage == 0:
            session = self._session
            self._session = None
            return await session.__aexit__(exc_type, exc, trace)


class AioHttpClient(HttpClient):
    """
    aiohttp based implementation of HttpClient.
    """
    _user_agent: str
    _language: Optional[str]
    _timeout = 30
    _session: AioSession

    def __init__(self, user_agent: str, language: Optional[str] = None) -> None:
        """
        user_agent: Name/version of the ACME client software.
        language: Value of Accept-Language http header. One SHOULD be given. See
                  https://tools.ietf.org/html/rfc7231#section-5.3.5
        """
        self._user_agent = f'{SERVER_SOFTWARE} {self.hacmec_user_agent} {user_agent}'
        self._language = language
        self._session = AioSession()

    async def get(self, url: str) -> AioHttpResponse:
        """
        Make a GET request
        """
        return await self.request('GET', url)

    async def head(self, url: str) -> AioHttpResponse:
        """
        Make a HEAD request
        """
        return await self.request('HEAD', url)

    async def post(self, url: str, content_type: str, body: bytes) -> AioHttpResponse:
        """
        Make a POST request. A "Content-Type" header needs to be added. The body is already encoded,
        only chunked or similar may be applied.
        """
        return await self.request('POST', url, {'Content-Type': content_type}, data=body)

    async def request(self, method: str, url: str, headers: Optional[Mapping[str, str]] = None,
                      **kwargs: Any) -> AioHttpResponse:
        """
        Make HTTP request.
        """
        # print(f'{method:4} {url:60} head={headers} args={kwargs}')
        head: Dict[str, Any] = {
            'User-Agent': self._user_agent,
            **(headers or {}),
        }
        if self._language:
            head['Accept-Language'] = self._language

        with async_timeout.timeout(self._timeout):
            async with self._session as session:
                async with session.request(method, url, headers=head, allow_redirects=False, **kwargs) as response:
                    return AioHttpResponse(response.status, response.headers, await response.read())

    async def __aenter__(self) -> AioHttpClient:
        await self._session.__aenter__()
        return self

    async def __aexit__(self, exc_type: Optional[Type[BaseException]], exc: Optional[BaseException],
                        trace: Optional[TracebackType]) -> Any:
        await self._session.__aexit__(exc_type, exc, trace)
