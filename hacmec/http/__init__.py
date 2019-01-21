"""
Abstract classes for HTTP clients.
"""

from __future__ import annotations

import json
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from typing import Any, Mapping, Sequence, Union

from httplink import ParsedLinks, parse_link_header

from .. import VERSION
from ..util import force


class HttpResponse(metaclass=ABCMeta):
    """
    This is the ABC which the HttpClient class must return for all requests.
    """

    _json: Mapping[str, Any]

    @property
    def json(self) -> Mapping[str, Any]:
        """
        Assuming the body is a json object/dict, decode it as such.
        """
        try:
            return self._json
        except AttributeError:
            self._json = force(json.loads(self.body.decode()), dict)
            return self._json

    def header(self, key: str) -> str:
        """
        Get value of first header.
        """
        return self.headers(key)[0]

    @property
    def type(self) -> str:
        """
        Content-Type: header.
        """
        try:
            return self.header('Content-Type').split(';')[0].strip()
        except IndexError:
            return 'application/octet-stream'

    @property
    def location(self) -> str:
        """
        Location: header.
        """
        return self.header('Location')

    @property
    def links(self) -> ParsedLinks:
        """
        Parsed Link: http header.
        """
        return parse_link_header(','.join(self.headers('Links')))

    @property
    @abstractmethod
    def status(self) -> int:
        """
        HTTP status code, e.g. 200 or 418.
        """

    @property
    @abstractmethod
    def body(self) -> Union[bytes, bytearray]:
        """
        The raw HTTP body, with any transport encoding (Chunked, Compression, etc.) already removed.
        """

    @abstractmethod
    def headers(self, key: str) -> Sequence[str]:
        """
        Get response headers for a case insensitive key.
        If key isn't found, return [].
        E.g. resp.header('ConTENt-TyPe') should return ['application/json'].
        """


class HttpClient(metaclass=ABCMeta):
    """
    Implementation of an HTTP client.
    """
    @property
    def hacmec_user_agent(self) -> str:
        """
        This string SHOULD be incorporated into the User-Agent request header.
        See ACME §6.1
        """
        return 'hacmec/' + VERSION

    @abstractmethod
    async def get(self, url: str) -> HttpResponse:
        """
        Make a GET request
        """

    @abstractmethod
    async def head(self, url: str) -> HttpResponse:
        """
        Make a HEAD request
        """

    @abstractmethod
    async def post(self, url: str, content_type: str, body: bytes) -> HttpResponse:
        """
        Make a POST request. A "Content-Type" header needs to be added. The body is already encoded,
        only chunked or similar may be applied.
        """


@dataclass
class HttpException(Exception):
    """
    Raised when an HTTP server reported an error.
    """
    resp: HttpResponse
