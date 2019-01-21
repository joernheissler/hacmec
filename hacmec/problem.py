"""
Problem documents as defined by RFC7807 and ACME.
"""
from __future__ import annotations
from typing import Any, List, Mapping, Optional, TypeVar, Type
from .http import HttpResponse
from .util import force


class HttpProblem(Exception):
    """
    RFC7807 problem document.
    """
    MIME_TYPE = 'application/problem+json'
    PREFIX: str = ''
    SUFFIX: str = ''

    problem: Mapping[str, Any]
    resp: Optional[HttpResponse]

    def __init__(self, problem: Mapping[str, Any], resp: Optional[HttpResponse] = None):
        self.problem = problem
        self.resp = resp
        super().__init__(self.type)

    @classmethod
    def create(cls, problem: Mapping[str, Any], resp: Optional[HttpResponse] = None) -> HttpProblem:
        """
        Create more specific sub class by looking at the problem type.
        """
        typ = problem.get('type') or 'about:blank'

        for sub in cls.__subclasses__():
            if sub.SUFFIX:
                if sub.PREFIX + sub.SUFFIX == typ:
                    return sub(problem, resp)
            elif typ.startswith(sub.PREFIX):
                return sub.create(problem, resp)
        return cls(problem, resp)

    @property
    def type(self) -> str:
        """
        A URI reference that identifies the problem type.
        """
        return force(self.problem.get('type'), str) or 'about:blank'

    @property
    def suffix(self) -> str:
        """
        Type suffix.
        """
        return self.type[len(self.PREFIX):]

    @property
    def title(self) -> str:
        """
        A short, human-readable summary of the problem type.
        """
        return self.problem.get('title') or ''

    @property
    def detail(self) -> str:
        """
        A human-readable explanation specific to this occurrence of the problem.
        """
        return force(self.problem.get('detail'), str) or ''

    @property
    def identifier(self) -> str:
        """
        Get subproblem identifier.
        """
        return force(self.problem['identifier'], str)

    def __str__(self) -> str:
        """
        Human-readable version of this problem.
        """
        value = f'type={self.type!r} title={self.title!r} detail={self.detail!r}'
        if self.resp:
            value += f' status={self.resp.status}'
        return value


class AcmeProblem(HttpProblem):
    """
    ACME problem, ACME §6.7
    """
    PREFIX = 'urn:ietf:params:acme:error:'

    @property
    def subproblems(self) -> List[HttpProblem]:
        """
        List of Sub problems, ACME §6.7.1
        """
        return [
            HttpProblem.create(force(sub, dict))
            for sub in self.problem.get('subproblems', [])
        ]


class AcmeProblemAccountDoesNotExist(AcmeProblem):
    """
    The request specified an account that does not exist
    """
    SUFFIX = 'accountDoesNotExist'


class AcmeProblemAlreadyRevoked(AcmeProblem):
    """
    The request specified a certificate to be revoked that has already been revoked
    """
    SUFFIX = 'alreadyRevoked'


class AcmeProblemBadCSR(AcmeProblem):
    """
    The CSR is unacceptable (e.g., due to a short key)
    """
    SUFFIX = 'badCSR'


class AcmeProblemBadNonce(AcmeProblem):
    """
    The client sent an unacceptable anti-replay nonce
    """
    SUFFIX = 'badNonce'


class AcmeProblemBadRevocationReason(AcmeProblem):
    """
    The revocation reason provided is not allowed by the server
    """
    SUFFIX = 'badRevocationReason'


class AcmeProblemBadSignatureAlgorithm(AcmeProblem):
    """
    The JWS was signed with an algorithm the server does not support
    """
    SUFFIX = 'badSignatureAlgorithm'


class AcmeProblemCaa(AcmeProblem):
    """
    Certification Authority Authorization (CAA) records forbid the CA from issuing
    """
    SUFFIX = 'caa'


class AcmeProblemCompound(AcmeProblem):
    """
    Specific error conditions are indicated in the "subproblems" array.
    """
    SUFFIX = 'compound'


class AcmeProblemConnection(AcmeProblem):
    """
    The server could not connect to validation target
    """
    SUFFIX = 'connection'


class AcmeProblemDns(AcmeProblem):
    """
    There was a problem with a DNS query during identifier validation
    """
    SUFFIX = 'dns'


class AcmeProblemExternalAccountRequired(AcmeProblem):
    """
    The request must include a value for the "externalAccountBinding" field
    """
    SUFFIX = 'externalAccountRequired'


class AcmeProblemIncorrectResponse(AcmeProblem):
    """
    Response received didn't match the challenge's requirements
    """
    SUFFIX = 'incorrectResponse'


class AcmeProblemInvalidContact(AcmeProblem):
    """
    A contact URL for an account was invalid
    """
    SUFFIX = 'invalidContact'


class AcmeProblemMalformed(AcmeProblem):
    """
    The request message was malformed
    """
    SUFFIX = 'malformed'


class AcmeProblemRateLimited(AcmeProblem):
    """
    The request exceeds a rate limit
    """
    SUFFIX = 'rateLimited'


class AcmeProblemRejectedIdentifier(AcmeProblem):
    """
    The server will not issue for the identifier
    """
    SUFFIX = 'rejectedIdentifier'


class AcmeProblemServerInternal(AcmeProblem):
    """
    The server experienced an internal error
    """
    SUFFIX = 'serverInternal'


class AcmeProblemTls(AcmeProblem):
    """
    The server received a TLS error during validation
    """
    SUFFIX = 'tls'


class AcmeProblemUnauthorized(AcmeProblem):
    """
    The client lacks sufficient authorization
    """
    SUFFIX = 'unauthorized'


class AcmeProblemUnsupportedContact(AcmeProblem):
    """
    A contact URL for an account used an unsupported protocol scheme
    """
    SUFFIX = 'unsupportedContact'


class AcmeProblemUnsupportedIdentifier(AcmeProblem):
    """
    An identifier is of an unsupported type
    """
    SUFFIX = 'unsupportedIdentifier'


class AcmeProblemUserActionRequired(AcmeProblem):
    """
    Visit the "instance" URL and take actions specified there
    """
    SUFFIX = 'userActionRequired'
