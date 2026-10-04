from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final
import hashlib
import hmac
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa


PROTOCOL_LABEL: Final = b"CSCE465-HS-v2"
GROUP_IDENTIFIER: Final = b"ffdhe3072"
KDF_LABEL: Final = b"CSCE465-KDF-v1"
GATEWAY_ROLE: Final = b"gateway"
NODE_ROLE: Final = b"node"
DH_BYTES: Final = 384
NONCE_BYTES: Final = 16
# SHA-256 of the 384-byte big-endian RFC 7919 ffdhe3072 modulus.  Checking it
# prevents a same-size, attacker-selected DH group from being mislabeled.
FFDHE3072_MODULUS_SHA256: Final = bytes.fromhex(
    "0eaf67db3a839156d5013494a5318a772b5697d270d721f37f092efc69ea5a17"
)


class HandshakeError(ValueError):
    """A peer message or the negotiated handshake is unacceptable."""


def _frame(field: bytes) -> bytes:
    """Encode one transcript field using a four-byte, big-endian length."""
    if len(field) > 0xFFFFFFFF:
        raise HandshakeError("transcript field is too long")
    return len(field).to_bytes(4, "big") + field


def encode_transcript(
    gateway_identity: bytes,
    node_identity: bytes,
    gateway_public: bytes,
    node_public: bytes,
    gateway_nonce: bytes,
    node_nonce: bytes,
) -> bytes:
    """Return the canonical transcript specified by the assignment.

    The order is label, group, gateway identity, node identity, gateway DH
    public value, node DH public value, gateway nonce, and node nonce.
    """
    _validate_identity(gateway_identity)
    _validate_identity(node_identity)
    _validate_public_bytes(gateway_public)
    _validate_public_bytes(node_public)
    _validate_nonce(gateway_nonce)
    _validate_nonce(node_nonce)
    fields = (
        PROTOCOL_LABEL,
        GROUP_IDENTIFIER,
        gateway_identity,
        node_identity,
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    )
    return b"".join(_frame(field) for field in fields)


def decode_transcript(encoded: bytes) -> tuple[bytes, ...]:
    """Strictly parse and validate a canonical transcript before it is hashed."""
    fields: list[bytes] = []
    offset = 0
    for _ in range(8):
        if len(encoded) - offset < 4:
            raise HandshakeError("malformed transcript length prefix")
        length = int.from_bytes(encoded[offset : offset + 4], "big")
        offset += 4
        if length > len(encoded) - offset:
            raise HandshakeError("declared transcript length exceeds input")
        fields.append(encoded[offset : offset + length])
        offset += length
    if offset != len(encoded):
        raise HandshakeError("malformed transcript has trailing fields")

    label, group, gateway_id, node_id, gateway_pub, node_pub, gateway_nonce, node_nonce = fields
    if label != PROTOCOL_LABEL or group != GROUP_IDENTIFIER:
        raise HandshakeError("unexpected protocol or group")
    _validate_identity(gateway_id)
    _validate_identity(node_id)
    _validate_public_bytes(gateway_pub)
    _validate_public_bytes(node_pub)
    _validate_nonce(gateway_nonce)
    _validate_nonce(node_nonce)
    # Require the one unique serialization after parsing too.  This catches
    # noncanonical encodings before a transcript hash can be computed.
    if encoded != encode_transcript(*fields[2:]):
        raise HandshakeError("noncanonical transcript encoding")
    return tuple(fields)


def _validate_identity(identity: bytes) -> None:
    if not isinstance(identity, bytes) or not identity or len(identity) > 1024:
        raise HandshakeError("invalid party identity")


def _validate_public_bytes(public_value: bytes) -> None:
    if not isinstance(public_value, bytes) or len(public_value) != DH_BYTES:
        raise HandshakeError("DH public value is not 384 bytes")


def _validate_nonce(nonce: bytes) -> None:
    if not isinstance(nonce, bytes) or len(nonce) != NONCE_BYTES:
        raise HandshakeError("nonce is not 16 bytes")


def load_ffdhe3072_parameters(path: str | Path | None = None) -> dh.DHParameters:
    """Load the Lab Preparation group file and reject a substitute group."""
    group_path = Path(path) if path is not None else Path(__file__).with_name("ffdhe3072.pem")
    try:
        parameters = serialization.load_pem_parameters(group_path.read_bytes())
    except (OSError, ValueError) as exc:
        raise HandshakeError("could not load ffdhe3072 parameters") from exc
    if not isinstance(parameters, dh.DHParameters):
        raise HandshakeError("group file does not contain DH parameters")
    _require_ffdhe3072_parameters(parameters)
    return parameters


def _require_ffdhe3072_parameters(parameters: dh.DHParameters) -> None:
    numbers = parameters.parameter_numbers()
    if numbers.p.bit_length() != 3072 or numbers.g != 2:
        raise HandshakeError("group is not ffdhe3072")
    modulus = numbers.p.to_bytes(DH_BYTES, "big")
    if not hmac.compare_digest(hashlib.sha256(modulus).digest(), FFDHE3072_MODULUS_SHA256):
        raise HandshakeError("group is not ffdhe3072")


def generate_signing_key() -> rsa.RSAPrivateKey:
    """Generate a required 3072-bit long-term RSA signing key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def _require_rsa_3072(key: rsa.RSAPublicKey | rsa.RSAPrivateKey) -> None:
    if not isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)) or key.key_size != 3072:
        raise HandshakeError("long-term signing key must be a 3072-bit RSA key")


def _public_as_bytes(public_key: dh.DHPublicKey) -> bytes:
    value = public_key.public_numbers().y
    try:
        return value.to_bytes(DH_BYTES, "big")
    except OverflowError as exc:
        raise HandshakeError("DH public value does not fit ffdhe3072") from exc


@dataclass(frozen=True)
class Hello:
    """The fresh data a party contributes to one local session."""

    identity: bytes
    public_value: bytes
    nonce: bytes


@dataclass(frozen=True)
class HandshakeMessage:
    """Authenticated handshake contribution sent to the peer in-process."""

    role: bytes
    identity: bytes
    public_value: bytes
    nonce: bytes
    transcript: bytes
    signature: bytes


@dataclass(frozen=True)
class SessionKeys:
    master: bytes
    gateway_to_node_encryption: bytes
    gateway_to_node_mac: bytes
    node_to_gateway_encryption: bytes
    node_to_gateway_mac: bytes
    session_id: bytes
    transcript_hash: bytes


def derive_session_keys(shared_secret: bytes, transcript_hash: bytes) -> SessionKeys:
    """Implement the assignment's KDF exactly, including all labels."""
    if len(shared_secret) != DH_BYTES or len(transcript_hash) != 32:
        raise HandshakeError("invalid DH secret or transcript hash length")
    master = hashlib.sha256(KDF_LABEL + shared_secret + transcript_hash).digest()

    def derive(label: bytes) -> bytes:
        return hmac.new(master, label + transcript_hash, hashlib.sha256).digest()

    return SessionKeys(
        master=master,
        gateway_to_node_encryption=derive(b"gateway-to-node encryption"),
        gateway_to_node_mac=derive(b"gateway-to-node MAC"),
        node_to_gateway_encryption=derive(b"node-to-gateway encryption"),
        node_to_gateway_mac=derive(b"node-to-gateway MAC"),
        session_id=derive(b"session identifier")[:8],
        transcript_hash=transcript_hash,
    )


class Party:
    """One endpoint of a local, mutually authenticated handshake."""

    def __init__(
        self,
        role: bytes,
        identity: bytes,
        signing_key: rsa.RSAPrivateKey,
        expected_peer_identity: bytes,
        peer_signing_key: rsa.RSAPublicKey,
        parameters: dh.DHParameters,
    ) -> None:
        if role not in (GATEWAY_ROLE, NODE_ROLE):
            raise HandshakeError("unknown role")
        _validate_identity(identity)
        _validate_identity(expected_peer_identity)
        _require_rsa_3072(signing_key)
        _require_rsa_3072(peer_signing_key)
        _require_ffdhe3072_parameters(parameters)
        self.role = role
        self.identity = identity
        self.expected_peer_identity = expected_peer_identity
        self._signing_key = signing_key
        self._peer_signing_key = peer_signing_key
        self._parameters = parameters
        self._private: dh.DHPrivateKey | None = None
        self._accepted_transcript: bytes | None = None

    def begin(self) -> Hello:
        """Generate new DH private material and a new nonce for this session."""
        self._private = self._parameters.generate_private_key()
        self._accepted_transcript = None
        return Hello(self.identity, _public_as_bytes(self._private.public_key()), os.urandom(NONCE_BYTES))

    def sign(self, own_hello: Hello, peer_hello: Hello) -> HandshakeMessage:
        """Authenticate the canonical transcript for this session."""
        if own_hello.identity != self.identity:
            raise HandshakeError("cannot sign another party's hello")
        transcript = self._transcript_from_hellos(own_hello, peer_hello)
        transcript_hash = hashlib.sha256(transcript).digest()
        signature = self._signing_key.sign(
            self.role + transcript_hash,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        return HandshakeMessage(self.role, own_hello.identity, own_hello.public_value,
                                own_hello.nonce, transcript, signature)

    def verify_and_derive(self, own_hello: Hello, peer: HandshakeMessage) -> SessionKeys:
        """Reject malformed, reflected, or unauthenticated peer data; derive keys."""
        if self._accepted_transcript is not None:
            raise HandshakeError("handshake session already accepted")
        peer_role = NODE_ROLE if self.role == GATEWAY_ROLE else GATEWAY_ROLE
        if peer.role != peer_role:
            raise HandshakeError("reflected or unexpected handshake role")
        if peer.identity != self.expected_peer_identity:
            raise HandshakeError("unexpected peer identity")
        _validate_public_bytes(peer.public_value)
        _validate_nonce(peer.nonce)

        # Decode before hashing or verifying.  A bad declared length is never
        # allowed to reach SHA-256 as a supposedly valid transcript.
        decoded = decode_transcript(peer.transcript)
        peer_hello = Hello(peer.identity, peer.public_value, peer.nonce)
        expected = self._transcript_from_hellos(own_hello, peer_hello)
        if not hmac.compare_digest(peer.transcript, expected):
            raise HandshakeError("transcript does not match handshake values")
        expected_fields = (
            PROTOCOL_LABEL, GROUP_IDENTIFIER,
            own_hello.identity if self.role == GATEWAY_ROLE else peer.identity,
            peer.identity if self.role == GATEWAY_ROLE else own_hello.identity,
            own_hello.public_value if self.role == GATEWAY_ROLE else peer.public_value,
            peer.public_value if self.role == GATEWAY_ROLE else own_hello.public_value,
            own_hello.nonce if self.role == GATEWAY_ROLE else peer.nonce,
            peer.nonce if self.role == GATEWAY_ROLE else own_hello.nonce,
        )
        if decoded != expected_fields:
            raise HandshakeError("transcript fields do not match peer message")
        transcript_hash = hashlib.sha256(peer.transcript).digest()
        try:
            self._peer_signing_key.verify(
                peer.signature, peer.role + transcript_hash,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256(),
            )
        except InvalidSignature as exc:
            raise HandshakeError("invalid RSA-PSS signature") from exc
        if self._private is None:
            raise HandshakeError("begin must be called before deriving a session")
        try:
            peer_public = dh.DHPublicNumbers(
                int.from_bytes(peer.public_value, "big"),
                self._parameters.parameter_numbers(),
            ).public_key()
            shared = self._private.exchange(peer_public)
        except ValueError as exc:
            raise HandshakeError("invalid peer DH public value") from exc
        if len(shared) > DH_BYTES:
            raise HandshakeError("DH secret exceeds ffdhe3072 width")
        self._accepted_transcript = peer.transcript
        return derive_session_keys(shared.rjust(DH_BYTES, b"\0"), transcript_hash)

    def _transcript_from_hellos(self, own: Hello, peer: Hello) -> bytes:
        """Place values by protocol role, never by identity sort order."""
        if own.identity == peer.identity:
            raise HandshakeError("gateway and node identities must differ")
        if self.role == GATEWAY_ROLE:
            gateway, node = own, peer
        else:
            gateway, node = peer, own
        return encode_transcript(
            gateway.identity, node.identity,
            gateway.public_value, node.public_value,
            gateway.nonce, node.nonce,
        )


def perform_handshake(gateway: Party, node: Party) -> tuple[SessionKeys, SessionKeys]:
    """Run one complete in-process exchange and return both matching sessions."""
    if gateway.role != GATEWAY_ROLE or node.role != NODE_ROLE:
        raise HandshakeError("perform_handshake requires gateway then node")
    gateway_hello = gateway.begin()
    node_hello = node.begin()
    gateway_message = gateway.sign(gateway_hello, node_hello)
    node_message = node.sign(node_hello, gateway_hello)
    gateway_session = gateway.verify_and_derive(gateway_hello, node_message)
    node_session = node.verify_and_derive(node_hello, gateway_message)
    return gateway_session, node_session


def demo() -> None:
    """Small executable demonstration of a successful local handshake."""
    parameters = load_ffdhe3072_parameters()
    gateway_key, node_key = generate_signing_key(), generate_signing_key()
    gateway = Party(GATEWAY_ROLE, b"gateway", gateway_key, b"node", node_key.public_key(), parameters)
    node = Party(NODE_ROLE, b"node", node_key, b"gateway", gateway_key.public_key(), parameters)
    gateway_session, node_session = perform_handshake(gateway, node)
    assert gateway_session == node_session
    print("Handshake accepted; session ID:", gateway_session.session_id.hex())


if __name__ == "__main__":
    demo()
