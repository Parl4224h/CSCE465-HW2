from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


VERSION: Final = 1
GATEWAY_TO_NODE: Final = 0
NODE_TO_GATEWAY: Final = 1
HEADER_LENGTH: Final = 15
IV_LENGTH: Final = 16
TAG_LENGTH: Final = 32
MAX_SEQUENCE: Final = (1 << 64) - 1
MAX_CIPHERTEXT_LENGTH: Final = (1 << 32) - 1


class RecordError(ValueError):
    """Raised when a record is malformed, unauthenticated, or unexpected."""


def _require_bytes(value: object, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise RecordError(f"{name} must be bytes")
    return value


def _require_octet(value: object, name: str) -> int:
    # bool is an int subclass, but accepting it here would make a surprising
    # wire value in a security boundary.
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFF:
        raise RecordError(f"{name} must be a one-byte integer")
    return value


def _require_sequence(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_SEQUENCE:
        raise RecordError("sequence must be an unsigned 64-bit integer")
    return value


def _keys_for_direction(session_keys: object, direction: int) -> tuple[bytes, bytes, bytes]:
    """Return (encryption key, MAC key, session ID) for one protocol direction."""
    try:
        session_id = session_keys.session_id  # type: ignore[attr-defined]
        if direction == GATEWAY_TO_NODE:
            encryption_key = session_keys.gateway_to_node_encryption  # type: ignore[attr-defined]
            mac_key = session_keys.gateway_to_node_mac  # type: ignore[attr-defined]
        elif direction == NODE_TO_GATEWAY:
            encryption_key = session_keys.node_to_gateway_encryption  # type: ignore[attr-defined]
            mac_key = session_keys.node_to_gateway_mac  # type: ignore[attr-defined]
        else:
            raise RecordError("unknown direction")
    except AttributeError as exc:
        raise RecordError("session_keys is missing record-layer keys") from exc

    session_id = _require_bytes(session_id, "session ID")
    encryption_key = _require_bytes(encryption_key, "encryption key")
    mac_key = _require_bytes(mac_key, "MAC key")
    if len(session_id) != 8:
        raise RecordError("session ID must be 8 bytes")
    if len(encryption_key) != 32:
        raise RecordError("AES-256 encryption key must be 32 bytes")
    if len(mac_key) != 32:
        raise RecordError("HMAC-SHA-256 key must be 32 bytes")
    return encryption_key, mac_key, session_id


def _ctr_crypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    cryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return cryptor.update(data) + cryptor.finalize()


def _tag(mac_key: bytes, authenticated: bytes) -> bytes:
    signer = hmac.HMAC(mac_key, hashes.SHA256())
    signer.update(authenticated)
    return signer.finalize()


def seal(
    session_keys: object,
    direction: int,
    sequence: int,
    message_type: int,
    plaintext: bytes,
) -> bytes:
    """Seal one record using the key associated with ``direction``.

    A caller must use each ``(direction, sequence)`` exactly once.  The
    ``RecordSender`` wrapper enforces that rule for a single sender instance.
    """
    direction = _require_octet(direction, "direction")
    sequence = _require_sequence(sequence)
    message_type = _require_octet(message_type, "message type")
    plaintext = _require_bytes(plaintext, "plaintext")
    if len(plaintext) > MAX_CIPHERTEXT_LENGTH:
        raise RecordError("plaintext is too long")

    encryption_key, mac_key, session_id = _keys_for_direction(session_keys, direction)
    iv = session_id + sequence.to_bytes(8, "big")
    header = (
        bytes((VERSION, direction))
        + sequence.to_bytes(8, "big")
        + bytes((message_type,))
        + len(plaintext).to_bytes(4, "big")
    )
    ciphertext = _ctr_crypt(encryption_key, iv, plaintext)
    return header + iv + ciphertext + _tag(mac_key, header + iv + ciphertext)


def open_record(
    session_keys: object,
    expected_direction: int,
    expected_sequence: int,
    record: bytes,
) -> tuple[int, bytes]:
    """Authenticate then decrypt the exact next record.

    The result is ``(message_type, plaintext)``.  No plaintext is produced on
    malformed input, an invalid MAC, a wrong direction, or a replay/out of
    order sequence number.
    """
    expected_direction = _require_octet(expected_direction, "expected direction")
    expected_sequence = _require_sequence(expected_sequence)
    record = _require_bytes(record, "record")
    encryption_key, mac_key, session_id = _keys_for_direction(session_keys, expected_direction)

    if len(record) < HEADER_LENGTH + IV_LENGTH + TAG_LENGTH:
        raise RecordError("record is too short")
    header = record[:HEADER_LENGTH]
    version, direction = header[0], header[1]
    sequence = int.from_bytes(header[2:10], "big")
    message_type = header[10]
    ciphertext_length = int.from_bytes(header[11:15], "big")
    total_length = HEADER_LENGTH + IV_LENGTH + ciphertext_length + TAG_LENGTH
    if len(record) != total_length:
        raise RecordError("record length does not match header")

    iv = record[HEADER_LENGTH : HEADER_LENGTH + IV_LENGTH]
    ciphertext = record[HEADER_LENGTH + IV_LENGTH : -TAG_LENGTH]
    supplied_tag = record[-TAG_LENGTH:]

    # Always use the receiver's expected-direction MAC key.  The direction in
    # an attacker-controlled header never chooses a key.
    verifier = hmac.HMAC(mac_key, hashes.SHA256())
    verifier.update(header + iv + ciphertext)
    try:
        verifier.verify(supplied_tag)  # cryptography performs constant-time verification.
    except InvalidSignature as exc:
        raise RecordError("invalid record MAC") from exc

    # These checks occur after authentication and before decryption.  They
    # bind every header field and prevent reflection/replay/out-of-order input.
    if version != VERSION:
        raise RecordError("unsupported record version")
    if direction != expected_direction:
        raise RecordError("record has the wrong direction")
    if sequence != expected_sequence:
        raise RecordError("unexpected record sequence")
    if iv != session_id + sequence.to_bytes(8, "big"):
        raise RecordError("record IV does not match its sequence")

    return message_type, _ctr_crypt(encryption_key, iv, ciphertext)


@dataclass
class RecordSender:
    """Stateful sender that starts at sequence zero and never reuses one."""

    session_keys: object
    direction: int
    next_sequence: int = field(default=0, init=False)

    def seal(self, message_type: int, plaintext: bytes) -> bytes:
        if self.next_sequence > MAX_SEQUENCE:
            raise RecordError("sender sequence space exhausted")
        record = seal(self.session_keys, self.direction, self.next_sequence, message_type, plaintext)
        self.next_sequence += 1
        return record


@dataclass
class RecordReceiver:
    """Stateful receiver that accepts only the next sequence in one direction."""

    session_keys: object
    expected_direction: int
    next_sequence: int = field(default=0, init=False)

    def open_record(self, record: bytes) -> tuple[int, bytes]:
        if self.next_sequence > MAX_SEQUENCE:
            raise RecordError("receiver sequence space exhausted")
        result = open_record(self.session_keys, self.expected_direction, self.next_sequence, record)
        self.next_sequence += 1
        return result
