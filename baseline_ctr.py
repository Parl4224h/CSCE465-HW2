from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


ORIGINAL = b'{"action":"READ","path":"notes.txt"}'
MODIFIED = b'{"action":"LIST","path":"notes.txt"}'
ACTION_OFFSET = ORIGINAL.index(b"READ")


def aes_ctr(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """Encrypt/decrypt AES-CTR data; CTR uses the same operation both ways."""
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    transform = cipher.encryptor()
    return transform.update(data) + transform.finalize()


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("XOR inputs must be the same length")
    return bytes(a ^ b for a, b in zip(left, right))


def relay_change_action(ciphertext: bytes) -> tuple[bytes, bytes]:
    """Change known plaintext READ to LIST without the AES key.

    In CTR mode C = P XOR keystream.  XORing C with (P XOR P') therefore
    yields P' XOR keystream, which decrypts to P'.
    """
    delta = xor_bytes(b"READ", b"LIST")
    altered = bytearray(ciphertext)
    for index, value in enumerate(delta):
        altered[ACTION_OFFSET + index] ^= value
    return bytes(altered), delta


@dataclass
class Receiver:
    """Intentionally has no authentication or nonce/replay cache."""

    key: bytes
    processed: list[dict[str, str]] = field(default_factory=list)

    def receive(self, nonce: bytes, ciphertext: bytes) -> dict[str, str]:
        plaintext = aes_ctr(self.key, nonce, ciphertext)
        command = json.loads(plaintext)
        self.processed.append(command)
        return command


def main() -> None:
    assert len(ORIGINAL) == len(MODIFIED)

    key = os.urandom(32)  # Unknown to the relay.
    nonce = os.urandom(16)
    ciphertext = aes_ctr(key, nonce, ORIGINAL)

    modified_ciphertext, delta = relay_change_action(ciphertext)
    assert aes_ctr(key, nonce, modified_ciphertext) == MODIFIED

    print("Original plaintext: ", ORIGINAL.decode())
    print("Modified plaintext: ", MODIFIED.decode())
    print(f"Action byte offset: {ACTION_OFFSET}")
    print("Original action bytes:  ", b"READ".hex(" "))
    print("Modified action bytes:  ", b"LIST".hex(" "))
    print("XOR delta (READ ^ LIST):", delta.hex(" "))
    print("Relation: C'[action] = C[action] XOR delta")
    print("Relay knows no key; it only applies this delta to the ciphertext.\n")

    receiver = Receiver(key)
    print("Receiver accepts modified ciphertext:", receiver.receive(nonce, modified_ciphertext))

    # The relay now replays the exact same nonce/ciphertext packet twice.
    replayed_once = receiver.receive(nonce, ciphertext)
    replayed_twice = receiver.receive(nonce, ciphertext)
    print("First replay: ", replayed_once)
    print("Second replay:", replayed_twice)
    print("Receiver processed count:", len(receiver.processed))
    print("The two replays were both processed because this receiver has no replay defense.")
