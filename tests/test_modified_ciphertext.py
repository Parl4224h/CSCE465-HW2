import pytest

from secure_record import RecordError


def test_modified_ciphertext_fails_authentication(record_endpoints):
    sender, receiver, _, _ = record_endpoints
    record = bytearray(sender.seal(0x20, b"confidential"))
    # Header is 15 bytes and IV is 16 bytes; this is the first ciphertext byte.
    record[31] ^= 0x01

    with pytest.raises(RecordError, match=r"^invalid record MAC$"):
        receiver.open_record(bytes(record))
    assert receiver.next_sequence == 0
