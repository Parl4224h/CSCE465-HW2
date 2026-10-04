import pytest

from secure_record import RecordError


def test_modified_authenticated_header_fails_authentication(record_endpoints):
    sender, receiver, _, _ = record_endpoints
    record = bytearray(sender.seal(0x21, b"header is authenticated"))
    record[10] ^= 0x01  # message_type is part of the authenticated header

    with pytest.raises(RecordError, match=r"^invalid record MAC$"):
        receiver.open_record(bytes(record))
    assert receiver.next_sequence == 0
