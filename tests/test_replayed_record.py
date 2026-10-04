import pytest

from secure_record import RecordError


def test_replayed_record_is_rejected_by_exact_sequence(record_endpoints):
    sender, receiver, _, _ = record_endpoints
    record = sender.seal(0x22, b"process once")
    assert receiver.open_record(record) == (0x22, b"process once")

    with pytest.raises(RecordError, match=r"^unexpected record sequence$"):
        receiver.open_record(record)
    assert receiver.next_sequence == 1
