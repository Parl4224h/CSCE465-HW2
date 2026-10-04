import pytest

from secure_record import RecordError


def test_record_reflected_into_opposite_direction_fails(record_endpoints):
    gateway_sender, _, _, gateway_receiver = record_endpoints
    reflected = gateway_sender.seal(0x23, b"must not reflect")

    # The receiving direction has another MAC key, so reflection is rejected
    # before decryption instead of being treated as a valid record.
    with pytest.raises(RecordError, match=r"^invalid record MAC$"):
        gateway_receiver.open_record(reflected)
    assert gateway_receiver.next_sequence == 0
