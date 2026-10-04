import pytest

from handshake import HandshakeError


def test_reflected_handshake_message_is_rejected(parties):
    gateway, node = parties
    gateway_hello = gateway.begin()
    node_hello = node.begin()
    gateway_message = gateway.sign(gateway_hello, node_hello)

    # Supplying the gateway's own signed contribution as its peer's message
    # must fail before any session keys can be derived.
    with pytest.raises(HandshakeError, match=r"^reflected or unexpected handshake role$"):
        gateway.verify_and_derive(gateway_hello, gateway_message)
