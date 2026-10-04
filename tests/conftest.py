from __future__ import annotations

import pytest

from handshake import (
    Party,
    generate_signing_key,
    load_ffdhe3072_parameters,
    perform_handshake,
)
from secure_record import (
    GATEWAY_TO_NODE,
    NODE_TO_GATEWAY,
    RecordReceiver,
    RecordSender,
)


@pytest.fixture(scope="module")
def identity_material():
    """Generate long-term keys once; each test creates a fresh session."""
    return (
        load_ffdhe3072_parameters(),
        generate_signing_key(),
        generate_signing_key(),
    )


@pytest.fixture
def parties(identity_material):
    parameters, gateway_key, node_key = identity_material
    gateway = Party(
        b"gateway", b"gateway", gateway_key, b"node", node_key.public_key(), parameters
    )
    node = Party(
        b"node", b"node", node_key, b"gateway", gateway_key.public_key(), parameters
    )
    return gateway, node


@pytest.fixture
def record_endpoints(parties):
    gateway, node = parties
    gateway_keys, node_keys = perform_handshake(gateway, node)
    return (
        RecordSender(gateway_keys, GATEWAY_TO_NODE),
        RecordReceiver(node_keys, GATEWAY_TO_NODE),
        RecordSender(node_keys, NODE_TO_GATEWAY),
        RecordReceiver(gateway_keys, NODE_TO_GATEWAY),
    )
