def test_valid_handshake_and_bidirectional_messages(record_endpoints):
    gateway_sender, node_receiver, node_sender, gateway_receiver = record_endpoints

    # This payload deliberately spans several AES blocks.
    gateway_record = gateway_sender.seal(0x10, b"command: status; " * 4)
    assert node_receiver.open_record(gateway_record) == (0x10, b"command: status; " * 4)

    node_record = node_sender.seal(0x11, b"status: healthy")
    assert gateway_receiver.open_record(node_record) == (0x11, b"status: healthy")
