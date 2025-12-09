# frontend/protocol.py
import json
import struct

# Protocol version
VERSION = 1

# Message types
MSG_LOGIN_REQUEST   = 1
MSG_LOGIN_RESPONSE  = 2
MSG_PRIVATE_MESSAGE = 3
MSG_GROUP_MESSAGE   = 4
MSG_SERVER_INFO     = 5
MSG_CREATE_GROUP    = 6   # user wants to create/join a group

# Old simple signup – kept only for backward compatibility (not used anymore)
MSG_SIGNUP_REQUEST  = 7
MSG_SIGNUP_RESPONSE = 8

# NEW: Multi-step signup
MSG_SIGNUP_EMAIL_REQUEST     = 9   # client → server (start signup with email)
MSG_SIGNUP_EMAIL_RESPONSE    = 10  # server → client

MSG_VERIFY_EMAIL_REQUEST     = 11  # client → server
MSG_VERIFY_EMAIL_RESPONSE    = 12  # server → client

MSG_SET_CREDENTIALS_REQUEST  = 13  # client → server (email + username + pwd)
MSG_SET_CREDENTIALS_RESPONSE = 14  # server → client

# Friends / directory
MSG_LIST_USERS_REQUEST   = 15
MSG_LIST_USERS_RESPONSE  = 16
MSG_FRIEND_REQUEST       = 17
MSG_FRIEND_RESPONSE      = 18
MSG_FRIEND_ACCEPT        = 19
MSG_FRIEND_LIST          = 20

# Groups admin/membership
MSG_CREATE_GROUP_RESPONSE    = 21
MSG_GROUP_ADD_MEMBER         = 22
MSG_GROUP_ADD_MEMBER_RESPONSE = 23
MSG_GROUP_REMOVE_MEMBER      = 24
MSG_GROUP_REMOVE_MEMBER_RESPONSE = 25

# Group member requests (non-admin request, admin approve/reject)
MSG_REQUEST_ADD_MEMBER       = 26
MSG_REQUEST_ADD_MEMBER_RESPONSE = 27
MSG_GET_MEMBER_REQUESTS      = 28
MSG_GET_MEMBER_REQUESTS_RESPONSE = 29
MSG_APPROVE_MEMBER_REQUEST   = 30
MSG_APPROVE_MEMBER_RESPONSE  = 31
MSG_REJECT_MEMBER_REQUEST    = 32
MSG_REJECT_MEMBER_RESPONSE   = 33

# Priorities
PRIORITY_CONTROL = 1   # login, signup, server-info, group creation
PRIORITY_CHAT    = 2   # private & group chat messages
PRIORITY_FILE    = 3   # reserved for future file transfer

# Packet header structure:
# version (1 byte)
# msg_type (1 byte)
# priority (1 byte)
# reserved (1 byte)
# payload_length (4 bytes)
HEADER_FORMAT = "!BBBBI"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


def _recv_exact(sock, length: int) -> bytes | None:
    """Receive exactly N bytes or None if the socket closes."""
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def send_packet(sock, msg_type: int, priority: int, payload: dict) -> None:
    """Encode and send a structured TCP packet."""
    payload_bytes = json.dumps(payload).encode("utf-8")

    header = struct.pack(
        HEADER_FORMAT,
        VERSION,
        msg_type,
        priority,
        0,  # reserved byte
        len(payload_bytes),
    )

    sock.sendall(header + payload_bytes)


def recv_packet(sock):
    """
    Receive one complete packet.
    Returns:
        (msg_type, priority, payload_dict)
    or:
        (None, None, None) on disconnect/error.
    """
    header_bytes = _recv_exact(sock, HEADER_SIZE)
    if not header_bytes:
        return None, None, None

    version, msg_type, priority, reserved, length = struct.unpack(
        HEADER_FORMAT, header_bytes
    )

    if length > 0:
        payload_bytes = _recv_exact(sock, length)
        if not payload_bytes:
            return None, None, None
        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except Exception:
            payload = {}
    else:
        payload = {}

    return msg_type, priority, payload
