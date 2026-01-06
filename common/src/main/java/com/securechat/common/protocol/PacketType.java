package com.securechat.common.protocol;

public enum PacketType {
    // Auth & Control
    LOGIN,

    // Chat
    DM,
    DM_ACK,
    GROUP_CREATE,
    GROUP_JOIN,
    GROUP_ACK,

    GROUP_LEAVE,
    GROUP_LIST_UPDATE,
    GROUP_MESSAGE,

    // File Transfer
    FILE_INIT,
    FILE_REQ, // Request to Send
    FILE_RESP, // Permission Granted
    FILE_CHUNK,
    CHUNK_ACK,
    FILE_COMPLETE,
    FILE_ABORT, // Added for UI sync on timeout

    // Resume Support
    RESUME_QUERY,
    RESUME_INFO,
    STATUS_UPDATE,
    USER_LIST,
    AUTH_RESPONSE,
    HEARTBEAT,

    // Social & Security
    USER_LIST_UPDATE,
    USER_LIST_QUERY,
    GROUP_LIST_QUERY,
    KEY_EXCHANGE
}
