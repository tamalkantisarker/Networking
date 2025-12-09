# frontend/connection.py
import socket
import threading
from typing import Callable, Optional

from protocol import (
    send_packet,
    recv_packet,
    MSG_LOGIN_REQUEST,
    MSG_LOGIN_RESPONSE,
    MSG_PRIVATE_MESSAGE,
    MSG_GROUP_MESSAGE,
    MSG_SERVER_INFO,
    MSG_CREATE_GROUP,
    MSG_SIGNUP_EMAIL_REQUEST,
    MSG_SIGNUP_EMAIL_RESPONSE,
    MSG_VERIFY_EMAIL_REQUEST,
    MSG_VERIFY_EMAIL_RESPONSE,
    MSG_SET_CREDENTIALS_REQUEST,
    MSG_SET_CREDENTIALS_RESPONSE,
    MSG_LIST_USERS_REQUEST,
    MSG_LIST_USERS_RESPONSE,
    MSG_FRIEND_REQUEST,
    MSG_FRIEND_RESPONSE,
    MSG_FRIEND_ACCEPT,
    MSG_FRIEND_LIST,
    MSG_CREATE_GROUP_RESPONSE,
    MSG_GROUP_ADD_MEMBER,
    MSG_GROUP_ADD_MEMBER_RESPONSE,
    MSG_GROUP_REMOVE_MEMBER,
    MSG_GROUP_REMOVE_MEMBER_RESPONSE,
    MSG_REQUEST_ADD_MEMBER,
    MSG_REQUEST_ADD_MEMBER_RESPONSE,
    MSG_GET_MEMBER_REQUESTS,
    MSG_GET_MEMBER_REQUESTS_RESPONSE,
    MSG_APPROVE_MEMBER_REQUEST,
    MSG_APPROVE_MEMBER_RESPONSE,
    MSG_REJECT_MEMBER_REQUEST,
    MSG_REJECT_MEMBER_RESPONSE,
    PRIORITY_CONTROL,
    PRIORITY_CHAT,
 )
HOST = "127.0.0.1"
PORT = 5000

_sock: Optional[socket.socket] = None
_receiver_thread: Optional[threading.Thread] = None
_message_handler: Optional[Callable[[int, dict], None]] = None
_current_username: Optional[str] = None
_running = False


# ---------------- REGISTER CALLBACK ----------------

def register_message_handler(fn: Callable[[int, dict], None]) -> None:
    """Frontend UI registers a callback to receive messages."""
    global _message_handler
    _message_handler = fn


# ---------------- RECEIVER LOOP ----------------

def _receiver_loop():
    """Runs in background thread and receives all server messages."""
    global _running

    while _running and _sock:
        try:
            msg_type, prio, payload = recv_packet(_sock)

            if msg_type is None:
                print("[CLIENT] Server closed connection.")
                break

            if _message_handler:
                _message_handler(msg_type, payload)

        except Exception as e:
            print(f"[CLIENT] Receiver loop error: {e}")
            break

    print("[CLIENT] Receiver loop stopped.")
    _running = False


# ---------------- CONNECT ONCE ----------------

def connect():
    """Ensures socket connection (idempotent)."""
    global _sock
    if _sock is None:
        _sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _sock.connect((HOST, PORT))
        print(f"[CLIENT] Connected to server at {HOST}:{PORT}")


# ---------------- SIGNUP STEPS ----------------

def signup_start_email(email: str):
    connect()
    send_packet(_sock, MSG_SIGNUP_EMAIL_REQUEST, PRIORITY_CONTROL, {"email": email})

    msg_type, _, resp = recv_packet(_sock)
    if msg_type != MSG_SIGNUP_EMAIL_RESPONSE:
        return False, "Unexpected response"

    return resp.get("ok", False), resp.get("message") or resp.get("error")


def signup_verify_code(email: str, code: str):
    connect()
    send_packet(_sock, MSG_VERIFY_EMAIL_REQUEST, PRIORITY_CONTROL, {"email": email, "code": code})

    msg_type, _, resp = recv_packet(_sock)
    if msg_type != MSG_VERIFY_EMAIL_RESPONSE:
        return False, "Unexpected response"

    return resp.get("ok", False), resp.get("message") or resp.get("error")


def signup_set_credentials(email: str, username: str, password: str):
    connect()
    send_packet(
        _sock,
        MSG_SET_CREDENTIALS_REQUEST,
        PRIORITY_CONTROL,
        {"email": email, "username": username, "password": password},
    )

    msg_type, _, resp = recv_packet(_sock)
    if msg_type != MSG_SET_CREDENTIALS_RESPONSE:
        return False, "Unexpected response"

    return resp.get("ok", False), resp.get("message") or resp.get("error")


# ---------------- LOGIN ----------------

def login(username: str, password: str) -> bool:
    global _current_username, _running, _receiver_thread

    connect()

    send_packet(
        _sock,
        MSG_LOGIN_REQUEST,
        PRIORITY_CONTROL,
        {"username": username, "password": password},
    )

    msg_type, _, resp = recv_packet(_sock)
    if msg_type != MSG_LOGIN_RESPONSE:
        return False

    if not resp.get("ok", False):
        print("[CLIENT] Login failed:", resp.get("error"))
        return False

    # Success
    _current_username = username

    # Start receiver thread
    _running = True
    _receiver_thread = threading.Thread(target=_receiver_loop, daemon=True)
    _receiver_thread.start()

    # Request online users & groups
    request_server_info()

    return True


# ---------------- CHAT OPS ----------------

def send_private_message(to_user: str, text: str):
    if _sock:
        send_packet(
            _sock,
            MSG_PRIVATE_MESSAGE,
            PRIORITY_CHAT,
            {"from": _current_username, "to": to_user, "text": text},
        )


def send_group_message(group: str, text: str):
    if _sock:
        send_packet(
            _sock,
            MSG_GROUP_MESSAGE,
            PRIORITY_CHAT,
            {"from": _current_username, "group": group, "text": text},
        )


def create_group(group: str):
    if _sock:
        send_packet(_sock, MSG_CREATE_GROUP, PRIORITY_CONTROL, {"group": group})


def add_member_to_group(group: str, user: str):
    if _sock:
        send_packet(_sock, MSG_GROUP_ADD_MEMBER, PRIORITY_CONTROL, {"group": group, "user": user})


def remove_member_from_group(group: str, user: str):
    if _sock:
        send_packet(_sock, MSG_GROUP_REMOVE_MEMBER, PRIORITY_CONTROL, {"group": group, "user": user})


def request_add_member_to_group(group: str, user: str):
    """Non-admin member requests to add a friend to the group"""
    if _sock:
        send_packet(_sock, MSG_REQUEST_ADD_MEMBER, PRIORITY_CONTROL, {"group": group, "user": user})


def get_pending_member_requests(group: str):
    """Admin requests list of pending member requests for their group"""
    if _sock:
        send_packet(_sock, MSG_GET_MEMBER_REQUESTS, PRIORITY_CONTROL, {"group": group})


def approve_member_request(group: str, user: str):
    """Admin approves a member request"""
    if _sock:
        send_packet(_sock, MSG_APPROVE_MEMBER_REQUEST, PRIORITY_CONTROL, {"group": group, "user": user})


def reject_member_request(group: str, user: str):
    """Admin rejects a member request"""
    if _sock:
        send_packet(_sock, MSG_REJECT_MEMBER_REQUEST, PRIORITY_CONTROL, {"group": group, "user": user})


def request_server_info():
    if _sock:
        send_packet(_sock, MSG_SERVER_INFO, PRIORITY_CONTROL, {})


def request_all_users():
    if _sock:
        send_packet(_sock, MSG_LIST_USERS_REQUEST, PRIORITY_CONTROL, {})


def send_friend_request(to_username: str):
    if _sock:
        send_packet(_sock, MSG_FRIEND_REQUEST, PRIORITY_CONTROL, {"to": to_username})


def accept_friend_request(from_username: str):
    if _sock:
        send_packet(_sock, MSG_FRIEND_ACCEPT, PRIORITY_CONTROL, {"from": from_username})


# ---------------- DISCONNECT ----------------

def disconnect():
    global _running, _sock
    _running = False
    if _sock:
        try:
            _sock.close()
        except:
            pass
    _sock = None
    print("[CLIENT] Disconnected.")
