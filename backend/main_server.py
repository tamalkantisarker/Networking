# backend/main_server.py

import socket
import threading
import random
import string
import hashlib
import smtplib
import os

from email.mime.text import MIMEText
from dotenv import load_dotenv

# -----------------------------
# LOAD ENV VARIABLES
# -----------------------------
load_dotenv()

SENDER_EMAIL = os.getenv("EMAIL_USER")
APP_PASSWORD = os.getenv("EMAIL_PASS")

# Toggle: Set to False to use console-only verification (no email sending)
USE_EMAIL = True

# print("DEBUG_EMAIL =", os.getenv("EMAIL_USER"))
# print("DEBUG_PASS  =", os.getenv("EMAIL_PASS"))

if USE_EMAIL:
    if not SENDER_EMAIL or not APP_PASSWORD:
        print("⚠️  EMAIL_USER or EMAIL_PASS missing from .env - using console verification")
        USE_EMAIL = False
    else:
        print(f"[SERVER] Email system active. Sending from: {SENDER_EMAIL}")
else:
    print("[SERVER] Email disabled - verification codes will print to console")

# -----------------------------
# IMPORT OTHER MODULES
# -----------------------------
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
import database


HOST = "0.0.0.0"
PORT = 5000

online_clients = {}       # username → socket
pending_verifications = {}  # email → {code, verified}


# -----------------------------
# PASSWORD HASH
# -----------------------------
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


# -----------------------------
# VERIFICATION CODE GENERATOR
# -----------------------------
def generate_verification_code(length=6):
    return "".join(random.choices(string.digits, k=length))


# -----------------------------
# SEND VERIFICATION EMAIL
# -----------------------------
def send_verification_email(email: str, code: str):
    """Send verification email through Gmail SMTP or print to console."""

    print(f"[DEBUG] Attempting to send email to: {email}")
    print(f"[DEBUG] Code: {code}")
    print(f"[DEBUG] USE_EMAIL flag: {USE_EMAIL}")

    if not USE_EMAIL:
        # Console-only mode: print code to server terminal
        print(f"\n{'='*60}")
        print(f"📧 VERIFICATION CODE for {email}")
        print(f"   Code: {code}")
        print(f"{'='*60}\n")
        return

    # Email mode: send via SMTP
    msg = MIMEText(f"Your verification code is: {code}")
    msg["Subject"] = "ChatApp Verification Code"
    msg["From"] = SENDER_EMAIL
    msg["To"] = email

    try:
        print(f"[DEBUG] Connecting to Gmail SMTP...")
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            print(f"[DEBUG] Logging in as {SENDER_EMAIL}...")
            server.login(SENDER_EMAIL, APP_PASSWORD)
            print(f"[DEBUG] Sending email...")
            server.sendmail(SENDER_EMAIL, [email], msg.as_string())

        print(f"✅ [EMAIL] Successfully sent code to {email}")

    except Exception as e:
        print(f"❌ [EMAIL ERROR] {e}")
        print(f"\n⚠️  Email failed - printing code to console instead:")
        print(f"{'='*60}")
        print(f"📧 VERIFICATION CODE for {email}")
        print(f"   Code: {code}")
        print(f"{'='*60}\n")


# -----------------------------
# LOGIN
# -----------------------------
def handle_login(client_sock, payload):
    username = payload.get("username", "").strip()
    password = payload.get("password", "")

    if not username or not password:
        send_packet(client_sock, MSG_LOGIN_RESPONSE, PRIORITY_CONTROL,
                    {"ok": False, "error": "Username & password required"})
        return None

    user = database.get_user_by_username(username)
    if not user:
        send_packet(client_sock, MSG_LOGIN_RESPONSE, PRIORITY_CONTROL,
                    {"ok": False, "error": "Unknown user"})
        return None

    if hash_password(password) != user["password_hash"]:
        send_packet(client_sock, MSG_LOGIN_RESPONSE, PRIORITY_CONTROL,
                    {"ok": False, "error": "Invalid password"})
        return None

    online_clients[username] = client_sock

    # Optional: Auto-join default group (comment out to disable)
    # database.create_group_if_not_exists("CSE3111")
    # database.add_user_to_group(username, "CSE3111")

    # load all user's groups (including ones they were added to while offline)
    user_groups = database.get_user_groups(username)

    send_packet(client_sock, MSG_LOGIN_RESPONSE, PRIORITY_CONTROL,
                {"ok": True, "username": username, "groups": user_groups})

    send_friend_snapshot(username)
    
    # Send complete server info with group members
    handle_server_info(client_sock, username)

    print(f"[SERVER] {username} logged in with groups: {user_groups}")
    return username


# -----------------------------
# SIGNUP STEP 1 — EMAIL
# -----------------------------
def handle_signup_email(client_sock, payload):
    email = payload.get("email", "").strip().lower()

    if not email or "@" not in email:
        send_packet(client_sock, MSG_SIGNUP_EMAIL_RESPONSE, PRIORITY_CONTROL,
                    {"ok": False, "error": "Enter a valid email"})
        return

    if database.get_user_by_email(email):
        send_packet(client_sock, MSG_SIGNUP_EMAIL_RESPONSE, PRIORITY_CONTROL,
                    {"ok": False, "error": "Email already used"})
        return

    code = generate_verification_code()
    pending_verifications[email] = {"code": code, "verified": False}

    send_verification_email(email, code)

    send_packet(client_sock, MSG_SIGNUP_EMAIL_RESPONSE, PRIORITY_CONTROL,
                {"ok": True, "message": "Verification code sent"})


# -----------------------------
# SIGNUP STEP 2 — VERIFY
# -----------------------------
def handle_verify_email(client_sock, payload):
    email = payload.get("email", "").strip().lower()
    code = payload.get("code", "").strip()

    info = pending_verifications.get(email)
    if not info:
        send_packet(client_sock, MSG_VERIFY_EMAIL_RESPONSE, PRIORITY_CONTROL,
                    {"ok": False, "error": "No signup started"})
        return

    if info["code"] != code:
        send_packet(client_sock, MSG_VERIFY_EMAIL_RESPONSE, PRIORITY_CONTROL,
                    {"ok": False, "error": "Incorrect code"})
        return

    info["verified"] = True

    send_packet(client_sock, MSG_VERIFY_EMAIL_RESPONSE, PRIORITY_CONTROL,
                {"ok": True, "message": "Email verified"})


# -----------------------------
# SIGNUP STEP 3 — CREATE USER
# -----------------------------
def handle_set_credentials(client_sock, payload):
    email = payload.get("email", "").strip().lower()
    username = payload.get("username", "").strip()
    password = payload.get("password", "")

    info = pending_verifications.get(email)
    if not info or not info["verified"]:
        send_packet(client_sock, MSG_SET_CREDENTIALS_RESPONSE, PRIORITY_CONTROL,
                    {"ok": False, "error": "Email not verified"})
        return

    if database.get_user_by_username(username):
        send_packet(client_sock, MSG_SET_CREDENTIALS_RESPONSE, PRIORITY_CONTROL,
                    {"ok": False, "error": "Username exists"})
        return

    pwd_hash = hash_password(password)
    database.create_user(email, username, pwd_hash)

    pending_verifications.pop(email, None)

    # Optional: Auto-join default group on signup (comment out to disable)
    # database.create_group_if_not_exists("CSE3111")
    # database.add_user_to_group(username, "CSE3111")

    send_packet(client_sock, MSG_SET_CREDENTIALS_RESPONSE, PRIORITY_CONTROL,
                {"ok": True, "message": "Account created"})


# -----------------------------
# PRIVATE MESSAGE
# -----------------------------
def handle_private_message(sender, payload):
    to_user = payload.get("to")
    text = payload.get("text", "")

    database.save_private_message(sender, to_user, text)

    if to_user in online_clients:
        send_packet(online_clients[to_user], MSG_PRIVATE_MESSAGE, PRIORITY_CHAT,
                    {"from": sender, "text": text})


# -----------------------------
# GROUP MESSAGE
# -----------------------------
def handle_group_message(sender, payload):
    group = payload.get("group")
    text = payload.get("text", "")

    if not database.is_user_in_group(sender, group):
        return

    database.save_group_message(sender, group, text)

    for member in database.get_group_members(group):
        if member != sender and member in online_clients:
            send_packet(online_clients[member], MSG_GROUP_MESSAGE, PRIORITY_CHAT,
                        {"from": sender, "group": group, "text": text})


# -----------------------------
# CREATE/JOIN GROUP
# -----------------------------
def handle_create_group(sender, payload):
    name = payload.get("group", "").strip()
    if not name:
        return

    ok, msg = database.create_group_with_admin(name, sender)

    if sender in online_clients:
        send_packet(online_clients[sender], MSG_CREATE_GROUP_RESPONSE, PRIORITY_CONTROL,
                    {"ok": ok, "message": msg, "group": name})

    if ok:
        # refresh creator view
        handle_server_info(online_clients[sender], sender)

    print(f"[SERVER] {sender} create group '{name}' -> {msg}")


def handle_add_member(sender: str, payload: dict):
    group = payload.get("group", "").strip()
    target = payload.get("user", "").strip()
    ok, msg = database.add_user_to_group_if_admin(sender, target, group)

    if sender in online_clients:
        send_packet(online_clients[sender], MSG_GROUP_ADD_MEMBER_RESPONSE, PRIORITY_CONTROL,
                    {"ok": ok, "message": msg, "group": group, "user": target})

    if ok and target in online_clients:
        # refresh target's group list
        handle_server_info(online_clients[target], target)

    if ok:
        print(f"[SERVER] {sender} added {target} to {group}")


def handle_remove_member(sender: str, payload: dict):
    """Admin removes a user from a group"""
    group = payload.get("group", "").strip()
    target = payload.get("user", "").strip()
    ok, msg = database.remove_user_from_group(sender, target, group)

    if sender in online_clients:
        send_packet(online_clients[sender], MSG_GROUP_REMOVE_MEMBER_RESPONSE, PRIORITY_CONTROL,
                    {"ok": ok, "message": msg, "group": group, "user": target})

    if ok and target in online_clients:
        # refresh target's group list (they lose the group)
        handle_server_info(online_clients[target], target)

    if ok:
        # Also update admin's view
        handle_server_info(online_clients[sender], sender)
        print(f"[SERVER] {sender} removed {target} from {group}")


def handle_request_add_member(sender: str, payload: dict):
    """Non-admin requests to add a friend to the group"""
    group = payload.get("group", "").strip()
    target = payload.get("user", "").strip()
    ok, msg = database.request_add_member_to_group(sender, target, group)

    if sender in online_clients:
        send_packet(online_clients[sender], MSG_REQUEST_ADD_MEMBER_RESPONSE, PRIORITY_CONTROL,
                    {"ok": ok, "message": msg, "group": group, "user": target})

    if ok:
        # Notify admin about pending request
        admin_username = database.get_group_admin(group)
        if admin_username and admin_username in online_clients:
            send_packet(online_clients[admin_username], MSG_REQUEST_ADD_MEMBER_RESPONSE, PRIORITY_CONTROL,
                        {"ok": True, "message": f"{sender} requested to add {target} to {group}",
                         "group": group, "requester": sender, "user": target})
        print(f"[SERVER] {sender} requested to add {target} to {group}")


def handle_get_member_requests(sender: str, payload: dict):
    """Get pending member requests for a group (admin only)"""
    group = payload.get("group", "").strip()
    requests = database.get_pending_member_requests(sender, group)

    if sender in online_clients:
        send_packet(online_clients[sender], MSG_GET_MEMBER_REQUESTS_RESPONSE, PRIORITY_CONTROL,
                    {"group": group, "requests": requests})


def handle_approve_member_request(sender: str, payload: dict):
    """Admin approves a member request"""
    group = payload.get("group", "").strip()
    target = payload.get("user", "").strip()
    ok, msg = database.approve_member_request(sender, group, target)

    if sender in online_clients:
        send_packet(online_clients[sender], MSG_APPROVE_MEMBER_RESPONSE, PRIORITY_CONTROL,
                    {"ok": ok, "message": msg, "group": group, "user": target})

    if ok:
        # Notify newly added member to refresh their groups
        if target in online_clients:
            handle_server_info(online_clients[target], target)
        # Refresh admin's view too
        handle_server_info(online_clients[sender], sender)
        print(f"[SERVER] {sender} approved {target} to join {group}")


def handle_reject_member_request(sender: str, payload: dict):
    """Admin rejects a member request"""
    group = payload.get("group", "").strip()
    target = payload.get("user", "").strip()
    ok, msg = database.reject_member_request(sender, group, target)

    if sender in online_clients:
        send_packet(online_clients[sender], MSG_REJECT_MEMBER_RESPONSE, PRIORITY_CONTROL,
                    {"ok": ok, "message": msg, "group": group, "user": target})

    if ok:
        print(f"[SERVER] {sender} rejected {target}'s request to join {group}")


# -----------------------------
# SERVER INFO
# -----------------------------
def handle_server_info(client_sock, username: str):
    users = list(online_clients.keys())
    groups = database.get_user_groups(username)
    
    # Build group members dict + admin info
    group_members = {}
    group_admins = {}
    for group_name in groups:
        members = database.get_group_members(group_name)
        group_members[group_name] = members
        
        # Get admin username
        group_id = database.get_group_id(group_name)
        if group_id:
            conn = database.get_connection()
            cur = conn.cursor()
            cur.execute("SELECT u.username FROM groups g JOIN users u ON g.admin_id = u.id WHERE g.id = %s;", (group_id,))
            row = cur.fetchone()
            group_admins[group_name] = row[0] if row else None
            cur.close()
            conn.close()

    send_packet(client_sock, MSG_SERVER_INFO, PRIORITY_CONTROL,
                {"users": users, "groups": groups, "group_members": group_members, "group_admins": group_admins})


def handle_list_users(sock):
    all_users = database.list_all_usernames()
    send_packet(sock, MSG_LIST_USERS_RESPONSE, PRIORITY_CONTROL, {"users": all_users})


def send_friend_snapshot(username: str):
    friends = database.get_friends(username)
    pending = database.get_pending_requests(username)
    if username in online_clients:
        send_packet(online_clients[username], MSG_FRIEND_LIST, PRIORITY_CONTROL,
                    {"friends": friends, "pending": pending})


def handle_friend_request(username: str, payload: dict):
    target = payload.get("to", "").strip()
    ok, msg = database.create_friend_request(username, target)

    # Ack to sender
    if username in online_clients:
        send_packet(online_clients[username], MSG_FRIEND_RESPONSE, PRIORITY_CONTROL,
                    {"ok": ok, "message": msg, "to": target})

    if not ok:
        return

    # Notify target if online
    if target in online_clients:
        send_packet(online_clients[target], MSG_FRIEND_RESPONSE, PRIORITY_CONTROL,
                    {"incoming": True, "from": username})

    # Update snapshots
    send_friend_snapshot(username)
    send_friend_snapshot(target)


def handle_friend_accept(username: str, payload: dict):
    requester = payload.get("from", "").strip()
    ok, msg = database.accept_friend_request(username, requester)

    if username in online_clients:
        send_packet(online_clients[username], MSG_FRIEND_RESPONSE, PRIORITY_CONTROL,
                    {"ok": ok, "message": msg, "accepted": requester})

    if ok and requester in online_clients:
        send_packet(online_clients[requester], MSG_FRIEND_RESPONSE, PRIORITY_CONTROL,
                    {"accepted_by": username})

    if ok:
        send_friend_snapshot(username)
        send_friend_snapshot(requester)


# -----------------------------
# CLIENT THREAD HANDLER
# -----------------------------
def client_thread(sock, addr):
    print(f"[SERVER] Connection from {addr}")
    username = None

    try:
        while True:
            msg_type, prio, payload = recv_packet(sock)
            if msg_type is None:
                break

            if msg_type == MSG_LOGIN_REQUEST:
                username = handle_login(sock, payload)
                if username:
                    handle_server_info(sock, username)

            elif msg_type == MSG_SIGNUP_EMAIL_REQUEST:
                handle_signup_email(sock, payload)

            elif msg_type == MSG_VERIFY_EMAIL_REQUEST:
                handle_verify_email(sock, payload)

            elif msg_type == MSG_SET_CREDENTIALS_REQUEST:
                handle_set_credentials(sock, payload)

            elif msg_type == MSG_PRIVATE_MESSAGE and username:
                handle_private_message(username, payload)

            elif msg_type == MSG_GROUP_MESSAGE and username:
                handle_group_message(username, payload)

            elif msg_type == MSG_CREATE_GROUP and username:
                handle_create_group(username, payload)

            elif msg_type == MSG_GROUP_ADD_MEMBER and username:
                handle_add_member(username, payload)

            elif msg_type == MSG_GROUP_REMOVE_MEMBER and username:
                handle_remove_member(username, payload)

            elif msg_type == MSG_REQUEST_ADD_MEMBER and username:
                handle_request_add_member(username, payload)

            elif msg_type == MSG_GET_MEMBER_REQUESTS and username:
                handle_get_member_requests(username, payload)

            elif msg_type == MSG_APPROVE_MEMBER_REQUEST and username:
                handle_approve_member_request(username, payload)

            elif msg_type == MSG_REJECT_MEMBER_REQUEST and username:
                handle_reject_member_request(username, payload)

            elif msg_type == MSG_SERVER_INFO and username:
                handle_server_info(sock, username)

            elif msg_type == MSG_LIST_USERS_REQUEST and username:
                handle_list_users(sock)

            elif msg_type == MSG_FRIEND_REQUEST and username:
                handle_friend_request(username, payload)

            elif msg_type == MSG_FRIEND_ACCEPT and username:
                handle_friend_accept(username, payload)

    except Exception as e:
        print("[SERVER ERROR]", e)

    finally:
        if username in online_clients:
            del online_clients[username]
        sock.close()
        print(f"[SERVER] {addr} disconnected")


# -----------------------------
# MAIN SERVER
# -----------------------------
def main():
    database.init_db()
    # Optional: Create default group (comment out to disable)
    # database.create_group_if_not_exists("CSE3111")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()

    print(f"[SERVER] Running on {HOST}:{PORT}")

    while True:
        client, addr = server.accept()
        threading.Thread(target=client_thread, args=(client, addr), daemon=True).start()


if __name__ == "__main__":
    main()
