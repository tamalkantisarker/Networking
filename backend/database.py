# backend/database.py
"""
Database helper for complete chat system:
- users
- groups
- group members
- private messages
- group messages
"""

import psycopg2
from psycopg2 import errors
from psycopg2.extras import RealDictCursor

DB_NAME = "chat_app"
DB_USER = "postgres"
DB_PASSWORD = "12345"
DB_HOST = "localhost"
DB_PORT = 5432


def get_connection():
    return psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT,
    )


# ----------------------------------------
# INITIAL SETUP: CREATE ALL TABLES
# ----------------------------------------

def init_db():
    conn = get_connection()
    cur = conn.cursor()

    # USERS
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
    """)

    # GROUPS (with admin_id to track group creator/owner)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS groups (
            id SERIAL PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            admin_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
    """)

    # Index on admin_id for faster lookups
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_groups_admin_id ON groups(admin_id);
    """)

    # GROUP MEMBERS
    cur.execute("""
        CREATE TABLE IF NOT EXISTS group_members (
            id SERIAL PRIMARY KEY,
            group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            joined_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(group_id, user_id)
        );
    """)

    # PRIVATE MESSAGES
    cur.execute("""
        CREATE TABLE IF NOT EXISTS private_messages (
            id SERIAL PRIMARY KEY,
            sender_id INTEGER NOT NULL REFERENCES users(id),
            receiver_id INTEGER NOT NULL REFERENCES users(id),
            message TEXT NOT NULL,
            sent_at TIMESTAMPTZ DEFAULT NOW()
        );
    """)

    # GROUP MESSAGES
    cur.execute("""
        CREATE TABLE IF NOT EXISTS group_messages (
            id SERIAL PRIMARY KEY,
            group_id INTEGER NOT NULL REFERENCES groups(id),
            sender_id INTEGER NOT NULL REFERENCES users(id),
            message TEXT NOT NULL,
            sent_at TIMESTAMPTZ DEFAULT NOW()
        );
    """)

    # FRIEND REQUESTS / FRIENDSHIPS
    cur.execute("""
        CREATE TABLE IF NOT EXISTS friend_requests (
            id SERIAL PRIMARY KEY,
            requester_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            addressee_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            status TEXT NOT NULL CHECK (status IN ('pending', 'accepted')),
            created_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(requester_id, addressee_id)
        );
    """)

    # GROUP MEMBER REQUESTS (non-admin members request to add friends)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS group_member_requests (
            id SERIAL PRIMARY KEY,
            group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
            requester_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            target_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
            created_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(group_id, requester_id, target_user_id)
        );
    """)

    conn.commit()
    cur.close()
    conn.close()
    print("[DB] All tables ready.")


# ----------------------------------------
# USER FUNCTIONS
# ----------------------------------------

def get_user_by_username(username: str):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM users WHERE username = %s;", (username,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row


def get_user_by_email(email: str):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM users WHERE email = %s;", (email,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row


def create_user(email: str, username: str, password_hash: str) -> bool:
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO users (email, username, password_hash)
            VALUES (%s, %s, %s);
        """, (email, username, password_hash))
        conn.commit()
        return True
    except:
        conn.rollback()
        return False
    finally:
        cur.close()
        conn.close()


# ----------------------------------------
# GROUP FUNCTIONS
# ----------------------------------------

def create_group_if_not_exists(name: str, admin_username: str | None = None):
    admin_id = None
    if admin_username:
        admin = get_user_by_username(admin_username)
        admin_id = admin["id"] if admin else None

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO groups (name, admin_id)
        VALUES (%s, %s)
        ON CONFLICT (name) DO NOTHING;
    """, (name, admin_id))
    conn.commit()
    cur.close()
    conn.close()


def create_group_with_admin(name: str, admin_username: str):
    admin = get_user_by_username(admin_username)
    if not admin:
        return False, "Admin user not found"

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO groups (name, admin_id)
            VALUES (%s, %s);
        """, (name, admin["id"]))
        conn.commit()
    except errors.UniqueViolation:
        conn.rollback()
        cur.close(); conn.close(); return False, "Group name already exists"
    except Exception as e:
        conn.rollback()
        cur.close(); conn.close(); return False, str(e)

    cur.close()
    conn.close()

    add_user_to_group(admin_username, name)
    return True, "Group created"


def get_group_id(name: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM groups WHERE name = %s;", (name,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row[0] if row else None


def get_all_groups():
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM groups;")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def get_user_groups(username: str):
    user = get_user_by_username(username)
    if not user:
        return []

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT g.name
        FROM group_members gm
        JOIN groups g ON gm.group_id = g.id
        WHERE gm.user_id = %s
        ORDER BY g.name;
    """, (user["id"],))
    rows = [r[0] for r in cur.fetchall()]
    cur.close()
    conn.close()
    return rows


def is_user_in_group(username: str, group_name: str) -> bool:
    user = get_user_by_username(username)
    group_id = get_group_id(group_name)
    if not user or not group_id:
        return False

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT 1 FROM group_members WHERE user_id = %s AND group_id = %s;",
        (user["id"], group_id),
    )
    exists = cur.fetchone() is not None
    cur.close()
    conn.close()
    return exists


def is_group_admin(username: str, group_name: str) -> bool:
    user = get_user_by_username(username)
    group_id = get_group_id(group_name)
    if not user or not group_id:
        return False

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT 1 FROM groups WHERE id = %s AND admin_id = %s;",
        (group_id, user["id"]),
    )
    exists = cur.fetchone() is not None
    cur.close()
    conn.close()
    return exists


def get_group_admin(group_name: str):
    """Get the username of the group admin"""
    group_id = get_group_id(group_name)
    if not group_id:
        return None
    
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT u.username FROM groups g JOIN users u ON g.admin_id = u.id WHERE g.id = %s;",
        (group_id,)
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row[0] if row else None


# ----------------------------------------
# GROUP MEMBERS
# ----------------------------------------

def add_user_to_group(username: str, group_name: str):
    user = get_user_by_username(username)
    group_id = get_group_id(group_name)

    if not user or not group_id:
        return False

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO group_members (group_id, user_id)
        VALUES (%s, %s)
        ON CONFLICT DO NOTHING;
    """, (group_id, user["id"]))
    conn.commit()
    cur.close()
    conn.close()
    return True


def get_group_members(group_name: str):
    group_id = get_group_id(group_name)
    if not group_id:
        return []

    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT u.username FROM group_members gm
        JOIN users u ON gm.user_id = u.id
        WHERE gm.group_id = %s;
    """, (group_id,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [r["username"] for r in rows]


# ----------------------------------------
# PRIVATE MESSAGES
# ----------------------------------------

def save_private_message(sender: str, receiver: str, message: str):
    s = get_user_by_username(sender)
    r = get_user_by_username(receiver)
    if not s or not r:
        return

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO private_messages (sender_id, receiver_id, message)
        VALUES (%s, %s, %s);
    """, (s["id"], r["id"], message))
    conn.commit()
    cur.close()
    conn.close()


# ----------------------------------------
# GROUP MESSAGES
# ----------------------------------------

def save_group_message(sender: str, group_name: str, message: str):
    s = get_user_by_username(sender)
    g = get_group_id(group_name)
    if not s or not g:
        return

    if not is_user_in_group(sender, group_name):
        return

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO group_messages (group_id, sender_id, message)
        VALUES (%s, %s, %s);
    """, (g, s["id"], message))
    conn.commit()
    cur.close()
    conn.close()


# ----------------------------------------
# FRIENDS / REQUESTS
# ----------------------------------------

def list_all_usernames():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users ORDER BY username;")
    rows = [r[0] for r in cur.fetchall()]
    cur.close()
    conn.close()
    return rows


def create_friend_request(requester: str, target: str):
    if requester == target:
        return False, "Cannot friend yourself"

    req_user = get_user_by_username(requester)
    tgt_user = get_user_by_username(target)
    if not req_user or not tgt_user:
        return False, "User not found"

    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # Check existing relation in either direction
    cur.execute(
        """
        SELECT status, requester_id, addressee_id
        FROM friend_requests
        WHERE (requester_id = %s AND addressee_id = %s)
           OR (requester_id = %s AND addressee_id = %s)
        """,
        (req_user["id"], tgt_user["id"], tgt_user["id"], req_user["id"]),
    )
    row = cur.fetchone()
    if row:
        if row["status"] == "accepted":
            cur.close(); conn.close(); return False, "Already friends"
        else:
            cur.close(); conn.close(); return False, "Request already pending"

    cur.execute(
        """
        INSERT INTO friend_requests (requester_id, addressee_id, status)
        VALUES (%s, %s, 'pending');
        """,
        (req_user["id"], tgt_user["id"]),
    )
    conn.commit()
    cur.close()
    conn.close()
    return True, "Request sent"


def accept_friend_request(addressee: str, requester: str):
    add_user = get_user_by_username(addressee)
    req_user = get_user_by_username(requester)
    if not add_user or not req_user:
        return False, "User not found"

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE friend_requests
        SET status = 'accepted'
        WHERE requester_id = %s AND addressee_id = %s AND status = 'pending'
        """,
        (req_user["id"], add_user["id"]),
    )
    updated = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()

    if updated:
        return True, "Accepted"
    return False, "No pending request"


def get_pending_requests(username: str):
    user = get_user_by_username(username)
    if not user:
        return []

    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(
        """
        SELECT u.username AS requester
        FROM friend_requests fr
        JOIN users u ON fr.requester_id = u.id
        WHERE fr.addressee_id = %s AND fr.status = 'pending'
        ORDER BY fr.created_at DESC;
        """,
        (user["id"],),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [r["requester"] for r in rows]


def get_friends(username: str):
    user = get_user_by_username(username)
    if not user:
        return []

    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(
        """
        SELECT CASE
                 WHEN fr.requester_id = %s THEN u2.username
                 ELSE u1.username
               END AS friend
        FROM friend_requests fr
        JOIN users u1 ON fr.requester_id = u1.id
        JOIN users u2 ON fr.addressee_id = u2.id
        WHERE fr.status = 'accepted' AND (fr.requester_id = %s OR fr.addressee_id = %s)
        ORDER BY fr.created_at DESC;
        """,
        (user["id"], user["id"], user["id"]),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [r["friend"] for r in rows]


def is_friend(user_a: str, user_b: str) -> bool:
    a = get_user_by_username(user_a)
    b = get_user_by_username(user_b)
    if not a or not b:
        return False

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT 1
        FROM friend_requests
        WHERE status = 'accepted'
          AND ((requester_id = %s AND addressee_id = %s)
               OR (requester_id = %s AND addressee_id = %s))
        """,
        (a["id"], b["id"], b["id"], a["id"]),
    )
    exists = cur.fetchone() is not None
    cur.close()
    conn.close()
    return exists


def add_user_to_group_if_admin(admin_username: str, target_username: str, group_name: str):
    if not is_group_admin(admin_username, group_name):
        return False, "Only group admin can add members"

    if not is_friend(admin_username, target_username):
        return False, "Can only add friends"

    added = add_user_to_group(target_username, group_name)
    if not added:
        return False, "User already in group or group missing"

    return True, "User added to group"


def remove_user_from_group(admin_username: str, target_username: str, group_name: str):
    """Admin removes a user from the group"""
    if not is_group_admin(admin_username, group_name):
        return False, "Only group admin can remove members"
    
    if admin_username == target_username:
        return False, "Admin cannot remove themselves"

    user = get_user_by_username(target_username)
    group_id = get_group_id(group_name)
    if not user or not group_id:
        return False, "User or group not found"

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM group_members WHERE user_id = %s AND group_id = %s;",
        (user["id"], group_id),
    )
    deleted = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()

    if deleted:
        return True, "User removed from group"
    return False, "User not in group"


# ----------------------------------------
# GROUP MEMBER REQUESTS (for non-admin to request adding friends)
# ----------------------------------------

def request_add_member_to_group(requester_username: str, target_username: str, group_name: str):
    """Non-admin member requests to add a friend to the group"""
    requester = get_user_by_username(requester_username)
    target = get_user_by_username(target_username)
    group_id = get_group_id(group_name)
    
    if not requester or not target or not group_id:
        return False, "User or group not found"
    
    # Check if requester is in the group
    if not is_user_in_group(requester_username, group_name):
        return False, "You are not in this group"
    
    # Check if target is already in the group
    if is_user_in_group(target_username, group_name):
        return False, "User is already in this group"
    
    # Check if they are friends
    if not is_friend(requester_username, target_username):
        return False, "You are not friends with this user"
    
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO group_member_requests 
            (group_id, requester_id, target_user_id, status)
            VALUES (%s, %s, %s, 'pending')
        """, (group_id, requester["id"], target["id"]))
        conn.commit()
        return True, "Request sent to admin for approval"
    except Exception as e:
        conn.rollback()
        if "duplicate" in str(e).lower():
            return False, "Request already pending for this user"
        return False, str(e)
    finally:
        cur.close()
        conn.close()


def get_pending_member_requests(admin_username: str, group_name: str):
    """Admin gets list of pending member requests for their group"""
    if not is_group_admin(admin_username, group_name):
        return []
    
    group_id = get_group_id(group_name)
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT gmr.id, gmr.group_id, gmr.requester_id, gmr.target_user_id, gmr.status,
               u1.username as requester, u2.username as target
        FROM group_member_requests gmr
        JOIN users u1 ON gmr.requester_id = u1.id
        JOIN users u2 ON gmr.target_user_id = u2.id
        WHERE gmr.group_id = %s AND gmr.status = 'pending'
        ORDER BY gmr.created_at ASC
    """, (group_id,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def approve_member_request(admin_username: str, group_name: str, target_username: str):
    """Admin approves a pending member request"""
    if not is_group_admin(admin_username, group_name):
        return False, "Only group admin can approve requests"
    
    target = get_user_by_username(target_username)
    group_id = get_group_id(group_name)
    
    if not target or not group_id:
        return False, "User or group not found"
    
    # Check if target is already in group
    if is_user_in_group(target_username, group_name):
        return False, "User is already in this group"
    
    conn = get_connection()
    cur = conn.cursor()
    try:
        # Add user to group
        cur.execute("""
            INSERT INTO group_members (group_id, user_id)
            VALUES (%s, %s)
        """, (group_id, target["id"]))
        
        # Mark request as approved
        cur.execute("""
            UPDATE group_member_requests
            SET status = 'approved'
            WHERE group_id = %s AND target_user_id = %s AND status = 'pending'
        """, (group_id, target["id"]))
        
        conn.commit()
        return True, f"{target_username} added to group"
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        cur.close()
        conn.close()


def reject_member_request(admin_username: str, group_name: str, target_username: str):
    """Admin rejects a pending member request"""
    if not is_group_admin(admin_username, group_name):
        return False, "Only group admin can reject requests"
    
    target = get_user_by_username(target_username)
    group_id = get_group_id(group_name)
    
    if not target or not group_id:
        return False, "User or group not found"
    
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE group_member_requests
            SET status = 'rejected'
            WHERE group_id = %s AND target_user_id = %s AND status = 'pending'
        """, (group_id, target["id"]))
        
        conn.commit()
        if cur.rowcount > 0:
            return True, "Request rejected"
        return False, "No pending request found"
    finally:
        cur.close()
        conn.close()

