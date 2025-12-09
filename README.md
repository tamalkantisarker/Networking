# Secure Chat Application

A full-featured Python-based chat application with user authentication, friend system, and group messaging capabilities using TCP sockets and PostgreSQL.

## Features

### 1. **User Authentication**
- Multi-step email verification signup process
- Secure login with password hashing (SHA-256)
- Email verification via Gmail SMTP or console
- Session management

### 2. **Friends System**
- Send/receive friend requests
- Accept/reject friend requests
- View friends list and pending requests
- User directory to discover new friends

### 3. **Group Messaging**
- Create groups with admin privileges
- Admin can add friends to groups
- Admin can remove members from groups
- View all group members
- See admin info for each group
- Groups persist across sessions

### 4. **Private Messaging**
- One-on-one direct messages
- Message history storage
- Unread message counters

### 5. **UI Features**
- Tabbed chat interface
- User/Friends/Directory/Pending tabs
- Groups tab with Create/Add member/Remove member buttons
- Close chat tabs with ✕ button
- Real-time status updates
- Member list with admin indicator

## Tech Stack

- **Backend**: Python 3 with TCP Sockets
- **Frontend**: Python Tkinter GUI
- **Database**: PostgreSQL
- **Authentication**: Email verification + Password hashing
- **Protocol**: Custom binary protocol with JSON payloads

## Project Structure

```
Networking Project1/
├── backend/
│   ├── main_server.py       # Server entry point
│   ├── database.py          # Database queries & helpers
│   ├── protocol.py          # Protocol constants & packet handling
│   └── .env                 # Email credentials (EMAIL_USER, EMAIL_PASS)
├── frontend/
│   ├── main_client.py       # Client entry point
│   ├── connection.py        # Server connection & messaging
│   ├── protocol.py          # Protocol constants (synced with backend)
│   └── ui/
│       ├── login_window.py  # Login & signup UI
│       └── chat_window.py   # Main chat UI
└── README.md
```

## Installation & Setup

### Prerequisites
- Python 3.8+
- PostgreSQL 12+
- pip (Python package manager)

### 1. Install Dependencies

```bash
pip install psycopg2-binary python-dotenv
```

### 2. Setup PostgreSQL Database

```bash
# Connect to PostgreSQL
psql -U postgres -d chat_app

# Run the SQL commands (see Database Schema section)
```

### 3. Configure Email (Optional)

Create a `.env` file in the backend folder:

```env
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password
```

**Gmail Setup:**
- Enable 2-Factor Authentication
- Generate an [App Password](https://myaccount.google.com/apppasswords)
- Use the app password in `.env`

If `.env` is not configured, verification codes will print to server console instead.

### 4. Start Backend

```bash
cd backend
python main_server.py
```

Expected output:
```
[DB] All tables ready.
[SERVER] Running on 0.0.0.0:5000
```

### 5. Start Frontend (in separate terminal)

```bash
cd frontend
python main_client.py
```

## Database Schema

### Tables

#### `users`
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

#### `groups`
```sql
CREATE TABLE groups (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    admin_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

#### `group_members`
```sql
CREATE TABLE group_members (
    id SERIAL PRIMARY KEY,
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    joined_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(group_id, user_id)
);
```

#### `private_messages`
```sql
CREATE TABLE private_messages (
    id SERIAL PRIMARY KEY,
    sender_id INTEGER NOT NULL REFERENCES users(id),
    receiver_id INTEGER NOT NULL REFERENCES users(id),
    message TEXT NOT NULL,
    sent_at TIMESTAMPTZ DEFAULT NOW()
);
```

#### `group_messages`
```sql
CREATE TABLE group_messages (
    id SERIAL PRIMARY KEY,
    group_id INTEGER NOT NULL REFERENCES groups(id),
    sender_id INTEGER NOT NULL REFERENCES users(id),
    message TEXT NOT NULL,
    sent_at TIMESTAMPTZ DEFAULT NOW()
);
```

#### `friend_requests`
```sql
CREATE TABLE friend_requests (
    id SERIAL PRIMARY KEY,
    requester_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    addressee_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'accepted')),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(requester_id, addressee_id)
);
```

## Protocol Documentation

### Message Types

| Type | Value | Direction | Purpose |
|------|-------|-----------|---------|
| MSG_LOGIN_REQUEST | 1 | Client → Server | Login attempt |
| MSG_LOGIN_RESPONSE | 2 | Server → Client | Login result |
| MSG_PRIVATE_MESSAGE | 3 | Client ↔ Server | Direct message |
| MSG_GROUP_MESSAGE | 4 | Client ↔ Server | Group message |
| MSG_SERVER_INFO | 5 | Client ↔ Server | User/group list |
| MSG_CREATE_GROUP | 6 | Client → Server | Create group |
| MSG_SIGNUP_EMAIL_REQUEST | 9 | Client → Server | Step 1: Email |
| MSG_SIGNUP_EMAIL_RESPONSE | 10 | Server → Client | Step 1: Response |
| MSG_VERIFY_EMAIL_REQUEST | 11 | Client → Server | Step 2: Verify code |
| MSG_VERIFY_EMAIL_RESPONSE | 12 | Server → Client | Step 2: Response |
| MSG_SET_CREDENTIALS_REQUEST | 13 | Client → Server | Step 3: Username/password |
| MSG_SET_CREDENTIALS_RESPONSE | 14 | Server → Client | Step 3: Response |
| MSG_LIST_USERS_REQUEST | 15 | Client → Server | Get all users |
| MSG_LIST_USERS_RESPONSE | 16 | Server → Client | All users list |
| MSG_FRIEND_REQUEST | 17 | Client → Server | Send friend request |
| MSG_FRIEND_RESPONSE | 18 | Server → Client | Friend action response |
| MSG_FRIEND_ACCEPT | 19 | Client → Server | Accept friend request |
| MSG_FRIEND_LIST | 20 | Server → Client | Friends & pending list |
| MSG_CREATE_GROUP_RESPONSE | 21 | Server → Client | Group creation result |
| MSG_GROUP_ADD_MEMBER | 22 | Client → Server | Add member to group |
| MSG_GROUP_ADD_MEMBER_RESPONSE | 23 | Server → Client | Add member result |
| MSG_GROUP_REMOVE_MEMBER | 24 | Client → Server | Remove member from group |
| MSG_GROUP_REMOVE_MEMBER_RESPONSE | 25 | Server → Client | Remove member result |

### Packet Structure

```
Header (13 bytes):
  - Version (1 byte): Protocol version
  - Type (1 byte): Message type
  - Priority (1 byte): 1=Control, 2=Chat, 3=File
  - Reserved (1 byte): Padding
  - Length (4 bytes): Payload length

Payload (variable):
  - JSON-encoded dictionary
```

## Usage Guide

### Signup
1. Click "Sign up"
2. Enter email → verify code sent to email/console
3. Enter verification code
4. Set username and password
5. Account created!

### Login
1. Enter username and password
2. Click "Login"
3. See your groups and friends

### Friends
1. **Directory tab**: Browse all users
2. **Add friend**: Select user → Click "Add friend"
3. **Pending tab**: View pending requests
4. **Accept**: Select request → Click "Accept"
5. **Friends tab**: View accepted friends

### Groups
1. **Create**: Groups tab → Click "Create" → Enter name
2. **Add member**: Select group → "Add member" → Choose friend
3. **Remove member**: Admin only → Select group → "Remove member"
4. **Chat**: Double-click group to open chat
5. **Members**: See all members in header (Admin shown)
6. **Close**: Click ✕ on tab

### Messaging
1. Open a user or group tab
2. Type message in input field
3. Press Enter or click "Send"
4. Messages appear in chat history

## API Examples

### Backend API

```python
# Add user to group (admin only)
ok, msg = database.add_user_to_group_if_admin(
    admin_username="alice",
    target_username="bob",
    group_name="TeamA"
)

# Remove user from group (admin only)
ok, msg = database.remove_user_from_group(
    admin_username="alice",
    target_username="bob",
    group_name="TeamA"
)

# Check if user is admin
is_admin = database.is_group_admin("alice", "TeamA")

# Get group members
members = database.get_group_members("TeamA")

# Get user's groups
groups = database.get_user_groups("alice")

# Get friends list
friends = database.get_friends("alice")

# Get pending friend requests
pending = database.get_pending_requests("alice")
```

## Testing Checklist

- [ ] User signup with email verification
- [ ] User login with correct credentials
- [ ] User login fails with wrong password
- [ ] Send/accept friend requests between users
- [ ] View directory and friends list
- [ ] Create group as admin
- [ ] Add friends to group
- [ ] Receive group membership notification
- [ ] Send/receive private messages
- [ ] Send/receive group messages
- [ ] Remove member from group (admin only)
- [ ] Non-admin cannot remove members
- [ ] Close chat tabs
- [ ] View group members and admin info
- [ ] Logout and re-login sees correct groups
- [ ] Offline member added to group, sees it on login

## Troubleshooting

### Email not sending
- Check `.env` file exists with EMAIL_USER and EMAIL_PASS
- Verify Gmail app password (not regular password)
- Check server console for error messages
- Codes will print to console if email fails

### Database connection error
```
psycopg2.OperationalError: could not connect to server
```
- Ensure PostgreSQL is running
- Check credentials in `database.py` (DB_USER, DB_PASSWORD)
- Verify database `chat_app` exists

### Cannot find module errors
```bash
pip install psycopg2-binary python-dotenv
```

### Port 5000 already in use
- Change PORT in `backend/main_server.py` and `frontend/connection.py`
- Or kill the process: `lsof -i :5000` (macOS/Linux)

## Future Enhancements

- [ ] Message read receipts
- [ ] Typing indicators
- [ ] File sharing
- [ ] Voice/video calls
- [ ] Profile pictures
- [ ] Message search
- [ ] Group descriptions
- [ ] Message reactions/emojis
- [ ] Admin transfer
- [ ] Leave group (non-admin)
- [ ] Mute notifications
- [ ] Ban/block users

## Performance Notes

- Messages are stored in database for persistence
- Friend lists cached on login, refreshed periodically
- Group members fetched on demand
- Supports multiple concurrent clients
- Tested with 3+ simultaneous users

## Security Notes

- Passwords hashed with SHA-256 (use bcrypt for production)
- Email verification prevents fake signups
- Admin-only operations validated on server
- SQL injection prevented with parameterized queries
- Consider TLS/SSL for production deployment

## License

This project is provided as-is for educational purposes.

## Support

For issues or questions, check:
1. Server console output for errors
2. Client console for connection issues
3. Database logs for SQL errors
4. README troubleshooting section

---

**Version**: 1.0  
**Last Updated**: December 9, 2025
