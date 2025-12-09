# frontend/ui/chat_window.py
import tkinter as tk
from tkinter import ttk
from datetime import datetime

import connection
from protocol import (
    MSG_PRIVATE_MESSAGE,
    MSG_GROUP_MESSAGE,
    MSG_SERVER_INFO,
    MSG_LIST_USERS_RESPONSE,
    MSG_FRIEND_LIST,
    MSG_FRIEND_RESPONSE,
    MSG_CREATE_GROUP_RESPONSE,
    MSG_GROUP_ADD_MEMBER_RESPONSE,
    MSG_GROUP_REMOVE_MEMBER_RESPONSE,
    MSG_REQUEST_ADD_MEMBER_RESPONSE,
    MSG_GET_MEMBER_REQUESTS_RESPONSE,
    MSG_APPROVE_MEMBER_RESPONSE,
    MSG_REJECT_MEMBER_RESPONSE,
)


class MainChatWindow(tk.Toplevel):
    def __init__(self, parent, username: str):
        super().__init__(parent)
        self.title("Secure Chat")
        self.geometry("1200x700")

        self.parent = parent
        self.username = username

        self.users = []              # online users list
        self.group_members = {}      # {"group_name": ["user1", "user2"], ...}
        self.groups = []             # group names only
        self.group_admins = {}       # {"group_name": "admin_username", ...}

        # directory / friends
        self.all_users = []
        self.friends = []
        self.pending = []

        self.displayed_users = []
        self.displayed_groups = []

        self.unread_counts = {}

        # register async message handler
        connection.register_message_handler(self.on_message_received)

        self._build_ui()

    # ---------------- UI BUILD ----------------

    def _build_ui(self):
        self.columnconfigure(0, weight=0, minsize=300)  # Sidebar with larger minimum width for all tabs
        self.columnconfigure(1, weight=1)  # Chat area takes remaining space
        self.rowconfigure(1, weight=1)

        # Top bar
        top_frame = ttk.Frame(self, padding=5)
        top_frame.grid(row=0, column=0, columnspan=2, sticky="nsew")

        ttk.Label(top_frame, text="Secure Chat", font=("Arial", 14, "bold")).pack(side="left")
        ttk.Label(top_frame, text=f"   Logged in as: {self.username}").pack(side="left")

        ttk.Button(top_frame, text="Logout", command=self.on_logout).pack(side="right")
        ttk.Button(top_frame, text="Back", command=self.on_logout).pack(side="right", padx=5)

        # Sidebar
        sidebar = ttk.Frame(self, padding=5)
        sidebar.grid(row=1, column=0, sticky="nsew")
        sidebar.rowconfigure(0, weight=1)
        sidebar.columnconfigure(0, weight=1)  # Make notebook take full sidebar width

        self.notebook_lists = ttk.Notebook(sidebar)
        self.notebook_lists.grid(row=0, column=0, sticky="nsew")

        # Users tab
        users_frame = ttk.Frame(self.notebook_lists)
        self.users_listbox = tk.Listbox(users_frame, height=15)
        self.users_listbox.pack(fill="both", expand=True)
        self.users_listbox.bind("<Double-Button-1>", self._open_user_tab)
        self.notebook_lists.add(users_frame, text="Users")

        # Directory (all users)
        directory_frame = ttk.Frame(self.notebook_lists)
        directory_frame.rowconfigure(0, weight=1)
        directory_frame.columnconfigure(0, weight=1)
        self.all_users_listbox = tk.Listbox(directory_frame, height=15)
        self.all_users_listbox.grid(row=0, column=0, sticky="nsew")
        ttk.Button(directory_frame, text="Add friend", command=self._send_friend_request).grid(row=1, column=0, sticky="ew", pady=4)
        self.notebook_lists.add(directory_frame, text="Directory")

        # Friends tab
        friends_frame = ttk.Frame(self.notebook_lists)
        friends_frame.rowconfigure(0, weight=1)
        friends_frame.columnconfigure(0, weight=1)
        self.friends_listbox = tk.Listbox(friends_frame, height=15)
        self.friends_listbox.grid(row=0, column=0, sticky="nsew")
        self.notebook_lists.add(friends_frame, text="Friends")

        # Pending tab
        pending_frame = ttk.Frame(self.notebook_lists)
        pending_frame.rowconfigure(0, weight=1)
        pending_frame.columnconfigure(0, weight=1)
        self.pending_listbox = tk.Listbox(pending_frame, height=15)
        self.pending_listbox.grid(row=0, column=0, sticky="nsew")
        ttk.Button(pending_frame, text="Accept", command=self._accept_friend_request).grid(row=1, column=0, sticky="ew", pady=4)
        self.notebook_lists.add(pending_frame, text="Pending")

        # Groups tab
        groups_frame = ttk.Frame(self.notebook_lists)
        groups_frame.rowconfigure(0, weight=1)
        groups_frame.columnconfigure(0, weight=1)
        self.groups_listbox = tk.Listbox(groups_frame, height=15)
        self.groups_listbox.grid(row=0, column=0, sticky="nsew")
        self.groups_listbox.bind("<Double-Button-1>", self._open_group_tab)
        self.groups_listbox.bind("<<ListboxSelect>>", self._on_group_selected)
        
        # Group controls frame
        group_btn_frame = ttk.Frame(groups_frame)
        group_btn_frame.grid(row=1, column=0, sticky="ew", pady=4)
        ttk.Button(group_btn_frame, text="Create", command=self._create_group_dialog).pack(side="left", padx=2)
        self.member_action_btn = ttk.Button(group_btn_frame, text="Add member", command=self._add_member_dialog, state="disabled")
        self.member_action_btn.pack(side="left", padx=2)
        self.remove_member_btn = ttk.Button(group_btn_frame, text="Remove member", command=self._remove_member_dialog, state="disabled")
        self.remove_member_btn.pack(side="left", padx=2)
        
        self.notebook_lists.add(groups_frame, text="Groups")

        # Chat area (right)
        right_frame = ttk.Frame(self, padding=5)
        right_frame.grid(row=1, column=1, sticky="nsew")
        right_frame.rowconfigure(1, weight=1)
        right_frame.columnconfigure(0, weight=1)

        # Header for chat (shows group/user name + members if group)
        header_frame = ttk.Frame(right_frame)
        header_frame.grid(row=0, column=0, sticky="ew", pady=5)
        
        self.chat_header_label = ttk.Label(header_frame, text="", font=("Arial", 12, "bold"))
        self.chat_header_label.pack(side="left")
        
        self.chat_members_label = ttk.Label(header_frame, text="", font=("Arial", 9))
        self.chat_members_label.pack(side="left", padx=20)

        self.chat_notebook = ttk.Notebook(right_frame)
        self.chat_notebook.grid(row=1, column=0, sticky="nsew")
        self.chat_notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        # Input area
        input_frame = ttk.Frame(right_frame)
        input_frame.grid(row=2, column=0, sticky="ew")

        ttk.Label(input_frame, text="Type message:").grid(row=0, column=0)
        self.message_entry = ttk.Entry(input_frame)
        self.message_entry.grid(row=0, column=1, sticky="ew", padx=5)
        self.message_entry.bind("<Return>", self.on_send_clicked)

        ttk.Button(input_frame, text="Send", command=self.on_send_clicked).grid(row=0, column=2)

        input_frame.columnconfigure(1, weight=1)

        # Status bar
        status_frame = ttk.Frame(self, padding=5)
        status_frame.grid(row=3, column=0, columnspan=2, sticky="ew")

        self.status_label = ttk.Label(status_frame, text="Status: Connected")
        self.status_label.pack(side="left")

        self.server_label = ttk.Label(status_frame, text="Server: 127.0.0.1:5000")
        self.server_label.pack(side="right")

        # kick off initial fetches
        connection.request_all_users()

    # ---------------- Tab creation ----------------

    def _get_or_create_tab(self, key: str):
        for i in range(self.chat_notebook.index("end")):
            if self.chat_notebook.tab(i, "text") == key:
                frame = self.chat_notebook.nametowidget(self.chat_notebook.tabs()[i])
                return frame, frame.text_widget

        frame = ttk.Frame(self.chat_notebook)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        text_widget = tk.Text(frame, state="disabled", wrap="word")
        text_widget.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(frame, command=text_widget.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        text_widget["yscrollcommand"] = scrollbar.set

        frame.text_widget = text_widget
        
        # Add tab with close button
        tab_frame = ttk.Frame(self.chat_notebook)
        tab_label = ttk.Label(tab_frame, text=key)
        tab_label.pack(side="left")
        close_btn = ttk.Button(tab_frame, text="✕", width=2, 
                               command=lambda: self._close_tab(key))
        close_btn.pack(side="left", padx=2)
        
        self.chat_notebook.add(frame, text=key)

        return frame, text_widget
    
    def _close_tab(self, key: str):
        """Close a chat tab"""
        for i in range(self.chat_notebook.index("end")):
            if self.chat_notebook.tab(i, "text") == key:
                self.chat_notebook.forget(i)
                self.unread_counts.pop(key, None)
                self.chat_header_label.config(text="")
                self.chat_members_label.config(text="")
                break

    # ---------------- Display message ----------------

    def _append_message(self, key: str, line: str):
        current = self.chat_notebook.select()
        current_key = self.chat_notebook.tab(current, "text") if current else None

        if key != current_key:
            self.unread_counts[key] = self.unread_counts.get(key, 0) + 1
            self._refresh_lists()

        _, text_widget = self._get_or_create_tab(key)
        text_widget.config(state="normal")
        text_widget.insert("end", line + "\n")
        text_widget.see("end")
        text_widget.config(state="disabled")

    # ---------------- HANDLERS ----------------

    def on_logout(self):
        connection.disconnect()
        self.destroy()
        self.parent.deiconify()

    def on_close(self):
        self.on_logout()

    def on_send_clicked(self, event=None):
        text = self.message_entry.get().strip()
        if not text:
            return

        current_tab = self.chat_notebook.select()
        if not current_tab:
            return

        key = self.chat_notebook.tab(current_tab, "text")

        if key in self.users:
            connection.send_private_message(key, text)
        elif key in self.groups:
            connection.send_group_message(key, text)
        else:
            return

        timestamp = datetime.now().strftime("%H:%M")
        self._append_message(key, f"[{timestamp}] You: {text}")

        self.message_entry.delete(0, "end")

        self.unread_counts.pop(key, None)
        self._refresh_lists()

    # ---------------- List selection ----------------

    def _get_selected_user(self):
        if not self.users_listbox.curselection():
            return None
        idx = self.users_listbox.curselection()[0]
        return self.displayed_users[idx]

    def _get_selected_group(self):
        if not self.groups_listbox.curselection():
            return None
        idx = self.groups_listbox.curselection()[0]
        return self.displayed_groups[idx]

    def _get_selected_directory_user(self):
        if not self.all_users_listbox.curselection():
            return None
        idx = self.all_users_listbox.curselection()[0]
        return self.all_users[idx] if idx < len(self.all_users) else None

    def _get_selected_pending(self):
        if not self.pending_listbox.curselection():
            return None
        idx = self.pending_listbox.curselection()[0]
        return self.pending[idx] if idx < len(self.pending) else None

    def _on_group_selected(self, event=None):
        """Enable/disable buttons and change actions based on admin status"""
        # Use after_idle to ensure selection is updated
        self.after_idle(self._update_group_buttons)
    
    def _update_group_buttons(self):
        """Update button states based on selected group and admin status"""
        group = self._get_selected_group()
        if not group:
            self.member_action_btn.config(state="disabled", text="Add member")
            self.remove_member_btn.pack_forget()
            return
        
        # Check if current user is admin of this group
        admin = self.group_admins.get(group)
        if admin == self.username:
            # User is admin - show "Add member" and enable "Remove member"
            self.member_action_btn.config(text="Add member", command=self._add_member_dialog, state="normal")
            self.remove_member_btn.pack_forget()
            self.remove_member_btn.pack(side="left", padx=2)
            self.remove_member_btn.config(state="normal")
        else:
            # User is not admin - show "Request to add" and hide "Remove member"
            self.member_action_btn.config(text="Request to add", command=self._request_add_member_dialog, state="normal")
            self.remove_member_btn.pack_forget()

    # ---------------- Receive messages ----------------

    def on_message_received(self, msg_type: int, payload: dict):
        self.after(0, self._handle_message, msg_type, payload)

    def _handle_message(self, msg_type: int, payload: dict):

        if msg_type == MSG_SERVER_INFO:
            self.users = payload.get("users", [])

            # groups is list of group names
            self.groups = payload.get("groups", [])
            
            # group_members is dict: {"group_name": ["user1", "user2"], ...}
            self.group_members = payload.get("group_members", {})
            
            # group_admins is dict: {"group_name": "admin_username", ...}
            self.group_admins = payload.get("group_admins", {})

            self._refresh_lists()

        elif msg_type == MSG_PRIVATE_MESSAGE:
            sender = payload["from"]
            text = payload["text"]
            t = datetime.now().strftime("%H:%M")
            self._append_message(sender, f"[{t}] {sender}: {text}")

        elif msg_type == MSG_GROUP_MESSAGE:
            group = payload["group"]
            sender = payload["from"]
            text = payload["text"]
            t = datetime.now().strftime("%H:%M")
            self._append_message(group, f"[{t}] {sender}@{group}: {text}")

        elif msg_type == MSG_LIST_USERS_RESPONSE:
            self.all_users = payload.get("users", [])
            self._refresh_all_users()

        elif msg_type == MSG_FRIEND_LIST:
            self.friends = payload.get("friends", [])
            self.pending = payload.get("pending", [])
            self._refresh_friends()
            self._refresh_pending()

        elif msg_type == MSG_FRIEND_RESPONSE:
            # Show simple status feedback
            message = payload.get("message") or payload.get("error") or "Friend update"
            self.status_label.config(text=f"Status: {message}")

        elif msg_type == MSG_CREATE_GROUP_RESPONSE:
            ok = payload.get("ok", False)
            msg = payload.get("message", "")
            self.status_label.config(text=f"Status: {msg}")
            if ok:
                # Request updated server info to refresh groups list
                connection.request_server_info()

        elif msg_type == MSG_GROUP_ADD_MEMBER_RESPONSE:
            ok = payload.get("ok", False)
            msg = payload.get("message", "")
            self.status_label.config(text=f"Status: {msg}")
            if ok:
                # Request updated server info to refresh groups and members
                connection.request_server_info()

        elif msg_type == MSG_GROUP_REMOVE_MEMBER_RESPONSE:
            ok = payload.get("ok", False)
            msg = payload.get("message", "")
            self.status_label.config(text=f"Status: {msg}")
            if ok:
                # Request updated server info to refresh groups and members
                connection.request_server_info()

        elif msg_type == MSG_REQUEST_ADD_MEMBER_RESPONSE:
            ok = payload.get("ok", False)
            msg = payload.get("message", "")
            # This could be response to our request, or notification to admin
            if ok or "requested" in msg.lower():
                self.status_label.config(text=f"Status: {msg}")
                # If admin received a request, they should see it
                if "requested" in msg.lower():
                    self.after(1000, lambda: connection.request_server_info())

        elif msg_type == MSG_GET_MEMBER_REQUESTS_RESPONSE:
            group = payload.get("group", "")
            requests = payload.get("requests", [])
            self.status_label.config(text=f"Status: {len(requests)} pending requests for {group}")
            # Could display these in a popup, but for now just show count

        elif msg_type == MSG_APPROVE_MEMBER_RESPONSE:
            ok = payload.get("ok", False)
            msg = payload.get("message", "")
            self.status_label.config(text=f"Status: {msg}")
            if ok:
                connection.request_server_info()

        elif msg_type == MSG_REJECT_MEMBER_RESPONSE:
            ok = payload.get("ok", False)
            msg = payload.get("message", "")
            self.status_label.config(text=f"Status: {msg}")

    # ---------------- Update lists ----------------

    def _refresh_lists(self):
        # USERS
        self.users_listbox.delete(0, "end")
        self.displayed_users = []

        friend_set = set(self.friends)
        for u in self.users:
            # Users tab shows only online friends
            if u == self.username or u not in friend_set:
                continue
            self.displayed_users.append(u)

            count = self.unread_counts.get(u, 0)
            display = f"{u} ({count})" if count else u
            self.users_listbox.insert("end", display)

        # GROUPS
        self.groups_listbox.delete(0, "end")
        self.displayed_groups = []

        for g in self.groups:
            self.displayed_groups.append(g)

            count = self.unread_counts.get(g, 0)
            display = f"{g} ({count})" if count else g
            self.groups_listbox.insert("end", display)

    def _refresh_all_users(self):
        """Show all users EXCEPT yourself and existing friends"""
        self.all_users_listbox.delete(0, "end")
        for u in self.all_users:
            # Skip yourself
            if u == self.username:
                continue
            # Skip if already your friend
            if u in self.friends:
                continue
            self.all_users_listbox.insert("end", u)

    def _refresh_friends(self):
        """Show only your friends"""
        self.friends_listbox.delete(0, "end")
        for u in self.friends:
            self.friends_listbox.insert("end", u)

    def _refresh_pending(self):
        """Show pending friend requests received"""
        self.pending_listbox.delete(0, "end")
        for u in self.pending:
            self.pending_listbox.insert("end", u)

    # ---------------- Open chats ----------------

    def _open_user_tab(self, event=None):
        sel = self._get_selected_user()
        if not sel:
            return
        self._get_or_create_tab(sel)
        self.unread_counts.pop(sel, None)
        self._refresh_lists()

    def _open_group_tab(self, event=None):
        sel = self._get_selected_group()
        if not sel:
            return
        self._get_or_create_tab(sel)
        self.unread_counts.pop(sel, None)
        self._refresh_lists()

    def _send_friend_request(self):
        target = self._get_selected_directory_user()
        if not target or target == self.username:
            return
        connection.send_friend_request(target)
        self.status_label.config(text=f"Status: Sent friend request to {target}")

    def _accept_friend_request(self):
        requester = self._get_selected_pending()
        if not requester:
            return
        connection.accept_friend_request(requester)
        self.status_label.config(text=f"Status: Accepted request from {requester}")

    def _create_group_dialog(self):
        top = tk.Toplevel(self)
        top.title("Create Group")
        top.geometry("300x100")
        
        ttk.Label(top, text="Group name:").pack(pady=5)
        name_entry = ttk.Entry(top)
        name_entry.pack(padx=10, fill="x")
        
        def create():
            name = name_entry.get().strip()
            if name:
                connection.create_group(name)
                top.destroy()
        
        ttk.Button(top, text="Create", command=create).pack(pady=10)

    def _request_add_member_dialog(self):
        """Non-admin member requests to add a friend to the group"""
        group = self._get_selected_group()
        if not group:
            self.status_label.config(text="Status: Select a group first")
            return
        
        if not self.friends:
            self.status_label.config(text="Status: You have no friends yet")
            return
        
        # Get current members in the group
        current_members = self.group_members.get(group, [])
        
        # Filter friends who are NOT already in the group
        available_friends = [f for f in self.friends if f not in current_members]
        
        if not available_friends:
            self.status_label.config(text="Status: All your friends are already in this group")
            return
        
        top = tk.Toplevel(self)
        top.title(f"Request to add member to {group}")
        top.geometry("300x220")
        
        ttk.Label(top, text="Friends to add (request approval):", font=("Arial", 10, "bold")).pack(pady=5)
        
        # Show info about current members
        current_text = f"Current members ({len(current_members)}): {', '.join(current_members)}"
        ttk.Label(top, text=current_text, font=("Arial", 8), wraplength=280).pack(pady=3)
        
        ttk.Label(top, text="Note: Admin must approve this request", font=("Arial", 8, "italic")).pack(pady=3)
        
        ttk.Label(top, text="Select friend to request:").pack(pady=5)
        friend_listbox = tk.Listbox(top, height=6)
        friend_listbox.pack(padx=10, fill="both", expand=True)
        
        # Populate with available friends
        for f in available_friends:
            friend_listbox.insert("end", f)
        
        def request():
            if not friend_listbox.curselection():
                return
            idx = friend_listbox.curselection()[0]
            friend = available_friends[idx]
            connection.request_add_member_to_group(group, friend)
            self.status_label.config(text=f"Status: Requested admin approval to add {friend} to {group}")
            top.destroy()
        
        ttk.Button(top, text="Request", command=request).pack(pady=5)

    def _add_member_dialog(self):
        """Admin directly adds a member to the group"""
        group = self._get_selected_group()
        if not group:
            self.status_label.config(text="Status: Select a group first")
            print("[DEBUG] No group selected")
            return
        
        print(f"[DEBUG] Selected group: {group}")
        print(f"[DEBUG] Group admins: {self.group_admins}")
        
        # Check if user is admin
        admin = self.group_admins.get(group)
        print(f"[DEBUG] Admin for {group}: {admin}, Current user: {self.username}")
        
        if admin != self.username:
            self.status_label.config(text=f"Status: Only admin ({admin}) can add members to {group}")
            print(f"[DEBUG] User is not admin")
            return
        
        if not self.friends:
            self.status_label.config(text="Status: You have no friends yet")
            print("[DEBUG] No friends")
            return
        
        # Get current members in the group
        current_members = self.group_members.get(group, [])
        print(f"[DEBUG] Current members: {current_members}")
        print(f"[DEBUG] Your friends: {self.friends}")
        
        # Filter friends who are NOT already in the group
        available_friends = [f for f in self.friends if f not in current_members]
        print(f"[DEBUG] Available friends: {available_friends}")
        
        if not available_friends:
            self.status_label.config(text="Status: All your friends are already in this group")
            return
        
        top = tk.Toplevel(self)
        top.title(f"Add member to {group}")
        top.geometry("300x200")
        
        ttk.Label(top, text="Available friends to add:", font=("Arial", 10, "bold")).pack(pady=5)
        
        # Show info about current members
        current_text = f"Current members ({len(current_members)}): {', '.join(current_members)}"
        ttk.Label(top, text=current_text, font=("Arial", 8), wraplength=280).pack(pady=3)
        
        ttk.Label(top, text="Select friend to add:").pack(pady=5)
        friend_listbox = tk.Listbox(top, height=6)
        friend_listbox.pack(padx=10, fill="both", expand=True)
        
        # Populate with available friends
        for f in available_friends:
            friend_listbox.insert("end", f)
        
        def add():
            if not friend_listbox.curselection():
                return
            idx = friend_listbox.curselection()[0]
            friend = available_friends[idx]
            connection.add_member_to_group(group, friend)
            self.status_label.config(text=f"Status: Adding {friend} to {group}...")
            top.destroy()
        
        ttk.Button(top, text="Add", command=add).pack(pady=5)


    def _remove_member_dialog(self):
        group = self._get_selected_group()
        if not group:
            self.status_label.config(text="Status: Select a group first")
            return
        
        # Check if user is admin
        admin = self.group_admins.get(group)
        if admin != self.username:
            self.status_label.config(text="Status: Only admin can remove members")
            return
        
        members = self.group_members.get(group, [])
        # Filter out self (admin can't remove themselves)
        removable_members = [m for m in members if m != self.username]
        
        if not removable_members:
            self.status_label.config(text="Status: No other members to remove")
            return
        
        top = tk.Toplevel(self)
        top.title(f"Remove member from {group}")
        top.geometry("300x220")
        
        ttk.Label(top, text="Group members:", font=("Arial", 10, "bold")).pack(pady=5)
        
        # Show admin info
        admin_text = f"Admin: {admin} (You)"
        ttk.Label(top, text=admin_text, font=("Arial", 8)).pack(pady=2)
        
        ttk.Label(top, text="Select member to remove:").pack(pady=5)
        member_listbox = tk.Listbox(top, height=6)
        member_listbox.pack(padx=10, fill="both", expand=True)
        
        # Show all removable members
        for m in removable_members:
            member_listbox.insert("end", m)
        
        def remove():
            if not member_listbox.curselection():
                return
            idx = member_listbox.curselection()[0]
            member = removable_members[idx]
            connection.remove_member_from_group(group, member)
            self.status_label.config(text=f"Status: Removing {member} from {group}...")
            top.destroy()
        
        ttk.Button(top, text="Remove", command=remove).pack(pady=5)

    # ---------------- Tab changed ----------------

    def _on_tab_changed(self, event=None):
        current = self.chat_notebook.select()
        if not current:
            self.chat_header_label.config(text="")
            self.chat_members_label.config(text="")
            return
        
        key = self.chat_notebook.tab(current, "text")
        self.unread_counts.pop(key, None)
        self._refresh_lists()
        
        # Update header with name and members if it's a group
        if key in self.groups:
            members = self.group_members.get(key, [])
            admin = self.group_admins.get(key, "Unknown")
            members_text = ", ".join(members) if members else "No members"
            
            # Show admin info
            is_admin = (admin == self.username)
            admin_label = " (You are admin)" if is_admin else f" (Admin: {admin})"
            
            self.chat_header_label.config(text=f"Group: {key}{admin_label}")
            self.chat_members_label.config(text=f"Members: {members_text}")
        elif key in self.users:
            self.chat_header_label.config(text=f"Chat with: {key}")
            self.chat_members_label.config(text="")
        else:
            self.chat_header_label.config(text="")
            self.chat_members_label.config(text="")
