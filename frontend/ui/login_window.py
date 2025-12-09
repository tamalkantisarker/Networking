import tkinter as tk
from tkinter import ttk, messagebox

import connection
from ui.chat_window import MainChatWindow


class LoginWindow(tk.Tk):
    def __init__(self, host: str = "127.0.0.1", port: int = 5000):
        super().__init__()
        self.title("Secure Chat Login")

        self.host = host
        self.port = port

        # window size & center
        win_w, win_h = 600, 400
        self.geometry(f"{win_w}x{win_h}")
        self.resizable(False, False)

        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        x = (screen_w // 2) - (win_w // 2)
        y = (screen_h // 2) - (win_h // 2)
        self.geometry(f"{win_w}x{win_h}+{x}+{y}")

        self.configure(bg="#E8EEF3")

        # ---------- LOGIN UI CARD ----------
        card = tk.Frame(self, bg="white", bd=2, relief="ridge")
        card.place(relx=0.5, rely=0.5, anchor="center")

        inner = tk.Frame(card, bg="white", padx=30, pady=25)
        inner.pack()

        tk.Label(inner,
                 text="Secure Chat Login",
                 font=("Arial", 18, "bold"),
                 bg="white").pack(pady=(0, 20))

        # Username
        user_frame = tk.Frame(inner, bg="white")
        user_frame.pack(fill="x", pady=5)
        tk.Label(user_frame, text="Username:", bg="white").pack(side="left", padx=(0, 10))
        self.username_entry = ttk.Entry(user_frame, width=30)
        self.username_entry.pack(side="left", fill="x", expand=True)

        # Password
        pass_frame = tk.Frame(inner, bg="white")
        pass_frame.pack(fill="x", pady=5)
        tk.Label(pass_frame, text="Password:", bg="white").pack(side="left", padx=(0, 10))
        self.password_entry = ttk.Entry(pass_frame, show="*", width=30)
        self.password_entry.pack(side="left", fill="x", expand=True)

        # Status label
        self.status_label = tk.Label(inner, text="", fg="red", bg="white", anchor="w")
        self.status_label.pack(fill="x", pady=(5, 0))

        # Buttons
        btn_frame = tk.Frame(inner, bg="white")
        btn_frame.pack(pady=15)

        ttk.Button(btn_frame, text="Login", command=self.do_login).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Create Account", command=self.show_signup_dialog).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Close", command=self.destroy).pack(side="left", padx=5)

        self.username_entry.focus()

    # ---------------- LOGIN LOGIC ----------------

    def do_login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            self.status_label.config(text="Please enter username and password")
            return

        ok = connection.login(username, password)
        if ok:
            self.status_label.config(text="")
            self.open_main_window(username)
        else:
            self.status_label.config(text="Login failed. Check credentials.")

    # ---------------- SIGNUP DIALOG ----------------

    def show_signup_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Create New Account")
        dialog.transient(self)
        dialog.grab_set()
        dialog.resizable(False, False)

        win_w, win_h = 400, 320
        x = self.winfo_rootx() + 50
        y = self.winfo_rooty() + 50
        dialog.geometry(f"{win_w}x{win_h}+{x}+{y}")

        container = tk.Frame(dialog, padx=20, pady=20)
        container.pack(fill="both", expand=True)

        current_step = tk.IntVar(value=1)
        email_var = tk.StringVar()
        code_var = tk.StringVar()
        username_var = tk.StringVar()
        password_var = tk.StringVar()

        step_label = tk.Label(container, text="Step 1: Enter your email",
                              font=("Arial", 12, "bold"))
        step_label.pack(pady=(0, 10))

        step_frame = tk.Frame(container)
        step_frame.pack(fill="both", expand=True)

        status_label = tk.Label(container, text="", fg="red")
        status_label.pack(fill="x", pady=(5, 0))

        btn_frame = tk.Frame(container)
        btn_frame.pack(pady=10)

        # ---------- STEP UIs ----------
        def build_step_1():
            for w in step_frame.winfo_children():
                w.destroy()
            tk.Label(step_frame, text="Email:").pack(anchor="w")
            entry = ttk.Entry(step_frame, textvariable=email_var, width=30)
            entry.pack(fill="x")
            entry.focus()

        def build_step_2():
            for w in step_frame.winfo_children():
                w.destroy()
            tk.Label(step_frame, text="Check server console for your code.").pack(anchor="w")
            tk.Label(step_frame, text="Verification code:").pack(anchor="w")
            entry = ttk.Entry(step_frame, textvariable=code_var, width=20)
            entry.pack(anchor="w")
            entry.focus()

        def build_step_3():
            for w in step_frame.winfo_children():
                w.destroy()

            tk.Label(step_frame, text="Choose username and password").pack(anchor="w")

            uf = tk.Frame(step_frame)
            uf.pack(fill="x", pady=5)
            tk.Label(uf, text="Username:").pack(side="left")
            ttk.Entry(uf, textvariable=username_var, width=25).pack(side="left", fill="x", expand=True)

            pf = tk.Frame(step_frame)
            pf.pack(fill="x", pady=5)
            tk.Label(pf, text="Password:").pack(side="left")
            ttk.Entry(pf, textvariable=password_var, show="*", width=25).pack(side="left", fill="x", expand=True)

        def refresh():
            step = current_step.get()
            if step == 1:
                step_label.config(text="Step 1: Enter your email")
                build_step_1()
            elif step == 2:
                step_label.config(text="Step 2: Enter verification code")
                build_step_2()
            else:
                step_label.config(text="Step 3: Create username & password")
                build_step_3()
            status_label.config(text="")

        # ---------- NEXT BUTTON ACTION ----------
        def on_next():
            step = current_step.get()

            if step == 1:
                email = email_var.get().strip()
                if "@" not in email:
                    status_label.config(text="Enter a valid email")
                    return
                ok, msg = connection.signup_start_email(email)
                status_label.config(text=msg)
                if ok:
                    current_step.set(2)
                    refresh()

            elif step == 2:
                email = email_var.get().strip()
                code = code_var.get().strip()
                ok, msg = connection.signup_verify_code(email, code)
                status_label.config(text=msg)
                if ok:
                    current_step.set(3)
                    refresh()

            elif step == 3:
                email = email_var.get().strip()
                username = username_var.get().strip()
                password = password_var.get().strip()

                if not username or not password:
                    status_label.config(text="All fields required")
                    return

                ok, msg = connection.signup_set_credentials(email, username, password)
                if ok:
                    messagebox.showinfo("Success", msg)
                    dialog.destroy()
                else:
                    status_label.config(text=msg)

        # ---------- BACK BUTTON ACTION ----------
        def on_back():
            step = current_step.get()
            if step > 1:
                current_step.set(step - 1)
                refresh()
            else:
                dialog.destroy()

        ttk.Button(btn_frame, text="Back", command=on_back).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Next", command=on_next).pack(side="left", padx=5)

        refresh()

    # ---------------- OPEN CHAT WINDOW ----------------

    def open_main_window(self, username: str):
        self.withdraw()
        main = MainChatWindow(self, username)
        main.protocol("WM_DELETE_WINDOW", main.on_close)
