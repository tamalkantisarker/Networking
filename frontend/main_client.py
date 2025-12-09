# frontend/main_client.py

try:
    from .ui.login_window import LoginWindow
except ImportError:
    # Allow running directly: python main_client.py
    import os, sys
    base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if base_path not in sys.path:
        sys.path.insert(0, base_path)
    from ui.login_window import LoginWindow


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000


def main():
    """
    Start the GUI login window.
    Host/port are passed in case future versions display or use them.
    """
    app = LoginWindow(host=DEFAULT_HOST, port=DEFAULT_PORT)
    app.mainloop()


if __name__ == "__main__":
    main()
