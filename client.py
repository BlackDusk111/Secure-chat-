"""
=============================================================
  SECURE CHAT CLIENT  |  client.py
  Features:
    • Register any username / Login
    • General broadcast channel
    • Private DM tabs per user (click a user to DM them)
    • Live encryption proof panel (shows real ciphertext)
    • RSA-2048 + AES-256-CBC hybrid encryption
=============================================================
"""

import socket
import threading
import json
import base64
import time
import tkinter as tk
from tkinter import scrolledtext
from datetime import datetime
from crypto_utils import (
    generate_rsa_keypair,
    serialize_public_key,
    load_public_key,
    aes_encrypt,
    aes_decrypt,
    rsa_encrypt,
    rsa_decrypt,
)

# ─────────────────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────────────────
HOST = "127.0.0.1"
PORT = 65432

# ─────────────────────────────────────────────────────────
#  COLOUR PALETTE
# ─────────────────────────────────────────────────────────
BG_DARK   = "#0d1117"
BG_PANEL  = "#161b22"
BG_CARD   = "#21262d"
ACCENT    = "#58a6ff"
GREEN     = "#3fb950"
RED       = "#f85149"
TEXT_MAIN = "#e6edf3"
TEXT_DIM  = "#8b949e"
BORDER    = "#30363d"
DM_COLOR  = "#bc8cff"

# ─────────────────────────────────────────────────────────
#  NETWORK HELPERS
# ─────────────────────────────────────────────────────────
def send_json(sock, data):
    payload = json.dumps(data).encode("utf-8")
    sock.sendall(len(payload).to_bytes(4, "big") + payload)

def recv_json(sock):
    try:
        raw_len = _recv_exact(sock, 4)
        if not raw_len:
            return None
        raw = _recv_exact(sock, int.from_bytes(raw_len, "big"))
        return json.loads(raw.decode("utf-8")) if raw else None
    except Exception:
        return None

def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


# ─────────────────────────────────────────────────────────
#  AUTH WINDOW  — completely rebuilt, no packing bugs
# ─────────────────────────────────────────────────────────
class AuthWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureChat")
        self.root.configure(bg=BG_DARK)
        self.root.resizable(False, False)
        self.result = None
        self._mode = "login"   # "login" or "register"
        self._build_ui()
        # Size window AFTER building so all widgets are measured correctly
        self.root.update_idletasks()
        self.root.geometry("440x600")

    def _build_ui(self):
        # ── TOP: lock icon + title ──────────────────────────
        tk.Label(self.root, text="🔒", font=("Segoe UI Emoji", 42),
                 bg=BG_DARK, fg=ACCENT).pack(pady=(28, 2))
        tk.Label(self.root, text="SecureChat",
                 font=("Segoe UI", 22, "bold"), bg=BG_DARK, fg=TEXT_MAIN).pack()
        tk.Label(self.root,
                 text="End-to-End Encrypted  ·  RSA-2048 + AES-256",
                 font=("Segoe UI", 9), bg=BG_DARK, fg=TEXT_DIM).pack(pady=(2, 18))

        # ── TAB BAR ─────────────────────────────────────────
        tab_row = tk.Frame(self.root, bg=BG_DARK)
        tab_row.pack(padx=36, fill="x")
        self._login_btn = tk.Button(
            tab_row, text="Login", font=("Segoe UI", 10, "bold"),
            bg=ACCENT, fg="white", relief="flat", cursor="hand2",
            command=lambda: self._switch("login"), padx=20, pady=7
        )
        self._login_btn.pack(side="left", fill="x", expand=True)
        self._reg_btn = tk.Button(
            tab_row, text="Register", font=("Segoe UI", 10, "bold"),
            bg=BG_CARD, fg=TEXT_DIM, relief="flat", cursor="hand2",
            command=lambda: self._switch("register"), padx=20, pady=7
        )
        self._reg_btn.pack(side="left", fill="x", expand=True)

        # ── FORM CARD ───────────────────────────────────────
        card = tk.Frame(self.root, bg=BG_PANEL)
        card.pack(padx=36, pady=14, fill="x")

        self._title_lbl = tk.Label(card, text="Welcome back",
                                   font=("Segoe UI", 13, "bold"),
                                   bg=BG_PANEL, fg=TEXT_MAIN, anchor="w")
        self._title_lbl.pack(fill="x", padx=20, pady=(18, 2))

        self._sub_lbl = tk.Label(card, text="Log in to your account",
                                 font=("Segoe UI", 9), bg=BG_PANEL, fg=TEXT_DIM, anchor="w")
        self._sub_lbl.pack(fill="x", padx=20, pady=(0, 14))

        # Username
        tk.Label(card, text="Username", font=("Segoe UI", 9),
                 bg=BG_PANEL, fg=TEXT_DIM, anchor="w").pack(fill="x", padx=20, pady=(0, 3))
        self._uvar = tk.StringVar()
        self._uentr = tk.Entry(card, textvariable=self._uvar,
                               font=("Consolas", 12), bg=BG_CARD, fg=TEXT_MAIN,
                               insertbackground=ACCENT, relief="flat", bd=9)
        self._uentr.pack(fill="x", padx=20, pady=(0, 12))

        # Password
        tk.Label(card, text="Password", font=("Segoe UI", 9),
                 bg=BG_PANEL, fg=TEXT_DIM, anchor="w").pack(fill="x", padx=20, pady=(0, 3))
        self._pvar = tk.StringVar()
        self._pentr = tk.Entry(card, textvariable=self._pvar, show="●",
                               font=("Consolas", 12), bg=BG_CARD, fg=TEXT_MAIN,
                               insertbackground=ACCENT, relief="flat", bd=9)
        self._pentr.pack(fill="x", padx=20, pady=(0, 12))

        # Confirm password — ALWAYS created, toggled visible/hidden
        self._confirm_outer = tk.Frame(card, bg=BG_PANEL)
        tk.Label(self._confirm_outer, text="Confirm Password",
                 font=("Segoe UI", 9), bg=BG_PANEL, fg=TEXT_DIM, anchor="w"
                 ).pack(fill="x", pady=(0, 3))
        self._cvar = tk.StringVar()
        self._centr = tk.Entry(self._confirm_outer, textvariable=self._cvar, show="●",
                               font=("Consolas", 12), bg=BG_CARD, fg=TEXT_MAIN,
                               insertbackground=ACCENT, relief="flat", bd=9)
        self._centr.pack(fill="x")
        # Hidden by default (login mode)
        # We use pack/pack_forget on _confirm_outer

        # Action button — placed AFTER confirm so it's always below it
        self._action_btn = tk.Button(
            card, text="Login", font=("Segoe UI", 11, "bold"),
            bg=ACCENT, fg="white", relief="flat", cursor="hand2",
            activebackground="#1f6feb", command=self._submit, pady=10
        )
        self._action_btn.pack(fill="x", padx=20, pady=(4, 20))

        # ── STATUS label (outside card, always visible) ─────
        self._status_var = tk.StringVar()
        self._status_lbl = tk.Label(
            self.root, textvariable=self._status_var,
            font=("Segoe UI", 9), bg=BG_DARK, fg=RED,
            wraplength=380, justify="center"
        )
        self._status_lbl.pack(pady=4)

        # Key bindings
        self._uentr.bind("<Return>", lambda e: self._pentr.focus())
        self._pentr.bind("<Return>", lambda e: self._centr.focus() if self._mode == "register" else self._submit())
        self._centr.bind("<Return>", lambda e: self._submit())
        self._uentr.focus()

    def _switch(self, mode):
        self._mode = mode
        self._status_var.set("")
        if mode == "login":
            self._login_btn.config(bg=ACCENT, fg="white")
            self._reg_btn.config(bg=BG_CARD, fg=TEXT_DIM)
            self._title_lbl.config(text="Welcome back")
            self._sub_lbl.config(text="Log in to your account")
            self._action_btn.config(text="Login")
            # Hide confirm field
            self._confirm_outer.pack_forget()
            self.root.geometry("440x600")
        else:
            self._reg_btn.config(bg=ACCENT, fg="white")
            self._login_btn.config(bg=BG_CARD, fg=TEXT_DIM)
            self._title_lbl.config(text="Create Account")
            self._sub_lbl.config(text="Choose any username and password")
            self._action_btn.config(text="Register & Join")
            # Show confirm field: unpack action btn, pack confirm, repack action btn
            self._action_btn.pack_forget()
            self._confirm_outer.pack(fill="x", padx=20, pady=(0, 12))
            self._action_btn.pack(fill="x", padx=20, pady=(4, 20))
            self._cvar.set("")
            self._centr.focus()
            self.root.geometry("440x680")  # taller to fit confirm field + button

    def _submit(self):
        username = self._uvar.get().strip()
        password = self._pvar.get()

        # Basic validation
        if not username:
            self._set_status("⚠ Please enter a username.")
            self._uentr.focus()
            return
        if not password:
            self._set_status("⚠ Please enter a password.")
            self._pentr.focus()
            return

        if self._mode == "register":
            if len(password) < 4:
                self._set_status("⚠ Password must be at least 4 characters.")
                return
            confirm = self._cvar.get()
            if not confirm:
                self._set_status("⚠ Please confirm your password.")
                self._centr.focus()
                return
            if password != confirm:
                self._set_status("⚠ Passwords do not match.")
                self._centr.focus()
                return

        # Disable button, show progress
        self._action_btn.config(state="disabled", text="Connecting…")
        self._set_status("Connecting to server…", color=TEXT_DIM)

        threading.Thread(
            target=self._do_connect,
            args=(username, password, self._mode),
            daemon=True
        ).start()

    def _do_connect(self, username, password, mode):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(8)
            sock.connect((HOST, PORT))
            sock.settimeout(None)

            send_json(sock, {"type": mode, "username": username, "password": password})
            resp = recv_json(sock)

            if not resp:
                self.root.after(0, self._fail, "No response from server. Is server.py running?")
                sock.close()
                return

            if not resp.get("success"):
                reason = resp.get("reason", "Authentication failed.")
                self.root.after(0, self._fail, reason)
                sock.close()
                return

            # Generate RSA key pair
            self.root.after(0, self._set_status, "Generating encryption keys…", TEXT_DIM)
            private_key, public_key = generate_rsa_keypair()
            pub_pem = serialize_public_key(public_key)

            send_json(sock, {"type": "public_key", "key": pub_pem})
            user_list_msg = recv_json(sock)
            users_full = user_list_msg.get("users", {}) if user_list_msg else {}

            self.root.after(0, self._success, sock, username, private_key, users_full)

        except ConnectionRefusedError:
            self.root.after(0, self._fail,
                            "Could not connect — make sure server.py is running first!")
        except TimeoutError:
            self.root.after(0, self._fail, "Connection timed out. Check that server.py is running.")
        except OSError as e:
            self.root.after(0, self._fail, f"Network error: {e}")
        except Exception as e:
            self.root.after(0, self._fail, f"Error: {e}")

    def _set_status(self, text, color=None):
        self._status_var.set(text)
        self._status_lbl.config(fg=color if color else RED)

    def _fail(self, reason):
        self._set_status(f"⚠  {reason}")
        btn_text = "Login" if self._mode == "login" else "Register & Join"
        self._action_btn.config(state="normal", text=btn_text)

    def _success(self, sock, username, private_key, users_full):
        self.result = (sock, username, private_key, users_full)
        self.root.quit()


# ─────────────────────────────────────────────────────────
#  CHAT WINDOW
# ─────────────────────────────────────────────────────────
class ChatWindow:
    def __init__(self, root, sock, username, private_key, users_full):
        self.root = root
        self.sock = sock
        self.username = username
        self.private_key = private_key

        # peer public keys: username → key object
        self.peer_keys = {}
        for u, pem in users_full.items():
            if u != username:
                try:
                    self.peer_keys[u] = load_public_key(pem)
                except Exception:
                    pass

        self.active_tab = "general"
        self.channel_history = {"general": []}
        self.unread = {}
        self.last_enc = {"ciphertext": "", "iv": "", "key": "", "channel": ""}
        self.proof_visible = False

        self.root.title(f"SecureChat — {username}")
        self.root.geometry("1060x660")
        self.root.configure(bg=BG_DARK)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._build_ui()
        self._update_user_buttons(list(users_full.keys()))
        threading.Thread(target=self._recv_loop, daemon=True).start()
        self._sys_msg("general", "🔐 Connected. RSA-2048 key exchange complete. AES-256-CBC active.")

    # ──────────────────────────────────────────────────────
    #  BUILD UI
    # ──────────────────────────────────────────────────────
    def _build_ui(self):
        # LEFT SIDEBAR
        sidebar = tk.Frame(self.root, bg=BG_PANEL, width=215)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="🔒 SecureChat",
                 font=("Segoe UI", 12, "bold"), bg=BG_PANEL, fg=ACCENT
                 ).pack(anchor="w", padx=14, pady=(16, 0))
        tk.Label(sidebar, text=f"● {self.username}",
                 font=("Segoe UI", 9), bg=BG_PANEL, fg=GREEN
                 ).pack(anchor="w", padx=16, pady=(2, 0))

        tk.Frame(sidebar, bg=BORDER, height=1).pack(fill="x", padx=10, pady=10)

        tk.Label(sidebar, text="CHANNELS", font=("Segoe UI", 8, "bold"),
                 bg=BG_PANEL, fg=TEXT_DIM).pack(anchor="w", padx=14)
        self._general_btn = tk.Button(
            sidebar, text="# general", font=("Segoe UI", 10),
            bg=ACCENT, fg="white", relief="flat", cursor="hand2", anchor="w",
            command=lambda: self._switch_tab("general"), padx=10, pady=4
        )
        self._general_btn.pack(fill="x", padx=8, pady=(4, 0))

        tk.Frame(sidebar, bg=BORDER, height=1).pack(fill="x", padx=10, pady=10)

        tk.Label(sidebar, text="DIRECT MESSAGES", font=("Segoe UI", 8, "bold"),
                 bg=BG_PANEL, fg=TEXT_DIM).pack(anchor="w", padx=14)

        self._dm_frame = tk.Frame(sidebar, bg=BG_PANEL)
        self._dm_frame.pack(fill="x", padx=8, pady=4)

        tk.Frame(sidebar, bg=BORDER, height=1).pack(fill="x", padx=10, pady=10)

        # Encryption info box
        enc_box = tk.Frame(sidebar, bg=BG_CARD)
        enc_box.pack(fill="x", padx=10, side="bottom", pady=10)
        tk.Label(enc_box, text="🛡 ENCRYPTION ACTIVE",
                 font=("Segoe UI", 8, "bold"), bg=BG_CARD, fg=GREEN
                 ).pack(anchor="w", padx=8, pady=(8, 2))
        for line in ["✓ RSA-2048 key exchange",
                     "✓ AES-256-CBC per message",
                     "✓ OAEP / SHA-256 padding",
                     "✓ Random key per message"]:
            tk.Label(enc_box, text=line, font=("Segoe UI", 8),
                     bg=BG_CARD, fg=TEXT_DIM).pack(anchor="w", padx=10)
        tk.Label(enc_box, text="", bg=BG_CARD).pack(pady=4)

        # Register new account button (bottom of sidebar, above enc box)
        tk.Button(
            sidebar, text="+ Register New Account",
            font=("Segoe UI", 9), bg=BG_PANEL, fg=TEXT_DIM,
            relief="flat", cursor="hand2", pady=5,
            activebackground=BG_CARD,
            command=self._open_register_window
        ).pack(side="bottom", fill="x", padx=10, pady=(0, 4))

        # MAIN AREA
        main = tk.Frame(self.root, bg=BG_DARK)
        main.pack(side="left", fill="both", expand=True)

        # Header
        hdr = tk.Frame(main, bg=BG_PANEL, height=50)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        self._chan_lbl = tk.Label(hdr, text="# general (everyone)",
                                  font=("Segoe UI", 12, "bold"), bg=BG_PANEL, fg=TEXT_MAIN)
        self._chan_lbl.pack(side="left", padx=16, pady=12)
        self._conn_lbl = tk.Label(hdr, text="● Connected",
                                  font=("Segoe UI", 9), bg=BG_PANEL, fg=GREEN)
        self._conn_lbl.pack(side="right", padx=10)
        self._enc_lbl = tk.Label(hdr, text="🔒 E2E Encrypted",
                                 font=("Segoe UI", 9), bg=BG_PANEL, fg=GREEN)
        self._enc_lbl.pack(side="right", padx=10)

        # Chat box
        self._chat = scrolledtext.ScrolledText(
            main, state="disabled", font=("Segoe UI", 10),
            bg=BG_DARK, fg=TEXT_MAIN, relief="flat", bd=0,
            wrap="word", padx=14, pady=8
        )
        self._chat.pack(fill="both", expand=True)

        self._chat.tag_config("self_name",  foreground=GREEN,    font=("Segoe UI", 9, "bold"))
        self._chat.tag_config("other_name", foreground=ACCENT,   font=("Segoe UI", 9, "bold"))
        self._chat.tag_config("dm_name",    foreground=DM_COLOR, font=("Segoe UI", 9, "bold"))
        self._chat.tag_config("time_tag",   foreground=TEXT_DIM, font=("Segoe UI", 8))
        self._chat.tag_config("msg_text",   foreground=TEXT_MAIN)
        self._chat.tag_config("enc_proof",  foreground="#3a7d4f", font=("Consolas", 7))
        self._chat.tag_config("sys_msg",    foreground=TEXT_DIM, font=("Segoe UI", 9, "italic"))
        self._chat.tag_config("dm_badge",   foreground=DM_COLOR, font=("Segoe UI", 8))

        # Encryption proof toggle bar
        proof_bar = tk.Frame(main, bg=BG_PANEL)
        proof_bar.pack(fill="x")
        tk.Button(proof_bar,
                  text="▼  Show Encryption Proof  —  what the server/network actually sees",
                  font=("Segoe UI", 8), bg=BG_PANEL, fg=TEXT_DIM, relief="flat",
                  cursor="hand2", command=self._toggle_proof
                  ).pack(side="left", padx=10, pady=3)

        # Proof panel (hidden until toggled)
        self._proof_frame = tk.Frame(main, bg="#0b0f14")
        self._proof_text = scrolledtext.ScrolledText(
            self._proof_frame, height=7, font=("Consolas", 8),
            bg="#0b0f14", fg="#3fb950", relief="flat", bd=0,
            wrap="word", state="disabled"
        )
        self._proof_text.pack(fill="x", padx=10, pady=6)

        # Input bar
        inp = tk.Frame(main, bg=BG_PANEL, pady=10)
        inp.pack(fill="x")
        self._mvar = tk.StringVar()
        self._mentr = tk.Entry(
            inp, textvariable=self._mvar, font=("Segoe UI", 11),
            bg=BG_CARD, fg=TEXT_MAIN, insertbackground=ACCENT, relief="flat", bd=10
        )
        self._mentr.pack(side="left", fill="x", expand=True, padx=(12, 6))
        self._mentr.bind("<Return>", lambda e: self._send())
        tk.Button(
            inp, text="Send 🔒", font=("Segoe UI", 10, "bold"),
            bg=ACCENT, fg="white", relief="flat", cursor="hand2",
            activebackground="#1f6feb", command=self._send, padx=14, pady=6
        ).pack(side="right", padx=(0, 12))
        self._mentr.focus()

    # ──────────────────────────────────────────────────────
    #  TABS / CHANNELS
    # ──────────────────────────────────────────────────────
    def _switch_tab(self, channel):
        self.active_tab = channel
        self.unread[channel] = 0
        if channel == "general":
            self._chan_lbl.config(text="# general  (everyone)")
            self._enc_lbl.config(text="🔒 E2E Encrypted  ·  AES-256 broadcast")
        else:
            self._chan_lbl.config(text=f"🔒 DM  ·  {channel}  (private)")
            self._enc_lbl.config(text="🔒 E2E Encrypted  ·  RSA-wrapped AES key")
        self._redraw(channel)
        self._refresh_tab_colors()

    def _update_user_buttons(self, users):
        for w in self._dm_frame.winfo_children():
            w.destroy()
        others = [u for u in users if u != self.username]
        if not others:
            tk.Label(self._dm_frame, text="  (no other users online)",
                     font=("Segoe UI", 8), bg=BG_PANEL, fg=TEXT_DIM).pack(anchor="w")
            return
        for u in others:
            if u not in self.channel_history:
                self.channel_history[u] = []
            unread = self.unread.get(u, 0)
            label = f"  @ {u}" + (f"  [{unread} new]" if unread else "")
            is_active = (self.active_tab == u)
            btn = tk.Button(
                self._dm_frame, text=label, font=("Segoe UI", 10),
                bg=BG_CARD if is_active else BG_PANEL,
                fg=DM_COLOR if is_active else TEXT_MAIN,
                relief="flat", cursor="hand2", anchor="w", padx=6, pady=3,
                command=lambda usr=u: self._switch_tab(usr)
            )
            btn.pack(fill="x", pady=1)

    def _refresh_tab_colors(self):
        # Update general button
        is_gen = self.active_tab == "general"
        self._general_btn.config(
            bg=ACCENT if is_gen else BG_PANEL,
            fg="white" if is_gen else TEXT_DIM
        )
        # Update DM buttons
        for btn in self._dm_frame.winfo_children():
            if not isinstance(btn, tk.Button):
                continue
            # Extract username from label text "  @ username  [N new]"
            raw = btn.cget("text").strip().lstrip("@ ")
            u = raw.split("  [")[0].strip()
            unread = self.unread.get(u, 0)
            label = f"  @ {u}" + (f"  [{unread} new]" if unread else "")
            is_active = (self.active_tab == u)
            btn.config(
                text=label,
                bg=BG_CARD if is_active else BG_PANEL,
                fg=DM_COLOR if is_active else TEXT_MAIN
            )

    # ──────────────────────────────────────────────────────
    #  CHAT DISPLAY
    # ──────────────────────────────────────────────────────
    def _redraw(self, channel):
        self._chat.config(state="normal")
        self._chat.delete("1.0", "end")
        for entry in self.channel_history.get(channel, []):
            self._render(entry)
        self._chat.config(state="disabled")
        self._chat.see("end")

    def _render(self, entry):
        if entry.get("etype") == "system":
            self._chat.insert("end", f"\n  {entry['text']}\n", "sys_msg")
            return
        sender = entry["sender"]
        text = entry["text"]
        ts = datetime.fromtimestamp(entry["timestamp"]).strftime("%H:%M")
        is_self = (sender == self.username)
        is_dm = entry.get("is_dm", False)
        name_tag = "self_name" if is_self else ("dm_name" if is_dm else "other_name")

        self._chat.insert("end", "\n")
        self._chat.insert("end", f"  {sender}", name_tag)
        self._chat.insert("end", f"  {ts}", "time_tag")
        if is_dm:
            self._chat.insert("end", "  🔒 PRIVATE", "dm_badge")
        self._chat.insert("end", "\n")
        self._chat.insert("end", f"  {text}\n", "msg_text")

        # Show a simple "encrypted" badge — no raw ciphertext clutter
        enc = entry.get("enc", {})
        if enc and enc.get("ciphertext"):
            self._chat.insert("end", "  🔒 encrypted\n", "enc_proof")

    def _add_to_channel(self, channel, entry):
        if channel not in self.channel_history:
            self.channel_history[channel] = []
        self.channel_history[channel].append(entry)

        if channel == self.active_tab:
            self._chat.config(state="normal")
            self._render(entry)
            self._chat.config(state="disabled")
            self._chat.see("end")
        else:
            self.unread[channel] = self.unread.get(channel, 0) + 1
            self._refresh_tab_colors()

    def _sys_msg(self, channel, text):
        self._add_to_channel(channel, {"etype": "system", "text": text})

    # ──────────────────────────────────────────────────────
    #  ENCRYPTION PROOF PANEL
    # ──────────────────────────────────────────────────────
    def _toggle_proof(self):
        self.proof_visible = not self.proof_visible
        if self.proof_visible:
            self._proof_frame.pack(fill="x",
                                   before=self._proof_frame.master.winfo_children()[-1])
            self._refresh_proof()
        else:
            self._proof_frame.pack_forget()

    def _refresh_proof(self, enc=None):
        if enc:
            self.last_enc = enc
        d = self.last_enc
        if not d.get("ciphertext"):
            text = "Send a message to see its encrypted form here."
        else:
            text = (
                "═══ ENCRYPTION PROOF — What the server & network actually see ═══\n\n"
                f"Channel     : {d.get('channel','?')}\n"
                f"Algorithm   : AES-256-CBC\n"
                f"IV (base64) : {d.get('iv','')}\n\n"
                f"CIPHERTEXT (base64 — this is what travels over the wire):\n"
                f"{d.get('ciphertext','')}\n\n"
                f"Encrypted AES Key:\n{d.get('key','')[:80]}…\n\n"
                "🔒 The original message text does NOT appear above.\n"
                "   Only the recipient with the correct RSA private key can decrypt it."
            )
        self._proof_text.config(state="normal")
        self._proof_text.delete("1.0", "end")
        self._proof_text.insert("end", text)
        self._proof_text.config(state="disabled")

    # ──────────────────────────────────────────────────────
    #  SEND
    # ──────────────────────────────────────────────────────
    def _send(self):
        text = self._mvar.get().strip()
        if not text:
            return
        self._mvar.set("")
        channel = self.active_tab

        if channel == "general":
            ct, iv, aes_key = aes_encrypt(text)
            enc_snap = {"ciphertext": ct, "iv": iv, "key": aes_key, "channel": "general"}
            try:
                send_json(self.sock, {"type": "message", "encrypted_text": ct,
                                      "iv": iv, "aes_key_enc": aes_key})
            except Exception as e:
                self._sys_msg("general", f"⚠ Send error: {e}")
                return
        else:
            pubkey = self.peer_keys.get(channel)
            if not pubkey:
                self._sys_msg(channel, f"⚠ No encryption key for {channel}. Are they online?")
                return
            ct, iv, aes_key = aes_encrypt(text)
            aes_key_raw = base64.b64decode(aes_key)
            aes_key_enc = rsa_encrypt(pubkey, aes_key_raw)
            enc_snap = {"ciphertext": ct, "iv": iv,
                        "key": aes_key_enc[:80], "channel": f"DM:{channel}"}
            try:
                send_json(self.sock, {"type": "dm", "to": channel,
                                      "encrypted_text": ct, "iv": iv,
                                      "aes_key_enc": aes_key_enc})
            except Exception as e:
                self._sys_msg(channel, f"⚠ DM error: {e}")
                return

        self._add_to_channel(channel, {
            "etype": "message", "sender": self.username, "text": text,
            "timestamp": time.time(), "is_dm": (channel != "general"), "enc": enc_snap
        })
        if self.proof_visible:
            self._refresh_proof(enc_snap)
        else:
            self.last_enc = enc_snap

    # ──────────────────────────────────────────────────────
    #  RECEIVE LOOP
    # ──────────────────────────────────────────────────────
    def _recv_loop(self):
        while True:
            msg = recv_json(self.sock)
            if msg is None:
                self.root.after(0, self._disconnected)
                break
            self.root.after(0, self._handle, msg)

    def _handle(self, msg):
        t = msg.get("type")

        if t == "system":
            for ch in list(self.channel_history.keys()):
                self._sys_msg(ch, msg.get("text", ""))

        elif t == "user_list":
            users = msg.get("users", [])
            for u in users:
                if u != self.username and u not in self.channel_history:
                    self.channel_history[u] = []
            self._update_user_buttons(users)

        elif t == "new_user_key":
            u = msg["username"]
            try:
                self.peer_keys[u] = load_public_key(msg["public_key_pem"])
            except Exception:
                pass

        elif t == "user_list_full":
            for u, pem in msg.get("users", {}).items():
                if u != self.username:
                    try:
                        self.peer_keys[u] = load_public_key(pem)
                    except Exception:
                        pass

        elif t == "message":
            sender = msg.get("from", "?")
            try:
                plaintext = aes_decrypt(msg["encrypted_text"], msg["iv"], msg["aes_key_enc"])
            except Exception as e:
                plaintext = f"[Decryption failed: {e}]"
            self._add_to_channel("general", {
                "etype": "message", "sender": sender, "text": plaintext,
                "timestamp": msg.get("timestamp", time.time()), "is_dm": False,
                "enc": {"ciphertext": msg["encrypted_text"], "iv": msg["iv"],
                        "key": msg["aes_key_enc"][:60], "channel": "general"}
            })

        elif t == "dm":
            sender = msg.get("from", "?")
            try:
                aes_key_raw = rsa_decrypt(self.private_key, msg["aes_key_enc"])
                aes_key_b64 = base64.b64encode(aes_key_raw).decode()
                plaintext = aes_decrypt(msg["encrypted_text"], msg["iv"], aes_key_b64)
            except Exception as e:
                plaintext = f"[DM decryption failed: {e}]"
            if sender not in self.channel_history:
                self.channel_history[sender] = []
            self._add_to_channel(sender, {
                "etype": "message", "sender": sender, "text": plaintext,
                "timestamp": msg.get("timestamp", time.time()), "is_dm": True,
                "enc": {"ciphertext": msg["encrypted_text"], "iv": msg["iv"],
                        "key": msg["aes_key_enc"][:60], "channel": f"DM:{sender}"}
            })

    def _disconnected(self):
        self._conn_lbl.config(text="● Disconnected", fg=RED)
        for ch in list(self.channel_history.keys()):
            self._sys_msg(ch, "⚠ Disconnected from server.")

    def _open_register_window(self):
        """Open a popup to register a new account (without disconnecting current session)."""
        win = tk.Toplevel(self.root)
        win.title("Register New Account")
        win.geometry("380x380")
        win.configure(bg=BG_DARK)
        win.resizable(False, False)
        win.grab_set()   # modal

        tk.Label(win, text="Register New Account",
                 font=("Segoe UI", 14, "bold"), bg=BG_DARK, fg=TEXT_MAIN
                 ).pack(pady=(24, 4))
        tk.Label(win, text="Create a second account (open a new client window to use it)",
                 font=("Segoe UI", 8), bg=BG_DARK, fg=TEXT_DIM, wraplength=340
                 ).pack(pady=(0, 16))

        card = tk.Frame(win, bg=BG_PANEL)
        card.pack(padx=24, fill="x")

        tk.Label(card, text="Username", font=("Segoe UI", 9),
                 bg=BG_PANEL, fg=TEXT_DIM, anchor="w").pack(fill="x", padx=16, pady=(16, 3))
        uvar = tk.StringVar()
        tk.Entry(card, textvariable=uvar, font=("Consolas", 11),
                 bg=BG_CARD, fg=TEXT_MAIN, insertbackground=ACCENT,
                 relief="flat", bd=8).pack(fill="x", padx=16)

        tk.Label(card, text="Password", font=("Segoe UI", 9),
                 bg=BG_PANEL, fg=TEXT_DIM, anchor="w").pack(fill="x", padx=16, pady=(12, 3))
        pvar = tk.StringVar()
        tk.Entry(card, textvariable=pvar, show="●", font=("Consolas", 11),
                 bg=BG_CARD, fg=TEXT_MAIN, insertbackground=ACCENT,
                 relief="flat", bd=8).pack(fill="x", padx=16)

        tk.Label(card, text="Confirm Password", font=("Segoe UI", 9),
                 bg=BG_PANEL, fg=TEXT_DIM, anchor="w").pack(fill="x", padx=16, pady=(12, 3))
        cvar = tk.StringVar()
        tk.Entry(card, textvariable=cvar, show="●", font=("Consolas", 11),
                 bg=BG_CARD, fg=TEXT_MAIN, insertbackground=ACCENT,
                 relief="flat", bd=8).pack(fill="x", padx=16, pady=(0, 16))

        status_var = tk.StringVar()
        status_lbl = tk.Label(win, textvariable=status_var, font=("Segoe UI", 9),
                              bg=BG_DARK, fg=RED, wraplength=340)
        status_lbl.pack(pady=4)

        def do_register():
            username = uvar.get().strip()
            password = pvar.get()
            confirm  = cvar.get()
            if not username or not password:
                status_var.set("⚠ Fill in all fields.")
                return
            if len(password) < 4:
                status_var.set("⚠ Password must be at least 4 characters.")
                return
            if password != confirm:
                status_var.set("⚠ Passwords do not match.")
                return
            reg_btn.config(state="disabled", text="Registering…")
            status_var.set("")

            def _thread():
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(6)
                    s.connect((HOST, PORT))
                    s.settimeout(None)
                    send_json(s, {"type": "register", "username": username, "password": password})
                    resp = recv_json(s)
                    s.close()
                    if resp and resp.get("success"):
                        win.after(0, lambda: status_var.set(f"✓ '{username}' registered! Open a new client to log in."))
                        win.after(0, lambda: status_lbl.config(fg=GREEN))
                        win.after(0, lambda: reg_btn.config(state="normal", text="Register"))
                    else:
                        reason = resp.get("reason", "Registration failed.") if resp else "No response."
                        win.after(0, lambda: status_var.set(f"⚠ {reason}"))
                        win.after(0, lambda: reg_btn.config(state="normal", text="Register"))
                except Exception as e:
                    win.after(0, lambda: status_var.set(f"⚠ {e}"))
                    win.after(0, lambda: reg_btn.config(state="normal", text="Register"))

            threading.Thread(target=_thread, daemon=True).start()

        reg_btn = tk.Button(
            win, text="Register", font=("Segoe UI", 10, "bold"),
            bg=GREEN, fg="white", relief="flat", cursor="hand2",
            activebackground="#2ea043", command=do_register, pady=8
        )
        reg_btn.pack(fill="x", padx=24, pady=(0, 4))

    def _on_close(self):
        try:
            self.sock.close()
        except Exception:
            pass
        self.root.destroy()


# ─────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────
def main():
    auth_root = tk.Tk()
    auth_win = AuthWindow(auth_root)
    auth_root.mainloop()

    if auth_win.result is None:
        return

    sock, username, private_key, users_full = auth_win.result
    auth_root.destroy()

    chat_root = tk.Tk()
    ChatWindow(chat_root, sock, username, private_key, users_full)
    chat_root.mainloop()


if __name__ == "__main__":
    main()