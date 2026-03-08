"""
=============================================================
  SECURE CHAT SERVER  |  server.py
  Features: Registration, Login, Broadcast, Private DMs
=============================================================
"""

import socket
import threading
import json
import hashlib
import os
import time
from queue import Queue

# ─────────────────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────────────────
HOST = "127.0.0.1"
PORT = 65432
USER_DB_FILE = "users.json"

# ─────────────────────────────────────────────────────────
#  USER DATABASE  (persisted to users.json on disk)
# ─────────────────────────────────────────────────────────
db_lock = threading.Lock()

def load_user_db() -> dict:
    if os.path.exists(USER_DB_FILE):
        with open(USER_DB_FILE, "r") as f:
            return json.load(f)
    return {}

def save_user_db(db: dict):
    with open(USER_DB_FILE, "w") as f:
        json.dump(db, f, indent=2)

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# ─────────────────────────────────────────────────────────
#  SERVER STATE
# ─────────────────────────────────────────────────────────
clients = {}         # username → {'socket': sock, 'public_key_pem': str}
clients_lock = threading.Lock()
message_queue = Queue()

# ─────────────────────────────────────────────────────────
#  SOCKET HELPERS
# ─────────────────────────────────────────────────────────
def send_json(sock, data: dict):
    try:
        payload = json.dumps(data).encode("utf-8")
        sock.sendall(len(payload).to_bytes(4, "big") + payload)
    except Exception as e:
        print(f"[SEND ERROR] {e}")

def recv_json(sock):
    try:
        raw_len = _recv_exact(sock, 4)
        if not raw_len:
            return None
        raw = _recv_exact(sock, int.from_bytes(raw_len, "big"))
        return json.loads(raw.decode("utf-8")) if raw else None
    except Exception as e:
        print(f"[RECV ERROR] {e}")
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
#  BROADCAST HELPERS
# ─────────────────────────────────────────────────────────
def broadcast_user_list():
    with clients_lock:
        online = list(clients.keys())
        targets = dict(clients)
    for info in targets.values():
        try:
            send_json(info["socket"], {"type": "user_list", "users": online})
        except Exception:
            pass

def broadcast_system(text, exclude=None):
    msg = {"type": "system", "text": text, "timestamp": time.time()}
    with clients_lock:
        targets = {u: c for u, c in clients.items() if u != exclude}
    for info in targets.values():
        try:
            send_json(info["socket"], msg)
        except Exception:
            pass

# ─────────────────────────────────────────────────────────
#  BROADCAST WORKER  (Queue consumer thread)
# ─────────────────────────────────────────────────────────
def broadcast_worker():
    while True:
        item = message_queue.get()
        if item is None:
            break
        target, payload = item

        if target == "__all__":
            sender = payload.get("from", "")
            with clients_lock:
                targets = {u: c for u, c in clients.items() if u != sender}
            for info in targets.values():
                try:
                    send_json(info["socket"], payload)
                except Exception:
                    pass
        else:
            # Direct message: send only to target
            with clients_lock:
                info = clients.get(target)
            if info:
                try:
                    send_json(info["socket"], payload)
                except Exception:
                    pass

        message_queue.task_done()

# ─────────────────────────────────────────────────────────
#  CLIENT HANDLER THREAD
# ─────────────────────────────────────────────────────────
def handle_client(conn, addr):
    username = None
    try:
        # ── Step 1: Register or Login ────────────────────
        auth = recv_json(conn)
        if not auth or auth.get("type") not in ("auth", "login", "register"):
            send_json(conn, {"type": "auth_result", "success": False, "reason": "Bad packet"})
            conn.close()
            return

        username = auth.get("username", "").strip()
        password = auth.get("password", "")

        if not username or not password:
            send_json(conn, {"type": "auth_result", "success": False, "reason": "Empty username or password"})
            conn.close()
            return

        with db_lock:
            user_db = load_user_db()

            if auth["type"] == "register":
                if username in user_db:
                    send_json(conn, {"type": "auth_result", "success": False,
                                     "reason": f"Username '{username}' is already taken."})
                    conn.close()
                    return
                user_db[username] = hash_password(password)
                save_user_db(user_db)
                print(f"[REGISTER] New user registered: {username}")

            else:  # login
                if username not in user_db:
                    send_json(conn, {"type": "auth_result", "success": False,
                                     "reason": "Username not found. Please register first."})
                    conn.close()
                    return
                if user_db[username] != hash_password(password):
                    send_json(conn, {"type": "auth_result", "success": False,
                                     "reason": "Incorrect password."})
                    conn.close()
                    return

        # Prevent duplicate logins
        with clients_lock:
            if username in clients:
                send_json(conn, {"type": "auth_result", "success": False,
                                 "reason": "This account is already logged in."})
                conn.close()
                return

        send_json(conn, {"type": "auth_result", "success": True})
        print(f"[AUTH] {username} authenticated from {addr}")

        # ── Step 2: RSA Public Key Exchange ─────────────
        key_msg = recv_json(conn)
        if not key_msg or key_msg.get("type") != "public_key":
            conn.close()
            return

        pubkey_pem = key_msg["key"]

        with clients_lock:
            clients[username] = {"socket": conn, "public_key_pem": pubkey_pem}

        # Send full user list (with public keys) to the new client
        with clients_lock:
            online_info = {u: c["public_key_pem"] for u, c in clients.items()}
        send_json(conn, {"type": "user_list_full", "users": online_info})

        # Tell all existing users about the new user's public key
        with clients_lock:
            others = {u: c for u, c in clients.items() if u != username}
        for info in others.values():
            try:
                send_json(info["socket"], {
                    "type": "new_user_key",
                    "username": username,
                    "public_key_pem": pubkey_pem
                })
            except Exception:
                pass

        broadcast_system(f"🔒 {username} joined the secure chat", exclude=username)
        broadcast_user_list()
        print(f"[ONLINE] {username}. Online: {list(clients.keys())}")

        # ── Step 3: Message Loop ─────────────────────────
        while True:
            msg = recv_json(conn)
            if msg is None:
                break

            mtype = msg.get("type")

            if mtype == "message":
                # General broadcast
                payload = {
                    "type": "message",
                    "from": username,
                    "channel": "general",
                    "encrypted_text": msg["encrypted_text"],
                    "iv": msg["iv"],
                    "aes_key_enc": msg["aes_key_enc"],
                    "timestamp": time.time()
                }
                message_queue.put(("__all__", payload))
                print(f"[BROADCAST] {username} → everyone")

            elif mtype == "dm":
                to_user = msg.get("to", "")
                with clients_lock:
                    is_online = to_user in clients

                if not is_online:
                    send_json(conn, {
                        "type": "system",
                        "text": f"⚠ {to_user} is not online right now.",
                        "timestamp": time.time()
                    })
                    continue

                payload = {
                    "type": "dm",
                    "from": username,
                    "to": to_user,
                    "encrypted_text": msg["encrypted_text"],
                    "iv": msg["iv"],
                    "aes_key_enc": msg["aes_key_enc"],  # AES key encrypted with recipient's RSA pubkey
                    "timestamp": time.time()
                }
                message_queue.put((to_user, payload))
                print(f"[DM] {username} → {to_user}")

    except Exception as e:
        print(f"[ERROR] {username or addr}: {e}")
    finally:
        if username:
            with clients_lock:
                clients.pop(username, None)
            broadcast_system(f"🔓 {username} left the chat")
            broadcast_user_list()
            print(f"[OFFLINE] {username} disconnected")
        conn.close()

# ─────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────
def main():
    threading.Thread(target=broadcast_worker, daemon=True).start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(20)

    db = load_user_db()
    print(f"╔══════════════════════════════════════════╗")
    print(f"║       SECURE CHAT SERVER STARTED         ║")
    print(f"╠══════════════════════════════════════════╣")
    print(f"║  Listening  {HOST}:{PORT}                 ║")
    print(f"║  Registered users: {len(db):<22}║")
    print(f"║  Register freely — any username/password ║")
    print(f"╚══════════════════════════════════════════╝")

    try:
        while True:
            conn, addr = server.accept()
            print(f"[CONNECTION] {addr}")
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")
    finally:
        message_queue.put(None)
        server.close()

if __name__ == "__main__":
    main()