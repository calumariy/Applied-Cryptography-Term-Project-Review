"""
Modified malleable version of server.py for use in benchmark parameter optimisations
Must be run before doing any operation using the DGSP_with_server folder.

bench_server.py — DGSP Manager Server

Listens for member connections and drives the join protocol (manager side).
The Manager object (manager.py) owns all cryptographic state; this file only
handles networking and message framing.

Wire protocol (newline-delimited JSON, UTF-8):

  JOIN REQUEST   →  {"cmd": "JOIN", "username": "<name>"}
  JOIN RESPONSE  ←  {"cmd": "JOIN_OK",  "id": <int>, "cstar_id": "<hex>"}
                 ←  {"cmd": "JOIN_ERR", "reason": "<text>"}

  CERT REQUEST   →  {"cmd": "CERT_REQ", "id": <int>, "cstar_id": "<hex>",
                                         "pub_keys": ["<hex>", ...]}
  CERT RESPONSE  ←  {"cmd": "CERT_OK",  "certs": [
                         {"zeta": "<hex>", "pi": "<hex>", "sigma_s": "<hex>"}, ...
                     ]}
                 ←  {"cmd": "CERT_ERR", "reason": "<text>"}

  PK REQUEST     →  {"cmd": "GET_PK"}
  PK RESPONSE    ←  {"cmd": "PK", "pk": "<hex>"}

ADDED PROTOCOLS
  
  OPEN

  REVOKE

  Usage: python server.py <host> <port> [n] [w] [h] [d] [k] [t]
  Has in built defaults for easier use in case n, w, h, d, k or t are
  not initialised.
Run:
    python bench_server_alpha.py 127.0.0.1 65432
"""

import sys
import os
import json
import socket
import threading
import traceback
from typing import Optional
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from DGSP.manager import Manager
from params.sphincs_params_Alpha import SphincsParamsAlpha


# ---------------------------------------------------------------------------
# Globals  (one manager, shared across all threads)
# ---------------------------------------------------------------------------

_manager: Manager
_manager_lock = threading.Lock()
_pk_hex: str = ""          # serialised PK broadcast to members on request

# ---------------------------------------------------------------------------
# Message framing  (newline-delimited JSON)
# ---------------------------------------------------------------------------

def send_msg(conn: socket.socket, obj: dict) -> None:
    """Serialise obj to JSON and send as a single newline-terminated line."""
    line = json.dumps(obj) + "\n"
    conn.sendall(line.encode("utf-8"))


def recv_msg(conn: socket.socket) -> Optional[dict]:
    """
    Read one newline-terminated JSON message from conn.
    Returns None on EOF / disconnect.
    Raises ValueError on malformed JSON.
    """
    buf = b""
    while b"\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        buf += chunk
    line, _ = buf.split(b"\n", 1)
    return json.loads(line.decode("utf-8"))


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def handle_get_pk(conn: socket.socket) -> None:
    send_msg(conn, {"cmd": "PK", "pk": _pk_hex})


def handle_join(conn: socket.socket, msg: dict) -> None:
    username = msg.get("username", "").strip()
    if not username:
        send_msg(conn, {"cmd": "JOIN_ERR", "reason": "Missing username"})
        return

    try:
        with _manager_lock:
            user_id, cstar_id = _manager.join(username)
        send_msg(conn, {
            "cmd":      "JOIN_OK",
            "id":       user_id,
            "cstar_id": cstar_id.hex(),
        })
        print(f"[JOIN] '{username}' assigned id={user_id}")

    except ValueError as e:
        send_msg(conn, {"cmd": "JOIN_ERR", "reason": str(e)})
    except Exception as e:
        send_msg(conn, {"cmd": "JOIN_ERR", "reason": f"Internal error: {e}"})
        traceback.print_exc()


def handle_cert_req(conn: socket.socket, msg: dict) -> None:
    try:
        user_id  = int(msg["id"])
        cstar_id = bytes.fromhex(msg["cstar_id"])
        pub_keys = [bytes.fromhex(pk) for pk in msg["pub_keys"]]
    except (KeyError, ValueError) as e:
        send_msg(conn, {"cmd": "CERT_ERR", "reason": f"Bad request fields: {e}"})
        return

    if not pub_keys:
        send_msg(conn, {"cmd": "CERT_ERR", "reason": "Empty pub_keys list"})
        return
            
    try:
        with _manager_lock:
            certs = _manager.response_m(user_id, cstar_id, pub_keys)

        cert_list = [
            {
                "zeta":    zeta.hex(),
                "pi":      pi.hex(),
                "sigma_s": sigma_s.hex(),
            }
            for (zeta, pi, sigma_s) in certs
        ]

        send_msg(conn, {"cmd": "CERT_OK", "certs": cert_list})
        print(f"[CERT] Issued {len(certs)} cert(s) for id={user_id}")

    except PermissionError as e:
        send_msg(conn, {"cmd": "CERT_ERR", "reason": str(e)})
    except KeyError as e:
        send_msg(conn, {"cmd": "CERT_ERR", "reason": f"Unknown user: {e}"})
    except Exception as e:
        send_msg(conn, {"cmd": "CERT_ERR", "reason": f"Internal error: {e}"})
        traceback.print_exc()


# ---------------------------------------------------------------------------
# Per-connection handler
# ---------------------------------------------------------------------------

def handle_client(conn: socket.socket, addr) -> None:
    """
    Dispatch incoming messages from one client connection.
    Each connection handles exactly one logical request then closes,
    keeping the protocol stateless at the transport layer.
    """
    print(f"[CONNECT] {addr}")
    try:
        msg = recv_msg(conn)
        if msg is None:
            print(f"[DISCONNECT] {addr} sent nothing")
            return

        cmd = msg.get("cmd", "")

        if cmd == "GET_PK":
            handle_get_pk(conn)

        elif cmd == "JOIN":
            handle_join(conn, msg)

        elif cmd == "CERT_REQ":
            handle_cert_req(conn, msg)
            
        elif cmd == "OPEN":
            handle_open(conn, msg)
        elif cmd == "REVOKE":
            handle_revoke(conn, msg)
        else:
            send_msg(conn, {"cmd": "ERR", "reason": f"Unknown command: '{cmd}'"})

    except json.JSONDecodeError as e:
        print(f"[ERROR] Malformed JSON from {addr}: {e}")
    except Exception as e:
        print(f"[ERROR] Unhandled exception for {addr}: {e}")
        traceback.print_exc()
    finally:
        conn.close()
        print(f"[CLOSE] {addr}")


def handle_open(conn: socket.socket, msg: dict) -> None:
    try:
        raw_msg  = bytes.fromhex(msg["msg"])
        sigma_w  = bytes.fromhex(msg["sigma_w"])
        counter  = bytes.fromhex(msg["counter"])
        rho      = bytes.fromhex(msg["rho"])
        zeta     = bytes.fromhex(msg["zeta"])
        sigma_s  = bytes.fromhex(msg["sigma_s"])
        tau      = bytes.fromhex(msg["tau"])
        sig      = (sigma_w, counter, rho, zeta, sigma_s, tau)
    except (KeyError, ValueError) as e:
        send_msg(conn, {"cmd": "OPEN_ERR", "reason": f"Bad request fields: {e}"})
        return
 
    try:
        with _manager_lock:
            user_id, pi = _manager.open(raw_msg, sig)
 
        send_msg(conn, {
            "cmd":     "OPEN_OK",
            "user_id": user_id,
            "pi":      pi.hex(),
        })
        print(f"[OPEN] Traced signature to id={user_id}")
 
    except Exception as e:
        send_msg(conn, {"cmd": "OPEN_ERR", "reason": f"Internal error: {e}"})
        traceback.print_exc()

def handle_revoke(conn: socket.socket, msg: dict) -> None:
    try:
        ids = msg.get("ids", None)
        if ids is None or not isinstance(ids, list):
            raise ValueError("Missing or invalid 'ids' field")

        # all ids become ints
        ids_to_revoke = [int(i) for i in ids]

    except (ValueError, TypeError) as e:
        send_msg(conn, {"cmd": "REVOKE_ERR", "reason": f"Bad request fields: {e}"})
        return

    try:
        with _manager_lock:
            rl = _manager.revoke(ids_to_revoke)

        # serialise RL (list of bytes → hex)
        rl_hex = [z.hex() for z in rl]

        send_msg(conn, {
            "cmd": "REVOKE_OK",
            "rl": rl_hex
        })

        print(f"[REVOKE] Revoked users: {ids_to_revoke} | RL size={len(rl_hex)}")

    except Exception as e:
        send_msg(conn, {"cmd": "REVOKE_ERR", "reason": f"Internal error: {e}"})
        traceback.print_exc()
        

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    global _manager, _pk_hex

    if len(sys.argv) < 3:
        print("Usage: python server.py <host> <port> [n] [w] [h] [d] [k] [t]")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    # ---- Initialise manager ----
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 16
    w = int(sys.argv[4]) if len(sys.argv) > 4 else 16
    h = int(sys.argv[5]) if len(sys.argv) > 5 else 6
    d = int(sys.argv[6]) if len(sys.argv) > 6 else 2
    k = int(sys.argv[7]) if len(sys.argv) > 7 else 4
    t = int(sys.argv[8]) if len(sys.argv) > 8 else 8
    params   = SphincsParamsAlpha(n=n, w=w, h=h, d=d, k=k, t=t)
    _manager = Manager(params)
    pk_bytes = _manager.keygen()
    _pk_hex  = pk_bytes.hex()
    print(f"[KEYGEN] Manager key generation complete. gpk = {_manager.gpk.hex()[:32]}…")

    # ---- Open server socket ----
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((host, port))
    except OSError as e:
        print(f"[ERROR] Cannot bind to {host}:{port} — {e}")
        sys.exit(1)

    server.listen()
    print(f"[LISTEN] Manager server listening on {host}:{port}")

    try:
        while True:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[SHUTDOWN] Keyboard interrupt — stopping server")
    finally:
        server.close()


if __name__ == "__main__":
    main()