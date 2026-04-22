import sys
import json
import socket
import threading
import traceback
from typing import Optional

from .manager import Manager
from params.sphincs_params import SphincsParams
from params.sphincs_params_Alpha import SphincsParamsAlpha
from params.sphincs_params_Plus_C import SphincsParamsC  

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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    global _manager, _pk_hex

    if len(sys.argv) != 3:
        print("Usage: python server.py <host> <port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    # ---- Initialise manager ----
    # TODO: adjust these parameters for better security / performance tradeoffs
    # params = SphincsParams(n=16, w=16, h=6, d=2, k=4, t=8)
    params = SphincsParamsAlpha(n=16, w=16, h=6, d=2, k=4, t=8)
    # params = SphincsParamsC(n=16, w=16, h=6, d=2, k=4, t=8, t_prime=16, z=0)
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