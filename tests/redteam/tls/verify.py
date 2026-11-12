"""Checks a server certificate the way a Python `ssl` (OpenSSL) client does (RT-SEC-10, Task 9a-2).

Usage:
  verify.py memory <ca.pem> <chain.pem> <key.pem> <name>
      A TLS server holding chain.pem and key.pem and a client trusting ca.pem alone shake hands
      through memory BIOs, in process: no socket, no listener.
  verify.py live <dir> <ca.pem> <host> <name>
      CONNECT <host>:443 through <dir>/net.sock (reached through an open descriptor of <dir>, as
      the path may be longer than sun_path allows), then TLS verifying for <name> against ca.pem.

The client is ssl.create_default_context(cafile=ca.pem): hostname checks on, no system roots.
Exit 0: verified; 1: refused (the reason on stderr); 2: usage error.
"""

import os
import socket
import ssl
import sys

MAX_ROUNDS = 50
HEAD_LIMIT = 8192


def client_context(ca: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca)
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


def memory(ca: str, chain: str, key: str, name: str) -> None:
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(chain, key)
    c_in, c_out, s_in, s_out = (ssl.MemoryBIO() for _ in range(4))
    client = client_context(ca).wrap_bio(c_in, c_out, server_hostname=name)
    server = server_ctx.wrap_bio(s_in, s_out, server_side=True)
    done = [False, False]
    for _ in range(MAX_ROUNDS):
        for i, end in enumerate((client, server)):
            if not done[i]:
                try:
                    end.do_handshake()
                    done[i] = True
                except ssl.SSLWantReadError:
                    pass
        s_in.write(c_out.read())
        c_in.write(s_out.read())
        if all(done):
            return
    raise RuntimeError("the handshake did not finish")


def live(directory: str, ca: str, host: str, name: str) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect(f"/proc/self/fd/{fd}/net.sock")
    finally:
        os.close(fd)
    with sock:
        sock.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
        head = b""
        while not head.endswith(b"\r\n\r\n"):
            byte = sock.recv(1)
            if not byte or len(head) > HEAD_LIMIT:
                raise RuntimeError(f"no CONNECT reply: {head!r}")
            head += byte
        if not head.startswith(b"HTTP/1.1 200 "):
            raise RuntimeError(f"CONNECT refused: {head!r}")
        with client_context(ca).wrap_socket(sock, server_hostname=name):
            pass


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 6 and argv[1] == "memory":
            memory(argv[2], argv[3], argv[4], argv[5])
        elif len(argv) == 6 and argv[1] == "live":
            live(argv[2], argv[3], argv[4], argv[5])
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except (ssl.SSLError, OSError, RuntimeError) as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
