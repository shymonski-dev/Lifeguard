from __future__ import annotations

import os
import select
import socket
import socketserver
from urllib.parse import urlsplit


def _parse_allowed_hosts() -> tuple[str, ...]:
    raw = os.getenv("LIFEGUARD_ALLOWED_HOSTS", "")
    hosts = [item.strip().lower().rstrip(".") for item in raw.split(",")]
    return tuple(item for item in hosts if item)


def _parse_allowed_ports() -> tuple[int, ...]:
    raw = os.getenv("LIFEGUARD_ALLOWED_EGRESS_PORTS", "80,443")
    ports: list[int] = []
    for item in raw.split(","):
        cleaned = item.strip()
        if not cleaned:
            continue
        try:
            port = int(cleaned)
        except ValueError:
            continue
        if 1 <= port <= 65535:
            ports.append(port)
    if not ports:
        ports = [80, 443]
    deduped: list[int] = []
    seen: set[int] = set()
    for port in ports:
        if port in seen:
            continue
        seen.add(port)
        deduped.append(port)
    return tuple(deduped)


ALLOWED_HOSTS = _parse_allowed_hosts()
ALLOWED_PORTS = set(_parse_allowed_ports())
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.getenv("LIFEGUARD_PROXY_PORT", "3128"))
IO_TIMEOUT_SECONDS = 30


def _is_host_allowed(host: str) -> bool:
    candidate = host.strip().lower().rstrip(".")
    if not candidate:
        return False
    for allowed in ALLOWED_HOSTS:
        if allowed == "*":
            return True
        if allowed.startswith("*."):
            suffix = allowed[2:]
            if candidate == suffix or candidate.endswith("." + suffix):
                return True
            continue
        if candidate == allowed or candidate.endswith("." + allowed):
            return True
    return False


def _parse_host_and_port(value: str, default_port: int) -> tuple[str, int] | None:
    cleaned = value.strip()
    if not cleaned:
        return None
    if cleaned.startswith("[") and "]" in cleaned:
        host_part, _, tail = cleaned.partition("]")
        host = host_part.lstrip("[").strip()
        if not host:
            return None
        port = default_port
        if tail.startswith(":"):
            try:
                port = int(tail[1:])
            except ValueError:
                return None
        return host, port

    if ":" in cleaned and cleaned.count(":") == 1:
        host, port_text = cleaned.split(":", 1)
        host = host.strip()
        try:
            port = int(port_text.strip())
        except ValueError:
            return None
        if not host:
            return None
        return host, port

    return cleaned, default_port


def _read_headers(client: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = client.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


class _ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client = self.request
        assert isinstance(client, socket.socket)
        client.settimeout(IO_TIMEOUT_SECONDS)

        raw_request = _read_headers(client)
        if not raw_request:
            return

        try:
            header_text = raw_request.decode("iso-8859-1")
        except UnicodeDecodeError:
            self._send_error(400, "Invalid request encoding.")
            return

        lines = header_text.split("\r\n")
        if not lines or not lines[0].strip():
            self._send_error(400, "Missing request line.")
            return

        parts = lines[0].split(" ", 2)
        if len(parts) != 3:
            self._send_error(400, "Malformed request line.")
            return

        method = parts[0].upper()
        target = parts[1]
        version = parts[2]

        if method == "CONNECT":
            self._handle_connect(target=target)
            return

        self._handle_http_forward(
            method=method,
            target=target,
            version=version,
            header_lines=lines[1:],
            raw_request=raw_request,
        )

    def _handle_connect(self, *, target: str) -> None:
        parsed = _parse_host_and_port(target, 443)
        if parsed is None:
            self._send_error(400, "Invalid CONNECT target.")
            return
        host, port = parsed
        if not _is_host_allowed(host):
            self._send_error(403, "Host is not allowed by policy.")
            return
        if port not in ALLOWED_PORTS:
            self._send_error(403, "Port is not allowed by policy.")
            return

        try:
            remote = socket.create_connection((host, port), timeout=10)
        except OSError:
            self._send_error(502, "Failed to reach upstream host.")
            return

        with remote:
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self._relay_bidirectional(client=self.request, remote=remote)

    def _handle_http_forward(
        self,
        *,
        method: str,
        target: str,
        version: str,
        header_lines: list[str],
        raw_request: bytes,
    ) -> None:
        host = ""
        port = 80
        outbound_path = target or "/"

        parsed_target = urlsplit(target)
        if parsed_target.scheme and parsed_target.hostname:
            host = parsed_target.hostname
            if parsed_target.scheme.lower() == "https":
                port = 443
            if parsed_target.port is not None:
                port = parsed_target.port
            outbound_path = parsed_target.path or "/"
            if parsed_target.query:
                outbound_path = f"{outbound_path}?{parsed_target.query}"
        else:
            host_header = self._extract_host_header(header_lines)
            if not host_header:
                self._send_error(400, "Missing Host header.")
                return
            parsed_host = _parse_host_and_port(host_header, 80)
            if parsed_host is None:
                self._send_error(400, "Invalid Host header.")
                return
            host, port = parsed_host

        if not _is_host_allowed(host):
            self._send_error(403, "Host is not allowed by policy.")
            return
        if port not in ALLOWED_PORTS:
            self._send_error(403, "Port is not allowed by policy.")
            return

        try:
            remote = socket.create_connection((host, port), timeout=10)
        except OSError:
            self._send_error(502, "Failed to reach upstream host.")
            return

        header_end = raw_request.find(b"\r\n\r\n")
        body = b""
        if header_end != -1:
            body = raw_request[header_end + 4 :]

        outbound_lines = [f"{method} {outbound_path} {version}"]
        for line in header_lines:
            if not line:
                continue
            lowered = line.lower()
            if lowered.startswith("proxy-connection:"):
                continue
            if lowered.startswith("proxy-authorization:"):
                continue
            outbound_lines.append(line)
        outbound_payload = ("\r\n".join(outbound_lines) + "\r\n\r\n").encode("iso-8859-1")

        with remote:
            remote.sendall(outbound_payload)
            if body:
                remote.sendall(body)
            self._relay_response(client=self.request, remote=remote)

    def _extract_host_header(self, header_lines: list[str]) -> str:
        for line in header_lines:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            if key.strip().lower() == "host":
                return value.strip()
        return ""

    def _relay_bidirectional(self, *, client: socket.socket, remote: socket.socket) -> None:
        sockets = [client, remote]
        while True:
            readable, _, _ = select.select(sockets, [], [], IO_TIMEOUT_SECONDS)
            if not readable:
                return
            for current in readable:
                try:
                    chunk = current.recv(65536)
                except OSError:
                    return
                if not chunk:
                    return
                target = remote if current is client else client
                try:
                    target.sendall(chunk)
                except OSError:
                    return

    def _relay_response(self, *, client: socket.socket, remote: socket.socket) -> None:
        while True:
            try:
                chunk = remote.recv(65536)
            except OSError:
                return
            if not chunk:
                return
            try:
                client.sendall(chunk)
            except OSError:
                return

    def _send_error(self, status_code: int, message: str) -> None:
        reason_lookup = {
            400: "Bad Request",
            403: "Forbidden",
            502: "Bad Gateway",
        }
        reason = reason_lookup.get(status_code, "Error")
        body = (message + "\n").encode("utf-8")
        headers = [
            f"HTTP/1.1 {status_code} {reason}",
            f"Content-Length: {len(body)}",
            "Content-Type: text/plain; charset=utf-8",
            "Connection: close",
            "",
            "",
        ]
        payload = "\r\n".join(headers).encode("utf-8") + body
        try:
            self.request.sendall(payload)
        except OSError:
            return


def main() -> None:
    with _ThreadedServer((LISTEN_HOST, LISTEN_PORT), _ProxyHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
