"""Read-only external Safehop verification, using only the Python standard library.

Run after activation: python tools/verify-safehop-dns.py
Add --refused-types to check the optional ANY/AXFR/IXFR rejection policy.
ANY requires REFUSED on every transport. AXFR/IXFR require REFUSED on ordinary
DNS/DoT; DoH additionally accepts an empty NOTIMP response because dnsdist 2.1.2
denies DoH transfers before applying Lua query rules.
On Windows, --interface-index selects an outgoing adapter for this process's
public-IP sockets only. It never changes OS routes or disconnects a VPN.
Importing this file performs no networking. No SSH, credentials, services, files,
or application settings are accessed. Only fixed public test domains are queried;
DNS messages and HTTP response bodies are never printed or saved.
"""
from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import hashlib
import http.client
import ipaddress
import json
import re
import secrets
import socket
import ssl
import struct
import sys
from typing import Callable


DOMAIN = "safehop.crabdance.com"
PUBLIC_IPV4 = "150.241.96.191"
LEGACY_DOMAIN = "pecaocek.ignorelist.com"
MAX_WIRE = 65535
MAX_RECORDS = 512
TEST_NAMES = frozenset(("example.com", "dnssec-failed.org"))
QTYPE_A = 1
QTYPE_IXFR = 251
QTYPE_AXFR = 252
QTYPE_ANY = 255
# Microsoft Winsock SDK ws2ipdef.h; Python on Windows may omit this constant.
WINDOWS_IP_UNICAST_IF = 31
INTERFACE_SOURCE_URL = "https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options"


class ProbeError(ValueError):
    """A bounded, fixed diagnostic; never contains server response contents."""


def require(condition: bool, diagnostic: str) -> None:
    if not condition:
        raise ProbeError(diagnostic)


def encode_name(name: str) -> bytes:
    """Encode a safe ASCII DNS hostname with the RFC 1035 size limits."""
    if not isinstance(name, str):
        raise ProbeError("dns_name_type")
    if name == ".":
        return b"\x00"
    name = name[:-1] if name.endswith(".") else name
    require(bool(name), "dns_name_empty")
    labels = name.split(".")
    encoded = bytearray()
    for label in labels:
        require(bool(re.fullmatch(r"[A-Za-z0-9_-]{1,63}", label)), "dns_label_invalid")
        raw = label.encode("ascii")
        encoded.extend(bytes((len(raw),)) + raw)
    encoded.append(0)
    require(len(encoded) <= 255, "dns_name_too_long")
    return bytes(encoded)


def build_query(name: str, *, qid: int | None = None, qtype: int = QTYPE_A) -> bytes:
    """RD set, CD clear, EDNS 1232-byte UDP payload and DNSSEC DO bit set."""
    qid = secrets.randbelow(65536) if qid is None else qid
    require(type(qid) is int and 0 <= qid <= 65535, "dns_qid_invalid")
    require(type(qtype) is int and 1 <= qtype <= 65535, "dns_qtype_invalid")
    header = struct.pack("!6H", qid, 0x0100, 1, 0, 0, 1)
    question = encode_name(name) + struct.pack("!2H", qtype, 1)
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0x00008000, 0)
    return header + question + opt


def decode_name(wire: bytes, start: int) -> tuple[str, int]:
    """Decode bounded names and backwards compression without pointer loops."""
    require(0 <= start < len(wire), "dns_name_out_of_bounds")
    cursor = start
    end = None
    labels = []
    visited = set()
    expanded_length = 1
    while True:
        require(cursor not in visited, "dns_pointer_loop")
        visited.add(cursor)
        require(cursor < len(wire), "dns_name_truncated")
        length = wire[cursor]
        if length & 0xC0 == 0xC0:
            require(cursor + 1 < len(wire), "dns_pointer_truncated")
            target = ((length & 0x3F) << 8) | wire[cursor + 1]
            require(target < cursor, "dns_pointer_not_backward")
            end = cursor + 2 if end is None else end
            cursor = target
            continue
        require(length & 0xC0 == 0, "dns_label_encoding_invalid")
        cursor += 1
        if not length:
            return ".".join(labels).lower(), cursor if end is None else end
        require(cursor + length <= len(wire), "dns_label_truncated")
        expanded_length += length + 1
        require(expanded_length <= 255, "dns_expanded_name_too_long")
        raw = wire[cursor:cursor + length]
        require(all(0x21 <= value <= 0x7E and value != 0x2E for value in raw), "dns_label_non_ascii")
        labels.append(raw.decode("ascii"))
        cursor += length


@dataclass(frozen=True)
class Question:
    name: str
    qtype: int
    qclass: int


@dataclass(frozen=True)
class Record:
    name: str
    rtype: int
    rclass: int
    ttl: int
    data: bytes
    target: str | None = None


@dataclass(frozen=True)
class Message:
    qid: int
    flags: int
    rcode: int
    questions: tuple[Question, ...]
    answers: tuple[Record, ...]
    authority: tuple[Record, ...]
    additional: tuple[Record, ...]


def parse_message(wire: bytes) -> Message:
    """Parse the entire message; reject truncation, excess data and unsafe names."""
    require(isinstance(wire, bytes) and 12 <= len(wire) <= MAX_WIRE, "dns_message_size")
    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack_from("!6H", wire)
    require(qdcount <= 16 and ancount + nscount + arcount <= MAX_RECORDS, "dns_record_count")
    cursor = 12
    questions = []
    for _ in range(qdcount):
        name, cursor = decode_name(wire, cursor)
        require(cursor + 4 <= len(wire), "dns_question_truncated")
        qtype, qclass = struct.unpack_from("!2H", wire, cursor)
        questions.append(Question(name, qtype, qclass))
        cursor += 4
    sections = []
    for count in (ancount, nscount, arcount):
        records = []
        for _ in range(count):
            name, cursor = decode_name(wire, cursor)
            require(cursor + 10 <= len(wire), "dns_record_truncated")
            rtype, rclass, ttl, size = struct.unpack_from("!HHIH", wire, cursor)
            cursor += 10
            end = cursor + size
            require(end <= len(wire), "dns_rdata_truncated")
            data = wire[cursor:end]
            target = None
            if rtype in (2, 5, 12):
                target, target_end = decode_name(wire, cursor)
                require(target_end == end, "dns_rdata_name_length")
            if rtype == 1:
                require(size == 4, "dns_a_rdata_length")
            if rtype == 28:
                require(size == 16, "dns_aaaa_rdata_length")
            records.append(Record(name, rtype, rclass, ttl, data, target))
            cursor = end
        sections.append(tuple(records))
    require(cursor == len(wire), "dns_trailing_data")
    opts = [record for record in sections[2] if record.rtype == 41]
    require(len(opts) <= 1, "dns_multiple_opt")
    require(not any(record.rtype == 41 for section in sections[:2] for record in section), "dns_opt_section")
    if opts:
        require(opts[0].name == "", "dns_opt_owner")
    rcode = (flags & 0x0F) | ((opts[0].ttl >> 24) << 4 if opts else 0)
    return Message(qid, flags, rcode, tuple(questions), *sections)


def validate_response(query: bytes, wire: bytes, *, expected_rcode: int = 0) -> dict:
    request = parse_message(query)
    response = parse_message(wire)
    require(response.qid == request.qid, "dns_qid_mismatch")
    require(bool(response.flags & 0x8000), "dns_qr_missing")
    require(response.flags & 0x7800 == 0, "dns_opcode_invalid")
    require(not response.flags & 0x0200, "dns_response_truncated")
    require(not response.flags & 0x0040, "dns_reserved_flag")
    require(response.questions == request.questions and len(response.questions) == 1, "dns_question_mismatch")
    require(response.rcode == expected_rcode, "dns_rcode_unexpected")
    if expected_rcode == 0:
        require(bool(response.flags & 0x0080), "dns_recursion_unavailable")
        require(bool(response.answers), "dns_answer_missing")
        reachable = {request.questions[0].name}
        for _ in range(len(response.answers)):
            previous = len(reachable)
            reachable.update(record.target for record in response.answers
                             if record.rtype == 5 and record.rclass == 1 and record.name in reachable)
            if len(reachable) == previous:
                break
        addresses = [record for record in response.answers
                     if record.rtype == 1 and record.rclass == 1 and record.name in reachable]
        require(bool(addresses), "dns_a_answer_missing")
        require(all(ipaddress.IPv4Address(record.data).is_global for record in addresses), "dns_a_answer_not_public")
    else:
        require(not response.answers, "dns_error_has_answers")
    return {"qid_match": True, "qr": True, "rcode": response.rcode,
            "answer_count": len(response.answers), "wire_bytes": len(wire)}


def trusted_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.hostname_checks_common_name = False
    return context


def certificate_details(connection: ssl.SSLSocket, hostname: str) -> dict:
    certificate = connection.getpeercert()
    sans = {value.lower() for kind, value in certificate.get("subjectAltName", ()) if kind == "DNS"}
    require(hostname.lower() in sans, "tls_exact_dns_san_missing")
    return {"trusted": True, "hostname_san": hostname, "tls_version": connection.version(),
            "certificate_sha256": hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest()}


def read_exact(connection: socket.socket, count: int) -> bytes:
    require(0 <= count <= MAX_WIRE, "dns_frame_size")
    data = bytearray()
    while len(data) < count:
        part = connection.recv(count - len(data))
        require(bool(part), "dns_frame_eof")
        data.extend(part)
    return bytes(data)


def validate_interface_index(interface_index: int | None) -> None:
    if interface_index is not None:
        require(sys.platform == "win32", "interface_index_windows_only")
        require(type(interface_index) is int and 1 <= interface_index <= 0xFFFFFF, "interface_index_invalid")


def select_outgoing_interface(connection: socket.socket, interface_index: int | None) -> None:
    """Windows per-socket IPv4 egress; input index must be in network byte order.

    https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
    https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/shared/ws2ipdef.h
    """
    validate_interface_index(interface_index)
    if interface_index is not None:
        # Pack the htonl result as a native DWORD: no Python signed-int overflow
        # for adapter indices whose network-order representation has bit 31 set.
        value = struct.pack("=I", socket.htonl(interface_index))
        connection.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_UNICAST_IF", WINDOWS_IP_UNICAST_IF), value)


def public_connection(port: int, timeout: float, *, interface_index: int | None = None) -> socket.socket:
    validate_interface_index(interface_index)
    if interface_index is None:
        return socket.create_connection((PUBLIC_IPV4, port), timeout=timeout)
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection.settimeout(timeout)
        select_outgoing_interface(connection, interface_index)
        connection.connect((PUBLIC_IPV4, port))
        return connection
    except BaseException:
        connection.close()
        raise


def udp_query(query: bytes, timeout: float, *, interface_index: int | None = None) -> tuple[bytes, dict]:
    validate_interface_index(interface_index)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.settimeout(timeout)
        select_outgoing_interface(connection, interface_index)
        connection.connect((PUBLIC_IPV4, 53))
        connection.send(query)
        return connection.recv(MAX_WIRE), {}


def stream_query(query: bytes, timeout: float, *, tls: bool = False, interface_index: int | None = None) -> tuple[bytes, dict]:
    port = 853 if tls else 53
    metadata = {}
    with public_connection(port, timeout, interface_index=interface_index) as plain:
        connection = trusted_context().wrap_socket(plain, server_hostname=DOMAIN) if tls else plain
        with connection:
            if tls:
                metadata = {"tls": certificate_details(connection, DOMAIN)}
            connection.sendall(struct.pack("!H", len(query)) + query)
            size = struct.unpack("!H", read_exact(connection, 2))[0]
            require(size >= 12, "dns_frame_too_short")
            return read_exact(connection, size), metadata


class PinnedHTTPS(http.client.HTTPSConnection):
    """Connect only to the public IPv4 while verifying the intended SNI hostname."""

    def __init__(self, hostname: str, port: int, timeout: float, *, interface_index: int | None = None):
        super().__init__(hostname, port, timeout=timeout, context=trusted_context())
        validate_interface_index(interface_index)
        self.interface_index = interface_index
        self.tls_details = {}

    def connect(self) -> None:
        plain = public_connection(self.port, self.timeout, interface_index=self.interface_index)
        try:
            self.sock = self._context.wrap_socket(plain, server_hostname=self.host)
            self.tls_details = certificate_details(self.sock, self.host)
        except BaseException:
            plain.close()
            if self.sock is not None:
                self.sock.close()
            raise


def https_request(method: str, path: str, timeout: float, *, body: bytes | None = None,
                  host_header: str = DOMAIN, hostname: str = DOMAIN, port: int = 443,
                  read_body: bool = True, limit: int = MAX_WIRE,
                  interface_index: int | None = None) -> tuple[int, dict, bytes, dict]:
    connection = PinnedHTTPS(hostname, port, timeout, interface_index=interface_index)
    headers = {"Host": host_header, "Accept": "application/dns-message", "Connection": "close"}
    if body is not None:
        headers.update({"Content-Type": "application/dns-message", "Content-Length": str(len(body))})
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read(limit + 1) if read_body else b""
        require(len(raw) <= limit, "http_response_too_large")
        return response.status, {key.lower(): value for key, value in response.getheaders()}, raw, connection.tls_details
    finally:
        connection.close()


def doh_query(query: bytes, timeout: float, *, method: str, interface_index: int | None = None) -> tuple[bytes, dict]:
    encoded = base64.urlsafe_b64encode(query).decode("ascii").rstrip("=")
    path = "/dns-query?dns=" + encoded if method == "GET" else "/dns-query"
    status, headers, raw, tls = https_request(method, path, timeout, body=query if method == "POST" else None,
                                            interface_index=interface_index)
    require(status == 200, "doh_http_status")
    require(headers.get("content-type", "").split(";", 1)[0].strip().lower() == "application/dns-message", "doh_content_type")
    require("location" not in headers and "set-cookie" not in headers, "doh_panel_headers")
    return raw, {"http_status": status, "content_type": "application/dns-message", "tls": tls}


def dns_check(name: str, transport: str, timeout: float, *, qtype: int = QTYPE_A, expected_rcode: int = 0,
              interface_index: int | None = None) -> dict:
    require(name in TEST_NAMES, "probe_domain_not_allowed")
    query = build_query(name, qtype=qtype)
    if transport == "udp53":
        wire, metadata = udp_query(query, timeout, interface_index=interface_index)
    elif transport == "tcp53":
        wire, metadata = stream_query(query, timeout, interface_index=interface_index)
    elif transport == "dot853":
        wire, metadata = stream_query(query, timeout, tls=True, interface_index=interface_index)
    elif transport in ("doh_get443", "doh_post443"):
        wire, metadata = doh_query(query, timeout, method="GET" if transport == "doh_get443" else "POST",
                                   interface_index=interface_index)
    else:
        raise ProbeError("probe_transport_invalid")
    # dnsdist 2.1.2 processQuery rejects DoH AXFR/IXFR with NOTIMP before
    # applyRulesToQuery, so the configured Lua REFUSED rule cannot see them:
    # https://github.com/PowerDNS/pdns/blob/dnsdist-2.1.2/pdns/dnsdistdist/dnsdist.cc#L1697-L1702
    # This exception is limited to explicit transfer-denial probes over DoH.
    # QID, QR, matching question, complete wire parsing and empty-answer checks
    # remain enforced by validate_response; all other transport/type rules stay
    # exact, including ANY=REFUSED and dnssec-failed.org=SERVFAIL.
    unsupported_doh_transfer = (expected_rcode == 5 and qtype in (QTYPE_AXFR, QTYPE_IXFR)
                                and transport in ("doh_get443", "doh_post443")
                                and parse_message(wire).rcode == 4)
    result = {**validate_response(query, wire, expected_rcode=4 if unsupported_doh_transfer else expected_rcode), **metadata}
    if unsupported_doh_transfer:
        result["denial"] = "not_implemented"
    return result


def bad_doh_check(method: str, path: str, timeout: float, expected: int, *, host_header: str = DOMAIN,
                  interface_index: int | None = None) -> dict:
    status, headers, raw, tls = https_request(method, path, timeout, host_header=host_header, limit=8192,
                                            interface_index=interface_index)
    require(status == expected, "doh_rejection_status")
    require("location" not in headers and "set-cookie" not in headers, "doh_rejection_panel_headers")
    lowered = raw.lower()
    require(not any(marker in lowered for marker in (b"quantumcontrol", b"operator/login", b"csrf", b"password", b"<form")), "doh_rejection_panel_body")
    return {"http_status": status, "panel_body": False, "tls": tls}


def direct_port_check(port: int, timeout: float, *, interface_index: int | None = None) -> dict:
    try:
        with public_connection(port, timeout, interface_index=interface_index):
            raise ProbeError("internal_port_publicly_open")
    except OSError as error:
        # A timeout proves neither a refused connection nor the intended reject rule.
        require(isinstance(error, ConnectionRefusedError) or error.errno in (errno.ECONNREFUSED, 10061), "internal_port_not_explicitly_refused")
    return {"port": port, "connection_refused": True}


def legacy_check(port: int, path: str, timeout: float, *, interface_index: int | None = None) -> dict:
    status, _, _, tls = https_request("GET", path, timeout, hostname=LEGACY_DOMAIN,
                                      host_header=LEGACY_DOMAIN + ":" + str(port), port=port, read_body=False,
                                      interface_index=interface_index)
    require(200 <= status < 400 or status in (401, 403), "legacy_http_status")
    return {"http_status": status, "tls": tls}


def public_hostname_check() -> dict:
    addresses = {item[4][0] for item in socket.getaddrinfo(DOMAIN, 443, socket.AF_INET, socket.SOCK_STREAM)}
    require(addresses == {PUBLIC_IPV4}, "public_hostname_ipv4_mismatch")
    return {"public_ipv4_matches": True}


def sanitized_error(error: Exception) -> str:
    if isinstance(error, ProbeError):
        return str(error)
    if isinstance(error, ssl.SSLCertVerificationError):
        return "tls_certificate_untrusted_or_hostname_mismatch"
    if isinstance(error, (TimeoutError, socket.timeout)):
        return "network_timeout"
    if isinstance(error, ConnectionRefusedError):
        return "connection_refused"
    if isinstance(error, ssl.SSLError):
        return "tls_handshake_failed"
    if isinstance(error, OSError):
        return "network_os_error"
    if isinstance(error, http.client.HTTPException):
        return "http_protocol_error"
    return "probe_internal_error"


def run_check(name: str, check: Callable[[], dict]) -> dict:
    try:
        return {"check": name, "pass": True, **check()}
    except Exception as error:
        return {"check": name, "pass": False, "error": sanitized_error(error)}


def check_jobs(timeout: float, *, refused_types: bool = False,
               interface_index: int | None = None) -> list[tuple[str, Callable[[], dict]]]:
    validate_interface_index(interface_index)
    # OS hostname resolution remains an observation of the normal client DNS
    # setup; every connection to the exact public IPv4 uses the chosen adapter.
    jobs = [("public_hostname_ipv4", public_hostname_check)]
    transports = ("udp53", "tcp53", "dot853", "doh_get443", "doh_post443")
    for transport in transports:
        for name, rcode in (("example.com", 0), ("dnssec-failed.org", 2)):
            jobs.append((transport + ":" + name, lambda name=name, transport=transport, rcode=rcode:
                         dns_check(name, transport, timeout, expected_rcode=rcode, interface_index=interface_index)))
        if refused_types:
            for qtype, label in ((QTYPE_ANY, "ANY"), (QTYPE_AXFR, "AXFR"), (QTYPE_IXFR, "IXFR")):
                jobs.append((transport + ":refuse_" + label, lambda transport=transport, qtype=qtype:
                             dns_check("example.com", transport, timeout, qtype=qtype, expected_rcode=5,
                                       interface_index=interface_index)))
    for label, method, path, expected, host in (
        ("unknown_uri", "GET", "/operator/login", 404, DOMAIN),
        ("missing_dns", "GET", "/dns-query", 400, DOMAIN),
        ("invalid_dns", "GET", "/dns-query?dns=invalid", 400, DOMAIN),
        ("extra_parameter", "GET", "/dns-query?dns=AAAAAAAAAAAAAAAA&extra=1", 400, DOMAIN),
        ("wrong_host", "GET", "/dns-query?dns=AAAAAAAAAAAAAAAA", 404, LEGACY_DOMAIN),
        ("unsupported_method", "PUT", "/dns-query", 405, DOMAIN),
    ):
        jobs.append(("doh_reject:" + label, lambda method=method, path=path, expected=expected, host=host:
                     bad_doh_check(method, path, timeout, expected, host_header=host, interface_index=interface_index)))
    for port in (18554, 18555, 18556, 18557):
        jobs.append(("internal_port:" + str(port), lambda port=port: direct_port_check(port, timeout,
                                                                                  interface_index=interface_index)))
    for port, path in ((8443, "/operator/login"), (8444, "/")):
        jobs.append(("legacy_https:" + str(port), lambda port=port, path=path: legacy_check(port, path, timeout,
                                                                                         interface_index=interface_index)))
    return jobs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=12.0, help="Per-socket timeout in seconds (0.1..30; default: 12)")
    parser.add_argument("--refused-types", action="store_true",
                        help="Check ANY=REFUSED and blocked AXFR/IXFR on all transports (DoH also permits empty NOTIMP)")
    parser.add_argument("--interface-index", type=int, default=None,
                        help="Windows only: outgoing IPv4 adapter index for this probe's sockets (no route changes)")
    arguments = parser.parse_args(argv)
    if not 0.1 <= arguments.timeout <= 30:
        parser.error("--timeout must be between 0.1 and 30 seconds")
    try:
        validate_interface_index(arguments.interface_index)
    except ProbeError as error:
        parser.error(str(error))
    jobs = check_jobs(arguments.timeout, refused_types=arguments.refused_types, interface_index=arguments.interface_index)
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(run_check, name, check) for name, check in jobs]
        checks = [future.result() for future in futures]
    passed = all(check["pass"] for check in checks)
    report = {"target": DOMAIN, "public_ipv4": PUBLIC_IPV4,
                      "checked_utc": datetime.now(timezone.utc).isoformat(), "pass": passed,
                      "checks": checks}
    if arguments.interface_index is not None:
        report["outgoing_interface_index"] = arguments.interface_index
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
