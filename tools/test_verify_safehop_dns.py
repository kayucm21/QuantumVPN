"""Offline DNS wire and external-probe scope tests; never contact any endpoint."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest
from unittest import mock


path = Path(__file__).with_name("verify-safehop-dns.py")
spec = importlib.util.spec_from_file_location("safehop_external_probe", path)
probe = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = probe
spec.loader.exec_module(probe)


def response(query, *, flags=0x8180, qid=None, answers=(), extra=b""):
    request = probe.parse_message(query)
    question_end = 12 + len(probe.encode_name(request.questions[0].name)) + 4
    return (struct.pack("!6H", request.qid if qid is None else qid, flags, 1, len(answers), 0, 0)
            + query[12:question_end] + b"".join(answers) + extra)


def a_record(*, owner=b"\xc0\x0c", data=b"\x5d\xb8\xd8\x22", size=None):
    return owner + struct.pack("!HHIH", 1, 1, 120, len(data) if size is None else size) + data


class DnsWireTests(unittest.TestCase):
    def setUp(self):
        self.query = probe.build_query("example.com", qid=0x1234)
        self.answer = response(self.query, answers=(a_record(),))

    def test_query_has_rfc_wire_question_and_dnssec_without_cd(self):
        request = probe.parse_message(self.query)
        self.assertEqual(request.qid, 0x1234)
        self.assertEqual(request.flags, 0x0100)
        self.assertEqual(request.questions, (probe.Question("example.com", 1, 1),))
        self.assertEqual(request.additional[0].rtype, 41)
        self.assertEqual(request.additional[0].rclass, 1232)
        self.assertEqual(request.additional[0].ttl, 0x8000)

    def test_name_encoder_accepts_trailing_dot_and_root(self):
        self.assertEqual(probe.encode_name("example.com."), b"\x07example\x03com\x00")
        self.assertEqual(probe.encode_name("."), b"\x00")

    def test_encoder_rejects_empty_non_ascii_control_and_long_labels(self):
        for name in ("", "example..com", "example.com..", "example.com\n", "a" * 64 + ".com", "пример.com", "a/b.com", None):
            with self.subTest(name=name), self.assertRaises(probe.ProbeError):
                probe.encode_name(name)

    def test_name_wire_size_limits(self):
        maximum = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))
        self.assertEqual(len(probe.encode_name(maximum)), 255)
        with self.assertRaises(probe.ProbeError):
            probe.encode_name(maximum + "d")

    def test_query_rejects_invalid_id_and_type(self):
        for qid in (-1, 65536, True, "1"):
            with self.subTest(qid=qid), self.assertRaises(probe.ProbeError):
                probe.build_query("example.com", qid=qid)
        for qtype in (0, -1, 65536, False):
            with self.subTest(qtype=qtype), self.assertRaises(probe.ProbeError):
                probe.build_query("example.com", qtype=qtype)

    def test_compressed_name_returns_original_cursor_and_canonical_case(self):
        wire = b"\x07ExAmPlE\x03COM\x00\xc0\x00"
        self.assertEqual(probe.decode_name(wire, 13), ("example.com", 15))

    def test_parser_safely_rejects_pointer_loops_and_forward_pointers(self):
        for wire, start in ((b"\xc0\x00", 0), (b"\xc0\x02\x00", 0), (b"\x01a\xc0\x00", 2), (b"\xc0", 0)):
            with self.subTest(wire=wire), self.assertRaises(probe.ProbeError):
                probe.decode_name(wire, start)

    def test_parser_rejects_reserved_labels_truncation_and_expanded_overflow(self):
        for wire in (b"\x40", b"\x80", b"\x03ab", b"\x01\xff\x00", b"\x01.\x00", (b"\x3f" + b"a" * 63) * 4 + b"\x00"):
            with self.subTest(length=len(wire)), self.assertRaises(probe.ProbeError):
                probe.decode_name(wire, 0)

    def test_valid_answer_checks_id_qr_rcode_and_answer_count(self):
        result = probe.validate_response(self.query, self.answer)
        self.assertTrue(result["qid_match"])
        self.assertTrue(result["qr"])
        self.assertEqual(result["rcode"], 0)
        self.assertEqual(result["answer_count"], 1)

    def test_validation_rejects_id_flags_and_unexpected_rcode(self):
        for wire in (response(self.query, qid=9, answers=(a_record(),)),
                     response(self.query, flags=0x0180, answers=(a_record(),)),
                     response(self.query, flags=0x8980, answers=(a_record(),)),
                     response(self.query, flags=0x8380, answers=(a_record(),)),
                     response(self.query, flags=0x81C0, answers=(a_record(),)),
                     response(self.query, flags=0x8182)):
            with self.subTest(wire=wire[:12]), self.assertRaises(probe.ProbeError):
                probe.validate_response(self.query, wire)

    def test_validation_rejects_wrong_question_missing_and_unrelated_answers(self):
        wrong_question = probe.build_query("different.com", qid=0x1234)
        unrelated = a_record(owner=probe.encode_name("different.com"))
        for wire in (response(wrong_question, answers=(a_record(),)), response(self.query),
                     response(self.query, answers=(unrelated,)), response(self.query, answers=(a_record(data=b"\x7f\x00\x00\x01"),))):
            with self.subTest(wire_length=len(wire)), self.assertRaises(probe.ProbeError):
                probe.validate_response(self.query, wire)

    def test_cname_answer_can_lead_to_public_a(self):
        target = probe.encode_name("target.example.com")
        cname = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 120, len(target)) + target
        address = a_record(owner=target)
        result = probe.validate_response(self.query, response(self.query, answers=(cname, address)))
        self.assertEqual(result["answer_count"], 2)

    def test_dnssec_servfail_and_refused_require_empty_answers(self):
        for rcode in (2, 5):
            with self.subTest(rcode=rcode):
                wire = response(self.query, flags=0x8180 | rcode)
                self.assertEqual(probe.validate_response(self.query, wire, expected_rcode=rcode)["answer_count"], 0)
                with self.assertRaises(probe.ProbeError):
                    probe.validate_response(self.query, response(self.query, flags=0x8180 | rcode, answers=(a_record(),)), expected_rcode=rcode)

    def test_parser_rejects_count_bounds_trailing_bytes_and_rdata_truncation(self):
        cases = (b"\x00" * 11, b"\x00" * 65536,
                 struct.pack("!6H", 1, 0x8180, 1, 513, 0, 0),
                 response(self.query, answers=(a_record(),), extra=b"\x00"),
                 response(self.query, answers=(a_record(size=20),)),
                 response(self.query, answers=(a_record(data=b"\x01\x02\x03"),)), self.answer[:-1])
        for wire in cases:
            with self.subTest(length=len(wire)), self.assertRaises(probe.ProbeError):
                probe.parse_message(wire)

    def test_cname_rdata_must_match_the_declared_size(self):
        cname = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 120, 3) + b"\xc0\x0c\x00"
        with self.assertRaises(probe.ProbeError):
            probe.parse_message(response(self.query, answers=(cname,)))

    def test_extended_edns_rcode_cannot_appear_successful(self):
        question = self.query[12:-11]
        opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0x01000000, 0)
        wire = struct.pack("!6H", 0x1234, 0x8180, 1, 1, 0, 1) + question + a_record() + opt
        self.assertEqual(probe.parse_message(wire).rcode, 16)
        with self.assertRaises(probe.ProbeError):
            probe.validate_response(self.query, wire)


class ExternalProbeScopeTests(unittest.TestCase):
    def test_notimp_exception_is_only_for_doh_axfr_and_ixfr_denials(self):
        # dnsdist 2.1.2 dnsdist.cc processQuery intercepts DoH transfers before
        # applying Lua rules. Every other type and transport must be REFUSED.
        for transport in ("udp53", "tcp53", "dot853", "doh_get443", "doh_post443"):
            for qtype in (probe.QTYPE_ANY, probe.QTYPE_AXFR, probe.QTYPE_IXFR):
                for rcode in (0, 2, 4, 5):
                    with self.subTest(transport=transport, qtype=qtype, rcode=rcode):
                        def reply(query, *args, **kwargs):
                            return response(query, flags=0x8180 | rcode), {}
                        with mock.patch.object(probe, "udp_query", side_effect=reply), \
                             mock.patch.object(probe, "stream_query", side_effect=reply), \
                             mock.patch.object(probe, "doh_query", side_effect=reply):
                            result = probe.run_check("test", lambda: probe.dns_check("example.com", transport, 1,
                                                                                      qtype=qtype, expected_rcode=5))
                        allowed_notimp = transport.startswith("doh_") and qtype in (probe.QTYPE_AXFR, probe.QTYPE_IXFR)
                        self.assertEqual(result["pass"], rcode == 5 or (rcode == 4 and allowed_notimp))
                        if result["pass"]:
                            self.assertEqual(result["answer_count"], 0)
                            self.assertEqual(result["rcode"], rcode)
                            self.assertEqual("denial" in result, rcode == 4)

    def test_doh_notimp_transfer_still_requires_safe_correlated_empty_response(self):
        for variant in ("answers", "qid", "qr", "truncated", "extra"):
            with self.subTest(variant=variant):
                def reply(query, *args, **kwargs):
                    return response(query, flags=0x8184 ^ (0x8000 if variant == "qr" else 0) |
                                    (0x0200 if variant == "truncated" else 0),
                                    qid=(probe.parse_message(query).qid ^ 1) if variant == "qid" else None,
                                    answers=(a_record(),) if variant == "answers" else (),
                                    extra=b"\x00" if variant == "extra" else b""), {}
                with mock.patch.object(probe, "doh_query", side_effect=reply):
                    result = probe.run_check("test", lambda: probe.dns_check("example.com", "doh_get443", 1,
                                                                              qtype=probe.QTYPE_AXFR, expected_rcode=5))
                self.assertFalse(result["pass"])

    def test_dnssec_and_success_doh_queries_never_accept_notimp(self):
        def reply(query, *args, **kwargs):
            return response(query, flags=0x8184), {}
        with mock.patch.object(probe, "doh_query", side_effect=reply):
            for name, rcode in (("example.com", 0), ("dnssec-failed.org", 2)):
                with self.subTest(name=name), self.assertRaises(probe.ProbeError):
                    probe.dns_check(name, "doh_post443", 1, expected_rcode=rcode)

    def test_default_sockets_preserve_normal_routes_without_setsockopt(self):
        connection = mock.Mock()
        probe.select_outgoing_interface(connection, None)
        connection.setsockopt.assert_not_called()
        with mock.patch.object(probe.socket, "create_connection", return_value=connection) as create, \
             mock.patch.object(probe.socket, "socket", side_effect=AssertionError("new socket")):
            self.assertIs(probe.public_connection(443, 3), connection)
            create.assert_called_once_with((probe.PUBLIC_IPV4, 443), timeout=3)

    def test_windows_index_sets_network_order_dword_before_tcp_connect(self):
        connection = mock.Mock()
        with mock.patch.object(probe.sys, "platform", "win32"), \
             mock.patch.object(probe.socket, "socket", return_value=connection), \
             mock.patch.object(probe.socket, "create_connection", side_effect=AssertionError("default route")):
            self.assertIs(probe.public_connection(443, 3, interface_index=128), connection)
        self.assertEqual(connection.method_calls, [mock.call.settimeout(3),
                         mock.call.setsockopt(probe.socket.IPPROTO_IP, getattr(probe.socket, "IP_UNICAST_IF", 31),
                                              struct.pack("=I", probe.socket.htonl(128))),
                         mock.call.connect((probe.PUBLIC_IPV4, 443))])

    def test_udp_selects_interface_before_connecting_only_to_public_ip(self):
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        connection.recv.return_value = b"response"
        with mock.patch.object(probe.sys, "platform", "win32"), mock.patch.object(probe.socket, "socket", return_value=connection):
            self.assertEqual(probe.udp_query(b"query", 3, interface_index=4)[0], b"response")
        calls = connection.method_calls
        self.assertEqual(calls[0], mock.call.settimeout(3))
        self.assertEqual(calls[1], mock.call.setsockopt(probe.socket.IPPROTO_IP, getattr(probe.socket, "IP_UNICAST_IF", 31),
                                                     struct.pack("=I", probe.socket.htonl(4))))
        self.assertEqual(calls[2], mock.call.connect((probe.PUBLIC_IPV4, 53)))

    def test_explicit_interface_is_windows_only_and_validated_before_network(self):
        with mock.patch.object(probe.sys, "platform", "linux"), \
             mock.patch.object(probe.socket, "socket", side_effect=AssertionError("network")):
            with self.assertRaises(probe.ProbeError):
                probe.public_connection(443, 1, interface_index=4)
        with mock.patch.object(probe.sys, "platform", "win32"):
            for index in (0, -1, True, "4", 0x1000000):
                with self.subTest(index=index), self.assertRaises(probe.ProbeError):
                    probe.check_jobs(1, interface_index=index)

    def test_failed_interface_selection_closes_socket_and_never_falls_back(self):
        connection = mock.Mock()
        connection.setsockopt.side_effect = OSError("invalid adapter")
        with mock.patch.object(probe.sys, "platform", "win32"), \
             mock.patch.object(probe.socket, "socket", return_value=connection), \
             mock.patch.object(probe.socket, "create_connection", side_effect=AssertionError("fallback")):
            with self.assertRaises(OSError):
                probe.public_connection(443, 1, interface_index=4)
        connection.close.assert_called_once()
        connection.connect.assert_not_called()

    def test_all_public_ip_jobs_forward_interface_option(self):
        with mock.patch.object(probe.sys, "platform", "win32"), \
             mock.patch.object(probe, "dns_check", return_value={}) as dns, \
             mock.patch.object(probe, "bad_doh_check", return_value={}) as bad, \
             mock.patch.object(probe, "direct_port_check", return_value={}) as direct, \
             mock.patch.object(probe, "legacy_check", return_value={}) as legacy:
            for name, check in probe.check_jobs(1, refused_types=True, interface_index=4):
                if name != "public_hostname_ipv4":
                    check()
            for method in (dns, bad, direct, legacy):
                self.assertTrue(method.called)
                self.assertTrue(all(call.kwargs["interface_index"] == 4 for call in method.call_args_list))

    def test_dot_and_https_wrap_interface_selected_public_socket(self):
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        connection.recv.side_effect = [b"\x00\x0c", b"\x00" * 12]
        context = mock.Mock()
        context.wrap_socket.return_value = connection
        with mock.patch.object(probe, "public_connection", return_value=connection) as create, \
             mock.patch.object(probe, "trusted_context", return_value=context), \
             mock.patch.object(probe, "certificate_details", return_value={}), \
             mock.patch.object(probe.sys, "platform", "win32"):
            probe.stream_query(b"query", 1, tls=True, interface_index=4)
            create.assert_called_with(853, 1, interface_index=4)
            context.wrap_socket.assert_called_with(connection, server_hostname=probe.DOMAIN)
            https = probe.PinnedHTTPS(probe.DOMAIN, 443, 1, interface_index=4)
            https.connect()
            create.assert_called_with(443, 1, interface_index=4)
            context.wrap_socket.assert_called_with(connection, server_hostname=probe.DOMAIN)

    def test_import_and_job_construction_do_not_contact_network(self):
        with mock.patch.object(probe.socket, "create_connection", side_effect=AssertionError("network")), \
             mock.patch.object(probe.socket, "getaddrinfo", side_effect=AssertionError("network")):
            jobs = probe.check_jobs(1)
            self.assertEqual(len(jobs), 23)
            self.assertEqual(len(probe.check_jobs(1, refused_types=True)), 38)

    def test_only_fixed_test_domains_are_accepted_before_network(self):
        with mock.patch.object(probe, "udp_query", side_effect=AssertionError("network")):
            with self.assertRaises(probe.ProbeError):
                probe.dns_check("private-user-domain.invalid", "udp53", 1)

    def test_tls_requires_trust_hostname_and_exact_dns_san(self):
        context = probe.trusted_context()
        self.assertEqual(context.verify_mode, probe.ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertFalse(context.hostname_checks_common_name)
        connection = mock.Mock()
        connection.getpeercert.side_effect = [{"subjectAltName": (("DNS", probe.DOMAIN),)}, b"der"]
        connection.version.return_value = "TLSv1.3"
        self.assertTrue(probe.certificate_details(connection, probe.DOMAIN)["trusted"])
        connection.getpeercert.side_effect = [{"subject": ((('commonName', probe.DOMAIN),),)}]
        with self.assertRaises(probe.ProbeError):
            probe.certificate_details(connection, probe.DOMAIN)

    def test_read_exact_handles_short_reads_and_rejects_eof(self):
        connection = mock.Mock()
        connection.recv.side_effect = [b"a", b"bc"]
        self.assertEqual(probe.read_exact(connection, 3), b"abc")
        connection.recv.side_effect = [b"a", b""]
        with self.assertRaises(probe.ProbeError):
            probe.read_exact(connection, 3)

    def test_doh_get_is_unpadded_base64url_and_post_is_wire_format(self):
        query = probe.build_query("example.com", qid=65535)
        wire = response(query, answers=(a_record(),))
        with mock.patch.object(probe, "https_request", return_value=(200, {"content-type": "application/dns-message"}, wire, {})) as request:
            self.assertEqual(probe.doh_query(query, 1, method="GET")[0], wire)
            method, path, _ = request.call_args.args
            self.assertEqual(method, "GET")
            self.assertRegex(path, r"^/dns-query\?dns=[A-Za-z0-9_-]+$")
            self.assertIsNone(request.call_args.kwargs["body"])
            probe.doh_query(query, 1, method="POST")
            self.assertEqual(request.call_args.args[:2], ("POST", "/dns-query"))
            self.assertEqual(request.call_args.kwargs["body"], query)

    def test_doh_rejects_panel_and_non_dns_payload_without_logging_body(self):
        for status, headers, raw in ((302, {"location": "/operator"}, b"secret"),
                                     (200, {"content-type": "text/html"}, b"secret"),
                                     (200, {"content-type": "application/dns-message", "set-cookie": "secret"}, b"secret")):
            with self.subTest(status=status), mock.patch.object(probe, "https_request", return_value=(status, headers, raw, {})):
                result = probe.run_check("test", lambda: probe.doh_query(b"wire", 1, method="POST"))
                self.assertFalse(result["pass"])
                self.assertNotIn("secret", str(result))

    def test_rejected_doh_request_cannot_return_a_panel_page(self):
        with mock.patch.object(probe, "https_request", return_value=(404, {}, b"<form><input name='password'></form>", {})):
            with self.assertRaises(probe.ProbeError):
                probe.bad_doh_check("GET", "/operator/login", 1, 404)

    def test_direct_port_timeout_does_not_count_as_refusal(self):
        with mock.patch.object(probe.socket, "create_connection", side_effect=ConnectionRefusedError()):
            self.assertTrue(probe.direct_port_check(18554, 1)["connection_refused"])
        with mock.patch.object(probe.socket, "create_connection", side_effect=TimeoutError()):
            with self.assertRaises(probe.ProbeError):
                probe.direct_port_check(18554, 1)

    def test_untrusted_network_error_text_is_not_printed(self):
        error = OSError("server sent secret/body/query data")
        result = probe.run_check("test", mock.Mock(side_effect=error))
        self.assertEqual(result, {"check": "test", "pass": False, "error": "network_os_error"})


if __name__ == "__main__":
    unittest.main()
