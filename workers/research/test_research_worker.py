#!/usr/bin/env python3
"""Adversarial contract tests for the optional research worker."""

from __future__ import annotations

import base64
import importlib.util
import io
import json
import pathlib
import subprocess
import threading
import time
import unittest
import urllib.parse
from unittest import mock


WORKER_PATH = pathlib.Path(__file__).with_name("research_worker.py")
SPEC = importlib.util.spec_from_file_location("steward_research_worker", WORKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("research worker could not be loaded")
worker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(worker)
PYPDF_AVAILABLE = importlib.util.find_spec("pypdf") is not None


def pdf_with_text(text: str) -> bytes:
    escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    content = f"BT /F1 12 Tf 72 720 Td ({escaped}) Tj ET".encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    document = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, value in enumerate(objects, start=1):
        offsets.append(len(document))
        document.extend(f"{number} 0 obj\n".encode("ascii"))
        document.extend(value)
        document.extend(b"\nendobj\n")
    xref = len(document)
    document.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    document.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        document.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    document.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii")
    )
    return bytes(document)


def eia_price_url(state: str = "WV") -> str:
    query = urllib.parse.urlencode(
        [
            ("frequency", "annual"),
            ("data[]", "price"),
            ("facets[stateid][]", state),
            ("facets[sectorid][]", "COM"),
            ("sort[0][column]", "period"),
            ("sort[0][direction]", "desc"),
            ("length", "5"),
        ]
    )
    return f"https://api.eia.gov/v2/electricity/retail-sales/data/?{query}"


class SearchTests(unittest.TestCase):
    def test_brave_search_normalizes_only_public_results(self) -> None:
        response = {
            "type": "search",
            "web": {
                "results": [
                    {
                        "description": "Decision-relevant excerpt",
                        "title": "Primary source",
                        "url": "https://source.example/report",
                    },
                    {
                        "description": "Ignore private destinations",
                        "title": "Private source",
                        "url": "http://127.0.0.1/private",
                    },
                ]
            }
        }
        with (
            mock.patch.object(worker, "upstream_json", return_value=response) as upstream,
            mock.patch.object(
                worker,
                "public_url",
                side_effect=[
                    "https://source.example/report",
                    worker.WorkerError(400, "private_source_denied", "private"),
                ],
            ),
        ):
            result = worker.search(
                {"query": "Colusa data center zoning", "limit": 5},
                None,
                b"brave-fixture-key",
            )

        self.assertEqual(
            result,
            {
                "schema_version": "steward.research-search-result.v1",
                "results": [
                    {
                        "engine": "brave",
                        "snippet": "Decision-relevant excerpt",
                        "title": "Primary source",
                        "url": "https://source.example/report",
                    }
                ],
            },
        )
        upstream.assert_called_once_with(
            worker.BRAVE_API_BASE,
            "GET",
            "/res/v1/web/search?q=Colusa+data+center+zoning&count=5",
            None,
            subscription_token=b"brave-fixture-key",
            retryable_statuses=worker.BRAVE_TRANSIENT_STATUS_CODES,
            retry_delays_seconds=worker.BRAVE_RETRY_DELAYS_SECONDS,
        )

    def test_brave_search_normalizes_valid_zero_result_response(self) -> None:
        response = {
            "query": {"original": "site:example.invalid unavailable topic"},
            "type": "search",
        }
        with mock.patch.object(worker, "upstream_json", return_value=response):
            result = worker.search(
                {"query": "site:example.invalid unavailable topic", "limit": 5},
                None,
                b"brave-fixture-key",
            )

        self.assertEqual(
            result,
            {
                "schema_version": "steward.research-search-result.v1",
                "results": [],
            },
        )

    def test_brave_search_rejects_non_search_and_malformed_web_responses(self) -> None:
        for response in ({}, {"type": "search", "web": None}, {"type": "search", "web": {}}):
            with (
                self.subTest(response=response),
                mock.patch.object(worker, "upstream_json", return_value=response),
                self.assertRaisesRegex(worker.WorkerError, "Brave response"),
            ):
                worker.search(
                    {"query": "bounded query", "limit": 5},
                    None,
                    b"brave-fixture-key",
                )

    def test_upstream_retries_only_configured_transient_statuses(self) -> None:
        class Response:
            def __init__(self, status: int, body: bytes) -> None:
                self.status = status
                self._body = body

            def read(self, maximum: int) -> bytes:
                self.maximum = maximum
                return self._body

        class Connection:
            def __init__(self, response: Response) -> None:
                self.response = response
                self.closed = False

            def request(self, *_args: object, **_kwargs: object) -> None:
                return None

            def getresponse(self) -> Response:
                return self.response

            def close(self) -> None:
                self.closed = True

        first = Connection(Response(502, b'{"error":"retry"}'))
        second = Connection(Response(200, b'{"result":"ok"}'))
        with (
            mock.patch.object(
                worker.http.client,
                "HTTPSConnection",
                side_effect=[first, second],
            ) as connections,
            mock.patch.object(worker.time, "sleep") as sleep,
        ):
            result = worker.upstream_json(
                worker.BRAVE_API_BASE,
                "GET",
                "/res/v1/web/search?q=retry",
                None,
                retryable_statuses=frozenset({502}),
                retry_delays_seconds=(1.0,),
            )

        self.assertEqual(result, {"result": "ok"})
        self.assertEqual(connections.call_count, 2)
        sleep.assert_called_once_with(1.0)
        self.assertTrue(first.closed)
        self.assertTrue(second.closed)

    def test_search_keeps_keyless_searx_path_when_brave_is_not_configured(self) -> None:
        upstream_base = urllib.parse.urlsplit("https://search.example")
        response = {
            "results": [
                {
                    "content": "Public search result",
                    "engine": "fixture",
                    "title": "Source",
                    "url": "https://source.example/report",
                }
            ]
        }
        with (
            mock.patch.object(worker, "upstream_json", return_value=response) as upstream,
            mock.patch.object(worker, "public_url", return_value="https://source.example/report"),
        ):
            result = worker.search(
                {"query": "Colusa site diligence", "limit": 5},
                upstream_base,
            )

        self.assertEqual(result["results"][0]["engine"], "fixture")
        upstream.assert_called_once_with(
            upstream_base,
            "GET",
            "/search?q=Colusa+site+diligence&format=json",
            None,
        )


class EIATests(unittest.TestCase):
    def response(self) -> dict[str, object]:
        return {
            "response": {
                "data": [
                    {
                        "period": "2024",
                        "price": "9.24",
                        "price-units": "cents per kilowatthour",
                        "sectorName": "commercial",
                        "sectorid": "COM",
                        "stateDescription": "West Virginia",
                        "stateid": "WV",
                    },
                    {
                        "period": "2023",
                        "price": "8.91",
                        "price-units": "cents per kilowatthour",
                        "sectorName": "commercial",
                        "sectorid": "COM",
                        "stateDescription": "West Virginia",
                        "stateid": "WV",
                    },
                ],
                "dateFormat": "YYYY",
                "description": "Electricity sales to ultimate customers",
                "frequency": "annual",
                "total": "24",
            },
            "warnings": [{"warning": "incomplete return", "description": "bounded"}],
        }

    def test_eia_profile_injects_key_and_never_reflects_it(self) -> None:
        requested_url = eia_price_url()
        api_key = b"eia-fixture-secret-key"
        with mock.patch.object(worker, "upstream_json", return_value=self.response()) as upstream:
            outcome = worker.extract_eia_outcome(
                requested_url,
                api_key,
                deadline=time.monotonic() + 5,
            )

        self.assertEqual(outcome["disposition"], "extracted")
        self.assertEqual(outcome["requested_url"], requested_url)
        self.assertEqual(outcome["resolved_url"], requested_url)
        self.assertEqual(outcome["source_media_type"], "application/json")
        projected = json.loads(outcome["content"])
        self.assertEqual(projected["schema_version"], worker.EIA_RESULT_SCHEMA)
        self.assertEqual(projected["state_id"], "WV")
        self.assertEqual(projected["data"][0]["period"], "2024")
        self.assertNotIn(api_key.decode(), json.dumps(outcome))
        called_path = upstream.call_args.args[2]
        self.assertIn("api_key=eia-fixture-secret-key", called_path)
        self.assertNotIn("api_key", requested_url)
        self.assertGreater(upstream.call_args.kwargs["timeout_seconds"], 4)
        self.assertLessEqual(upstream.call_args.kwargs["timeout_seconds"], 5)

    def test_eia_profile_rejects_query_widening_and_multiple_calls(self) -> None:
        invalid = (
            eia_price_url().replace("length=5", "length=500"),
            eia_price_url().replace("COM", "RES"),
            eia_price_url().replace("frequency=annual", "frequency=monthly"),
            eia_price_url("XX"),
            eia_price_url() + "&api_key=attacker",
        )
        for url in invalid:
            with self.subTest(url=url), self.assertRaises(worker.WorkerError) as raised:
                worker.eia_request_state(url)
            self.assertEqual(raised.exception.code, "invalid_source_url")

        with self.assertRaises(worker.WorkerError) as raised:
            worker.extract_v2({"urls": [eia_price_url("WV"), eia_price_url("CA")]})
        self.assertEqual(raised.exception.code, "invalid_request")

    def test_eia_profile_fails_as_a_source_when_key_or_response_is_unavailable(self) -> None:
        requested_url = eia_price_url()
        self.assertEqual(
            worker.extract_v2({"urls": [requested_url]}),
            {
                "schema_version": "steward.research-extract-result.v2",
                "outcomes": [
                    {
                        "requested_url": requested_url,
                        "disposition": "failed",
                        "failure_code": "source_unavailable",
                    }
                ],
            },
        )
        with mock.patch.object(
            worker,
            "upstream_json",
            side_effect=worker.WorkerError(
                502,
                "upstream_rejected",
                "provider included secret details",
            ),
        ):
            outcome = worker.extract_eia_outcome(
                requested_url,
                b"eia-fixture-secret-key",
                deadline=time.monotonic() + 5,
            )
        self.assertEqual(outcome["failure_code"], "source_rejected")
        self.assertNotIn("secret", json.dumps(outcome))

    def test_eia_profile_rejects_provider_schema_drift(self) -> None:
        response = self.response()
        response["response"]["data"][0]["stateid"] = "CA"
        with mock.patch.object(worker, "upstream_json", return_value=response):
            outcome = worker.extract_eia_outcome(
                eia_price_url(),
                b"eia-fixture-secret-key",
                deadline=time.monotonic() + 5,
            )
        self.assertEqual(outcome["failure_code"], "unsupported_source")


class PDFExtractionTests(unittest.TestCase):
    @unittest.skipUnless(PYPDF_AVAILABLE, "pypdf is installed in the research worker image")
    def test_child_extracts_text_with_bounded_output(self) -> None:
        result = worker.parse_pdf_payload(pdf_with_text("Primary source evidence"))
        self.assertEqual(result["title"], "")
        self.assertIn("Primary source evidence", result["content"])

        oversized = worker.parse_pdf_payload(pdf_with_text("A" * (worker.MAX_SOURCE_TEXT + 4096)))
        self.assertLessEqual(len(oversized["content"].encode("utf-8")), worker.MAX_SOURCE_TEXT)

    @unittest.skipUnless(PYPDF_AVAILABLE, "pypdf is installed in the research worker image")
    def test_child_rejects_page_fanout(self) -> None:
        from pypdf import PdfWriter

        output = io.BytesIO()
        writer = PdfWriter()
        for _ in range(worker.MAX_PDF_PAGES + 1):
            writer.add_blank_page(width=72, height=72)
        writer.write(output)
        writer.close()

        with self.assertRaisesRegex(worker.PDFInputRejected, "page count"):
            worker.parse_pdf_payload(output.getvalue())

    @unittest.skipUnless(PYPDF_AVAILABLE, "pypdf is installed in the research worker image")
    def test_subprocess_isolated_parser_accepts_pdf(self) -> None:
        title, content = worker.extract_pdf_text(pdf_with_text("Isolated evidence"))
        self.assertEqual(title, "")
        self.assertIn("Isolated evidence", content)

    def test_parser_timeout_and_malformed_output_fail_closed(self) -> None:
        raw = pdf_with_text("bounded")
        with mock.patch.object(
            worker.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(cmd="python", timeout=worker.PDF_WALL_SECONDS),
        ):
            with self.assertRaises(worker.WorkerError) as raised:
                worker.extract_pdf_text(raw)
        self.assertEqual(raised.exception.code, "pdf_extraction_timeout")
        self.assertNotIn("bounded", raised.exception.message)

        oversized = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=b"x" * (worker.MAX_PDF_CHILD_RESPONSE + 1),
        )
        with mock.patch.object(worker.subprocess, "run", return_value=oversized):
            with self.assertRaises(worker.WorkerError) as raised:
                worker.extract_pdf_text(raw)
        self.assertEqual(raised.exception.code, "unsupported_source")

    def test_parser_receives_no_ambient_credentials(self) -> None:
        raw = pdf_with_text("bounded")
        result = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps({"title": "", "content": "bounded"}).encode(),
        )
        with mock.patch.object(worker.subprocess, "run", return_value=result) as run:
            worker.extract_pdf_text(raw)
        arguments, options = run.call_args
        self.assertEqual(arguments[0][-1], worker.PDF_CHILD_MODE)
        self.assertEqual(
            options["env"],
            {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"},
        )
        self.assertTrue(options["close_fds"])
        self.assertEqual(options["cwd"], "/")

    def test_invalid_pdf_is_rejected_without_invoking_parser(self) -> None:
        with mock.patch.object(worker.subprocess, "run") as run:
            with self.assertRaises(worker.WorkerError) as raised:
                worker.extract_pdf_text(b"not a PDF")
        self.assertEqual(raised.exception.code, "unsupported_source")
        run.assert_not_called()

    def test_public_url_boundary_rejects_ambiguous_paths_before_dns(self) -> None:
        for invalid_url in (
            "https://valid.example/source with-space",
            "https://valid.example/source\u00a0with-space",
            "https://valid.example/caf\u00e9",
            "https://valid.example/a\\b",
            f"https://{'a' * 64}.example/source",
            "https://a..example/source",
            "https://-a.example/source",
            "https://a-.example/source",
            "https://a.example../source",
        ):
            with self.subTest(invalid_url=invalid_url):
                with mock.patch.object(
                    worker,
                    "resolve_public_addresses",
                ) as resolve:
                    with self.assertRaises(worker.WorkerError) as raised:
                        worker.public_destination(invalid_url)
                self.assertEqual(raised.exception.code, "invalid_source_url")
                resolve.assert_not_called()

    def test_public_url_boundary_accepts_encoded_international_uri_forms(self) -> None:
        for valid_url, expected_host in (
            (
                "https://xn--caf-dma.example/caf%C3%A9",
                "xn--caf-dma.example",
            ),
            (
                "https://[2606:4700:4700::1111]/source",
                "2606:4700:4700::1111",
            ),
            (
                "https://valid.example./source",
                "valid.example",
            ),
        ):
            with self.subTest(valid_url=valid_url):
                _url, _parsed, host, _port = worker.public_url_shape(valid_url)
                self.assertEqual(host, expected_host)

    def test_extract_batch_remains_fail_fast_without_partial_results(self) -> None:
        failure = worker.WorkerError(502, "unsupported_source", "source failed")
        with mock.patch.object(
            worker,
            "fetch_public_page",
            side_effect=[
                ("https://one.example", "One", "first"),
                failure,
                ("https://three.example", "Three", "third"),
            ],
        ) as fetch:
            with self.assertRaises(worker.WorkerError) as raised:
                worker.extract(
                    {"urls": ["https://one.example", "https://two.example", "https://three.example"]}
                )
        self.assertIs(raised.exception, failure)
        self.assertEqual(fetch.call_count, 2)

    @unittest.skipUnless(PYPDF_AVAILABLE, "pypdf is installed in the research worker image")
    def test_pdf_uses_existing_pinned_fetch_and_response_contract(self) -> None:
        raw = pdf_with_text("Authoritative source")

        class Headers:
            def get(self, name: str, default: str | None = None) -> str | None:
                return "identity" if name == "Content-Encoding" else default

            def get_content_type(self) -> str:
                return "application/pdf"

        class Response:
            status = 200
            headers = Headers()

            def read(self, maximum: int) -> bytes:
                self.maximum = maximum
                return raw

        class Connection:
            closed = False

            def close(self) -> None:
                self.closed = True

        response = Response()
        connection = Connection()
        parsed = urllib.parse.urlsplit("https://source.example/report.pdf")
        with (
            mock.patch.object(
                worker,
                "public_destination",
                return_value=("https://source.example/report.pdf", parsed, ["93.184.216.34"]),
            ) as destination,
            mock.patch.object(worker, "request_public_page", return_value=(response, connection)) as request,
        ):
            url, title, content = worker.fetch_public_page("https://source.example/report.pdf")

        destination.assert_called_once_with("https://source.example/report.pdf")
        request.assert_called_once_with(parsed, ["93.184.216.34"])
        self.assertEqual(response.maximum, worker.MAX_UPSTREAM + 1)
        self.assertTrue(connection.closed)
        self.assertEqual((url, title), ("https://source.example/report.pdf", ""))
        self.assertIn("Authoritative source", content)


class TotalBatchExtractionTests(unittest.TestCase):
    def fixture_process_factory(
        self,
        replies: dict[str, object],
        *,
        delays: dict[str, float] | None = None,
        hanging: set[str] | None = None,
        launched: list[subprocess.Popen[bytes]] | None = None,
    ) -> object:
        delays = delays or {}
        hanging = hanging or set()

        def factory(index: int, requested_url: str, batch_deadline: float) -> worker.V2SourceProcess:
            if requested_url in hanging:
                script = "import time; time.sleep(60)"
                arguments = [worker.sys.executable, "-I", "-c", script]
            else:
                value = replies[requested_url]
                raw = value if isinstance(value, bytes) else json.dumps(
                    value,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode()
                encoded = base64.b64encode(raw).decode("ascii")
                script = (
                    "import base64,sys,time;"
                    "time.sleep(float(sys.argv[1]));"
                    "sys.stdout.buffer.write(base64.b64decode(sys.argv[2]))"
                )
                arguments = [
                    worker.sys.executable,
                    "-I",
                    "-c",
                    script,
                    str(delays.get(requested_url, 0)),
                    encoded,
                ]
            process = subprocess.Popen(
                arguments,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
            )
            if process.stdout is None:
                self.fail("fixture process has no stdout")
            stdout_fd = process.stdout.fileno()
            worker.os.set_blocking(stdout_fd, False)
            if launched is not None:
                launched.append(process)
            return worker.V2SourceProcess(
                index=index,
                requested_url=requested_url,
                process=process,
                deadline=min(
                    batch_deadline,
                    time.monotonic() + worker.V2_SOURCE_SECONDS,
                ),
                output=bytearray(),
                stdout_fd=stdout_fd,
            )

        return factory

    @staticmethod
    def extracted_outcome(
        requested_url: str,
        *,
        resolved_url: str | None = None,
        title: str = "",
        content: str = "bounded",
        truncated: bool = False,
        source_media_type: str = "text/html",
    ) -> dict[str, object]:
        return {
            "requested_url": requested_url,
            "disposition": "extracted",
            "resolved_url": resolved_url or requested_url,
            "source_media_type": source_media_type,
            "title": title,
            "content": content,
            "content_type": "text/plain",
            "content_truncated": truncated,
        }

    def test_v2_returns_one_ordered_outcome_per_url(self) -> None:
        urls = [
            "https://slow.example/source",
            "https://rejected.example/source",
            "https://fast.example/source",
        ]

        replies = {
            urls[0]: self.extracted_outcome(
                urls[0],
                resolved_url="https://resolved.example/slow",
                title="Slow",
                content="first",
            ),
            urls[1]: {
                "requested_url": urls[1],
                "disposition": "failed",
                "failure_code": "source_rejected",
            },
            urls[2]: self.extracted_outcome(urls[2], title="Fast", content="third"),
        }
        factory = self.fixture_process_factory(
            replies,
            delays={urls[0]: 0.08, urls[2]: 0.01},
        )
        with mock.patch.object(worker, "start_v2_source_process", side_effect=factory):
            result = worker.extract_v2({"urls": urls})

        self.assertEqual(result["schema_version"], "steward.research-extract-result.v2")
        self.assertEqual(
            [outcome["requested_url"] for outcome in result["outcomes"]],
            urls,
        )
        self.assertEqual(
            [outcome["disposition"] for outcome in result["outcomes"]],
            ["extracted", "failed", "extracted"],
        )
        self.assertEqual(
            result["outcomes"][0],
            {
                "requested_url": urls[0],
                "disposition": "extracted",
                "resolved_url": "https://resolved.example/slow",
                "source_media_type": "text/html",
                "title": "Slow",
                "content": "first",
                "content_type": "text/plain",
                "content_truncated": False,
            },
        )
        self.assertEqual(
            result["outcomes"][1],
            {
                "requested_url": urls[1],
                "disposition": "failed",
                "failure_code": "source_rejected",
            },
        )
        self.assertNotIn("diagnostic", json.dumps(result))

    def test_v2_real_child_keeps_private_destination_failure_local(self) -> None:
        requested_url = "http://127.0.0.1/private"
        result = worker.extract_v2({"urls": [requested_url]})
        self.assertEqual(
            result,
            {
                "schema_version": "steward.research-extract-result.v2",
                "outcomes": [
                    {
                        "requested_url": requested_url,
                        "disposition": "failed",
                        "failure_code": "private_source_denied",
                    }
                ],
            },
        )

    def test_v2_source_failures_are_values_under_http_200(self) -> None:
        urls = ["https://one.example/source", "https://two.example/source"]
        server = worker.http.server.HTTPServer(("127.0.0.1", 0), worker.Handler)
        server.worker_token = b"fixture-worker-token"
        server.search_upstream = None
        serving = threading.Thread(target=server.handle_request)
        body = json.dumps({"urls": urls}, separators=(",", ":")).encode()
        replies = {
            urls[0]: self.extracted_outcome(urls[0], title="One", content="first"),
            urls[1]: {
                "requested_url": urls[1],
                "disposition": "failed",
                "failure_code": "source_rejected",
            },
        }
        factory = self.fixture_process_factory(replies)

        try:
            with mock.patch.object(worker, "start_v2_source_process", side_effect=factory):
                serving.start()
                connection = worker.http.client.HTTPConnection(
                    "127.0.0.1",
                    server.server_port,
                    timeout=2,
                )
                try:
                    connection.request(
                        "POST",
                        "/v2/extract",
                        body=body,
                        headers={
                            "Authorization": "Bearer fixture-worker-token",
                            "Content-Type": "application/json",
                            "Content-Length": str(len(body)),
                        },
                    )
                    response = connection.getresponse()
                    response_body = response.read()
                finally:
                    connection.close()
        finally:
            server.server_close()
            serving.join(2)

        self.assertFalse(serving.is_alive())
        self.assertEqual(response.status, 200)
        result = json.loads(response_body)
        self.assertEqual(
            [outcome["disposition"] for outcome in result["outcomes"]],
            ["extracted", "failed"],
        )
        self.assertEqual(result["outcomes"][1]["failure_code"], "source_rejected")
        self.assertNotIn(b"private upstream detail", response_body)

    def test_v2_accepts_canonical_public_json_extraction(self) -> None:
        requested_url = "https://source.example/data"
        with mock.patch.object(
            worker,
            "fetch_public_page",
            return_value=(
                requested_url,
                "",
                '{\n  "address": "2861 Niagara Avenue"\n}',
                "application/json",
            ),
        ):
            outcome = worker.extract_v2_outcome(
                requested_url,
                time.monotonic() + worker.V2_BATCH_SECONDS,
            )

        self.assertEqual(outcome["disposition"], "extracted")
        self.assertEqual(outcome["source_media_type"], "application/json")
        self.assertEqual(outcome["content_type"], "text/plain")
        self.assertIn("2861 Niagara Avenue", outcome["content"])

    def test_v2_failure_codes_are_closed_and_message_free(self) -> None:
        expected = {
            "source_unresolvable",
            "private_source_denied",
            "source_unavailable",
            "invalid_source_redirect",
            "source_rejected",
            "unsupported_source",
            "source_too_large",
            "pdf_extraction_timeout",
        }
        self.assertEqual(worker.V2_SOURCE_FAILURE_CODES, expected)
        for code in sorted(expected):
            with self.subTest(code=code):
                failure = worker.WorkerError(502, code, f"sensitive {code} details")
                with mock.patch.object(worker, "fetch_public_page", side_effect=failure):
                    outcome = worker.extract_v2_outcome(
                        "https://source.example/report",
                        time.monotonic() + worker.V2_BATCH_SECONDS,
                    )
                self.assertEqual(
                    outcome,
                    {
                        "requested_url": "https://source.example/report",
                        "disposition": "failed",
                        "failure_code": code,
                    },
                )

    def test_v2_request_and_protocol_failures_reject_the_whole_call(self) -> None:
        with mock.patch.object(worker, "start_v2_source_process") as start:
            with self.assertRaises(worker.WorkerError) as raised:
                worker.extract_v2(
                    {"urls": ["https://valid.example/source", "file:///etc/passwd"]}
                )
        self.assertEqual(raised.exception.code, "invalid_source_url")
        start.assert_not_called()

        for invalid_url in (
            "https://valid.example/source with-space",
            "https://valid.example/source\u00a0with-space",
            "https://valid.example/caf\u00e9",
            "https://valid.example/a\\b",
            f"https://{'a' * 64}.example/source",
            "https://a..example/source",
        ):
            with self.subTest(invalid_url=invalid_url):
                with mock.patch.object(worker, "start_v2_source_process") as start:
                    with self.assertRaises(worker.WorkerError) as raised:
                        worker.extract_v2({"urls": [invalid_url]})
                self.assertEqual(raised.exception.code, "invalid_source_url")
                start.assert_not_called()

        for code in ("invalid_source_url", "invalid_request", "upstream_unavailable"):
            with self.subTest(code=code):
                failure = worker.WorkerError(502, code, "whole-call failure")
                with mock.patch.object(worker, "fetch_public_page", side_effect=failure):
                    with self.assertRaises(worker.WorkerError) as raised:
                        worker.extract_v2_outcome(
                            "https://source.example/report",
                            time.monotonic() + worker.V2_BATCH_SECONDS,
                        )
                self.assertIs(raised.exception, failure)

        requested_url = "https://source.example/report"
        factory = self.fixture_process_factory({requested_url: b'{"unexpected":true}'})
        with mock.patch.object(worker, "start_v2_source_process", side_effect=factory):
            with self.assertRaisesRegex(RuntimeError, "invalid outcome"):
                worker.extract_v2({"urls": [requested_url]})

    def test_v2_bounds_normalized_text_and_the_total_response(self) -> None:
        self.assertEqual(worker.normalized_v2_text("\x00safe")[0], " safe")
        urls = []
        for index in range(10):
            prefix = f"https://source-{index}.example/"
            urls.append(prefix + ("a" * (2048 - len(prefix.encode("utf-8")))))
        raw_content = "\\" * (worker.MAX_V2_SOURCE_TEXT + 4096)
        with mock.patch.object(
            worker,
            "fetch_public_page",
            side_effect=lambda url, *, deadline, include_source_media: (
                url,
                "\x00" * 2048,
                raw_content,
                "text/plain",
            ),
        ):
            sample = worker.extract_v2_outcome(urls[0], time.monotonic() + 1)
        replies = {
            url: {
                **sample,
                "requested_url": url,
                "resolved_url": url,
            }
            for url in urls
        }
        factory = self.fixture_process_factory(replies)
        with mock.patch.object(worker, "start_v2_source_process", side_effect=factory):
            result = worker.extract_v2({"urls": urls})

        for outcome in result["outcomes"]:
            self.assertEqual(len(outcome["content"].encode("utf-8")), worker.MAX_V2_SOURCE_TEXT)
            self.assertTrue(outcome["content_truncated"])
        encoded = json.dumps(
            result,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        self.assertLessEqual(len(encoded), worker.MAX_RESPONSE)

    def test_v2_never_exceeds_its_fixed_concurrency(self) -> None:
        urls = [f"https://source-{index}.example/report" for index in range(10)]
        replies = {url: self.extracted_outcome(url) for url in urls}
        launched: list[subprocess.Popen[bytes]] = []
        base_factory = self.fixture_process_factory(
            replies,
            delays={url: 0.2 for url in urls},
            launched=launched,
        )
        maximum = 0

        def factory(index: int, requested_url: str, batch_deadline: float) -> worker.V2SourceProcess:
            nonlocal maximum
            source = base_factory(index, requested_url, batch_deadline)
            active = sum(process.poll() is None for process in launched)
            maximum = max(maximum, active)
            return source

        with mock.patch.object(worker, "start_v2_source_process", side_effect=factory):
            result = worker.extract_v2({"urls": urls})

        self.assertEqual(len(result["outcomes"]), len(urls))
        self.assertEqual(maximum, worker.V2_MAX_CONCURRENCY)

    def test_v2_kills_hung_sources_within_the_shared_deadline(self) -> None:
        urls = [f"https://hung-{index}.example/report" for index in range(10)]
        launched: list[subprocess.Popen[bytes]] = []
        factory = self.fixture_process_factory(
            {},
            hanging=set(urls),
            launched=launched,
        )
        started = time.monotonic()
        with (
            mock.patch.object(worker, "start_v2_source_process", side_effect=factory),
            mock.patch.object(worker, "V2_SOURCE_SECONDS", 0.08),
            mock.patch.object(worker, "V2_BATCH_SECONDS", 0.2),
        ):
            result = worker.extract_v2({"urls": urls})
        elapsed = time.monotonic() - started

        self.assertLess(elapsed, 1)
        self.assertEqual(
            [outcome["failure_code"] for outcome in result["outcomes"]],
            ["source_unavailable"] * len(urls),
        )
        self.assertTrue(launched)
        self.assertTrue(all(process.poll() is not None for process in launched))

    def test_expired_source_deadline_uses_existing_failure_code(self) -> None:
        with mock.patch.object(worker.time, "monotonic", return_value=100):
            with self.assertRaises(worker.WorkerError) as raised:
                worker.remaining_source_seconds(99)
        self.assertEqual(raised.exception.code, "source_unavailable")

    def test_v2_never_waits_indefinitely_for_a_killed_child(self) -> None:
        class StuckProcess:
            pid = 12345
            stdout = None

            def poll(self) -> None:
                return None

            def wait(self, *, timeout: float) -> None:
                self.timeout = timeout
                raise subprocess.TimeoutExpired(cmd="source", timeout=timeout)

        process = StuckProcess()
        source = worker.V2SourceProcess(
            index=0,
            requested_url="https://source.example/report",
            process=process,
            deadline=time.monotonic(),
            output=bytearray(),
            stdout_fd=None,
        )
        selector = worker.selectors.DefaultSelector()
        try:
            with (
                mock.patch.object(worker, "V2_PENDING_REAPS", []) as pending,
                mock.patch.object(worker.os, "killpg") as kill_group,
            ):
                worker.stop_v2_source_process(selector, source, kill=True)
                self.assertEqual(process.timeout, 0.05)
                self.assertEqual(pending, [process])
                kill_group.assert_called_once_with(process.pid, worker.signal.SIGKILL)
        finally:
            selector.close()


if __name__ == "__main__":
    unittest.main()
