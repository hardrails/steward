#!/usr/bin/env python3
"""Adversarial contract tests for the optional research worker."""

from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import subprocess
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


if __name__ == "__main__":
    unittest.main()
