import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import seed_ledger


class SeedLedgerTests(unittest.TestCase):
    def test_refuses_committed_output_before_contacting_the_service(self):
        source = seed_ledger.SOURCE
        for out in (source, source / "live", source.parent):
            with self.subTest(out=out), patch(
                "sys.argv", ["seed_ledger.py", "--ledger", "unused.test", "--out", str(out)]
            ), patch.object(
                seed_ledger.fixtures, "service_cert"
            ) as fetch, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    seed_ledger.main()
                self.assertEqual(error.exception.code, 2)
                fetch.assert_not_called()

    def test_refuses_to_overwrite_an_existing_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "existing"
            marker.write_bytes(b"keep this capture")
            with patch(
                "sys.argv",
                ["seed_ledger.py", "--ledger", "unused.test", "--out", directory],
            ), patch.object(
                seed_ledger.fixtures, "service_cert"
            ) as fetch, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    seed_ledger.main()
                self.assertEqual(error.exception.code, 2)
                fetch.assert_not_called()
            self.assertEqual(marker.read_bytes(), b"keep this capture")

    def test_rejects_a_service_response_that_changes_the_signed_statement(self):
        source = seed_ledger.SOURCE
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "capture"
            with patch(
                "sys.argv",
                ["seed_ledger.py", "--ledger", "unused.test", "--out", str(out)],
            ), patch.object(
                seed_ledger.fixtures,
                "service_cert",
                return_value=(source / "mst-test-service-cert.pem").read_text(),
            ), patch.object(seed_ledger, "Client") as client:
                client.return_value.get.return_value.read.return_value = (
                    source / "mst-test-scitt-keys.cbor"
                ).read_bytes()
                client.return_value.submit_signed_statement_and_wait_for_receipt.return_value = (
                    SimpleNamespace(
                        is_receipt_embedded=True,
                        response_bytes=(source / "payload-tampered.cose").read_bytes(),
                    )
                )
                with self.assertRaisesRegex(ValueError, "changed the signed statement"):
                    seed_ledger.main()
            self.assertFalse(out.exists(), "a refused capture must not look usable")


if __name__ == "__main__":
    unittest.main()
