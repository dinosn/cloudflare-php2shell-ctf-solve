from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "src" / "stock")]

import wave_stock_live as wave  # noqa: E402


class _Socket:
    def __init__(self, raw: bytes):
        self.raw = raw
        self.sent = bytearray()

    def settimeout(self, timeout: float) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)

    def recv(self, size: int) -> bytes:
        raw, self.raw = self.raw, b""
        return raw

    def close(self) -> None:
        pass


class VerifierSchemaTest(unittest.TestCase):
    def test_exploit_id_derives_permalink(self) -> None:
        exploit_id = "5b4e2bf5-6726-4782-99f6-fad1172add42"
        entity = json.dumps({"verified": True, "exploitId": exploit_id}).encode()
        raw = (
            b"HTTP/1.1 200 OK\r\nContent-Length: "
            + str(len(entity)).encode()
            + b"\r\n\r\n"
            + entity
        )
        sock = _Socket(raw)
        with mock.patch.object(wave.socket, "create_connection", return_value=sock), \
                mock.patch.object(
                    wave.ssl.SSLContext, "wrap_socket", return_value=sock
                ):
            result, returned_raw = wave.verify_flag(
                "776b7a65-92bc-44ed-8266-af4cf4dc5090",
                "synthetic-test-flag",
                1.0,
            )

        self.assertEqual(raw, returned_raw)
        self.assertTrue(result["verified"])
        self.assertEqual(exploit_id, result["exploit_id"])
        self.assertEqual(
            f"https://php-rce.cloudflare.app/exploits/{exploit_id}",
            result["permalink"],
        )


if __name__ == "__main__":
    unittest.main()
