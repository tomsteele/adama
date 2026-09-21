import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("register_workers", Path(__file__).with_name("register-workers.py"))
registration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(registration)


class RegistrationTests(unittest.TestCase):
    def test_discovers_service_and_uses_actual_worker_name(self):
        calls = []

        def compose(*args, capture=False):
            calls.append(args)
            if args[0] == "config":
                return json.dumps({"services": {
                    "custom-service": {"labels": {"io.adama.worker": "true"}},
                    "not-a-worker": {},
                }})
            if "ADAMA_REGISTER_ONLY=1" in args:
                return json.dumps({"definition": {"version": 1, "name": "custom-runtime-name"}})

        with patch.object(registration, "compose", side_effect=compose):
            registration.register(build=False)
        self.assertIn(("run", "--rm", "--no-deps", "-T", "work", "inventory", "begin"), calls)
        self.assertEqual(calls[-1][-3:], ("inventory", "set", "custom-runtime-name"))
        self.assertFalse(any("not-a-worker" in call for call in calls))

    def test_failed_registration_never_marks_inventory_ready(self):
        calls = []

        def compose(*args, capture=False):
            calls.append(args)
            if args[0] == "config":
                return json.dumps({"services": {"broken": {"labels": {"io.adama.worker": "true"}}}})
            if "ADAMA_REGISTER_ONLY=1" in args:
                raise ValueError("invalid definition")

        with patch.object(registration, "compose", side_effect=compose):
            with self.assertRaises(ValueError):
                registration.register(build=False)
        self.assertTrue(any(call[-2:] == ("inventory", "begin") for call in calls))
        self.assertFalse(any("set" in call for call in calls))


if __name__ == "__main__":
    unittest.main()
