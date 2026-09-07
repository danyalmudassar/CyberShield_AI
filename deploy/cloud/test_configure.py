import contextlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('cloud_configuration', Path(__file__).with_name('configure.py'))
configure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(configure)


class CloudConfigurationTests(unittest.TestCase):
    def invoke(self, root, domain, passwords):
        with patch.object(configure, '__file__', str(root / 'deploy/cloud/configure.py')), \
             patch('sys.argv', ['configure.py', '--domain', domain]), \
             patch.object(configure.getpass, 'getpass', side_effect=passwords), \
             contextlib.redirect_stdout(io.StringIO()) as output, \
             contextlib.redirect_stderr(io.StringIO()):
            configure.main()
            return output.getvalue()

    def test_private_configuration_without_printing_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            password = 'Temporary-test-credential-2026'
            output = self.invoke(root, 'security.example.com', [password, password])
            self.assertNotIn(password, output)
            self.assertEqual((root / '.cloud.env').stat().st_mode & 0o777, 0o600)
            self.assertEqual((root / 'deploy/cloud/runtime').stat().st_mode & 0o777, 0o700)
            self.assertEqual((root / 'deploy/cloud/runtime/operator_password').read_text(), password)

    def test_existing_configuration_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / '.cloud.env'
            config.write_text('preserve this')
            with self.assertRaises(SystemExit):
                self.invoke(root, 'security.example.com', [])
            self.assertEqual(config.read_text(), 'preserve this')

    def test_invalid_domain_has_no_side_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(SystemExit):
                self.invoke(root, 'https://example.com/injected', [])
            self.assertEqual(list(root.iterdir()), [])

    def test_password_mismatch_has_no_side_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(SystemExit):
                self.invoke(root, 'security.example.com', ['First-test-password', 'Second-test-password'])
            self.assertEqual(list(root.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
