import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('production_config', Path(__file__).with_name('verify-production-config.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ProductionConfigTests(unittest.TestCase):
    def test_valid_origins(self):
        for value in ['https://api.example.test', 'https://app.example.test/', 'https://example.test:8443/', 'https://[::1]/']:
            self.assertTrue(module.valid_origin(value), value)

    def test_invalid_origins(self):
        for value in ['', 'http://example.test', 'https://user:password@example.test', 'https://example.test/api/', 'https://example.test?', 'https://example.test#', 'https://example.test:invalid', 'https://exa mple.test', 'https://:@example.test', 'https://example.test%zz', 'https://example.test\\evil']:
            self.assertFalse(module.valid_origin(value), value)
