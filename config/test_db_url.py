"""Check PostgreSQL URL decoding and secret-safe errors; Python 3.12+, stdlib."""
from unittest import TestCase
from .db_url import postgres_config


class DatabaseURLTests(TestCase):
    def test_encoded_credentials_and_database(self):
        config=postgres_config('postgresql://demo:p%40ss%3Aword@internal:5432/review%5Fdemo')
        self.assertEqual((config['PASSWORD'],config['NAME']),('p@ss:word','review_demo'))
        self.assertEqual(config['OPTIONS']['sslmode'],'require')

    def test_optional_port_and_ssl_mode(self):
        config=postgres_config('postgres://demo:test@internal/review?sslmode=verify-full')
        self.assertEqual(config['PORT'],'5432')
        self.assertEqual(config['OPTIONS']['sslmode'],'verify-full')

    def test_invalid_urls_do_not_disclose_credentials(self):
        for url in ('mysql://demo:SECRET@host/db','postgres://demo:SECRET@host:bad/db','postgres://demo:SECRET@host/'):
            with self.subTest(url_type=url.split(':')[0]):
                with self.assertRaises(ValueError) as raised:
                    postgres_config(url)
                self.assertNotIn('SECRET',str(raised.exception))
