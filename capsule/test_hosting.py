import io
import os
from datetime import timedelta
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.http import HttpResponse
from django.test import TestCase, RequestFactory, override_settings
from django.utils import timezone
from capsule.middleware import LoginThrottle
from capsule.models import Study, Round, LoginWindow


class HostingTests(TestCase):
    @override_settings(SYNTHETIC_DEMO=False)
    def test_seed_requires_explicit_demo_mode(self):
        with self.assertRaises(CommandError):
            call_command('hosted_demo', stdout=io.StringIO())
        self.assertEqual(get_user_model().objects.count(), 0)

    @override_settings(SYNTHETIC_DEMO=True)
    @patch.dict(os.environ, {'CAPSULE_DEMO_PASSWORD': 'synthetic-test-password-123456'})
    def test_restart_preserves_credentials_packet_and_state(self):
        call_command('hosted_demo', stdout=io.StringIO())
        r=Round.objects.get()
        r.state='open'
        r.save(update_fields=['state'])
        original=get_user_model().objects.get(username='demo-author').password
        call_command('hosted_demo', stdout=io.StringIO())
        self.assertEqual(Study.objects.count(), 1)
        self.assertEqual(Round.objects.get().state, 'open')
        self.assertEqual(get_user_model().objects.get(username='demo-author').password, original)

    @override_settings(DEBUG=False)
    def test_login_throttle_is_shared_and_window_recovers(self):
        request=RequestFactory().post('/login/', {'username':'synthetic-account'})
        middleware=LoginThrottle(lambda r: HttpResponse('ok'))
        for _ in range(20):
            self.assertTrue(middleware.allowed(request))
        second=LoginThrottle(lambda r: HttpResponse('ok'))
        response=second(request)
        self.assertEqual(response.status_code,429)
        self.assertEqual(response['Retry-After'],'600')
        LoginWindow.objects.update(started_at=timezone.now()-timedelta(minutes=11))
        self.assertTrue(second.allowed(request))

    @override_settings(SYNTHETIC_DEMO=True)
    def test_banner_health_and_anonymous_boundary(self):
        response=self.client.get('/login/')
        self.assertContains(response,'Synthetic demo')
        self.assertEqual(self.client.get('/').status_code,302)
        response=self.client.get('/healthz/')
        self.assertEqual(response.json(), {'status':'ok'})
        self.assertEqual(response['Cache-Control'],'no-store, private')

    @override_settings(SECURE_SSL_REDIRECT=True, SECURE_PROXY_SSL_HEADER=('HTTP_X_FORWARDED_PROTO','https'))
    def test_proxy_https_and_healthcheck_redirect_policy(self):
        self.assertEqual(self.client.get('/login/').status_code,301)
        self.assertEqual(self.client.get('/login/', HTTP_X_FORWARDED_PROTO='https').status_code,200)
        self.assertEqual(self.client.get('/healthz/').status_code,200)
