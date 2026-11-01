"""Exercise HTTPS login with browser CSRF checks; Python 3.12+, Django."""
import re
from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings


@override_settings(SECURE_SSL_REDIRECT=True, SESSION_COOKIE_SECURE=True, CSRF_COOKIE_SECURE=True)
class HTTPSLoginTests(TestCase):
    def setUp(self):
        self.user=get_user_model().objects.create_user(username='synthetic-browser',password='synthetic-test-only-72941')
        self.browser=Client(enforce_csrf_checks=True)

    def form(self):
        response=self.browser.get('/login/',secure=True)
        token=re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"',response.content.decode()).group(1)
        return response,{'username':self.user.username,'password':'synthetic-test-only-72941','csrfmiddlewaretoken':token}

    def test_no_origin_https_form_can_sign_in_with_same_origin_referer(self):
        page,data=self.form()
        # A same-origin browser follows the response policy when sending Referer.
        headers={} if page['Referrer-Policy']=='no-referrer' else {'HTTP_REFERER':'https://testserver/login/'}
        response=self.browser.post('/login/',data,secure=True,**headers)
        self.assertEqual(response.status_code,302)
        self.assertEqual(self.browser.session['_auth_user_id'],str(self.user.pk))

    def test_cross_origin_or_cross_site_referer_is_rejected(self):
        _,data=self.form()
        for headers in ({'HTTP_ORIGIN':'https://untrusted.invalid','HTTP_REFERER':'https://testserver/login/'},
                        {'HTTP_REFERER':'https://untrusted.invalid/login/'}):
            with self.subTest(header=list(headers)):
                self.assertEqual(self.browser.post('/login/',data,secure=True,**headers).status_code,403)
        self.assertNotIn('_auth_user_id',self.browser.session)

    def test_missing_token_is_rejected_even_with_valid_origin(self):
        _,data=self.form()
        del data['csrfmiddlewaretoken']
        response=self.browser.post('/login/',data,secure=True,HTTP_ORIGIN='https://testserver')
        self.assertEqual(response.status_code,403)
        self.assertNotIn('_auth_user_id',self.browser.session)
