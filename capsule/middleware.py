import hashlib
import hmac
from datetime import timedelta
from django.conf import settings
from django.db import transaction
from django.http import HttpResponse
from django.utils import timezone

class LoginThrottle:
    def __init__(self,get_response): self.get_response=get_response

    @transaction.atomic
    def allowed(self,request):
        from .models import LoginWindow
        now=timezone.now()
        identifiers=(('account:'+request.POST.get('username','')[:150],20),
                     ('address:'+request.META.get('REMOTE_ADDR','unknown'),80))
        accepted=True
        for identifier,limit in identifiers:
            key=hmac.new(settings.SECRET_KEY.encode(),identifier.encode(),hashlib.sha256).hexdigest()
            row,_=LoginWindow.objects.select_for_update().get_or_create(key=key,defaults={'started_at':now})
            if now-row.started_at>=timedelta(minutes=10):
                row.started_at=now;row.attempts=0
            if row.attempts>=limit:
                accepted=False
            else:
                row.attempts+=1
                row.save(update_fields=['started_at','attempts'])
        return accepted

    def __call__(self,request):
        if request.path=='/login/' and request.method=='POST' and not settings.DEBUG and not self.allowed(request):
            response=HttpResponse('Too many sign-in attempts. Try again in 10 minutes.',status=429)
            response['Retry-After']='600'
            return response
        return self.get_response(request)

class PrivateResponses:
    def __init__(self,get_response): self.get_response=get_response
    def __call__(self,request):
        response=self.get_response(request)
        response['Cache-Control']='no-store, private'
        response['X-Content-Type-Options']='nosniff'
        response['X-Frame-Options']='DENY'
        response['Content-Security-Policy']="default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'none'; img-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        return response
