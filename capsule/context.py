from django.conf import settings

def deployment(request):
    return {'synthetic_demo': settings.SYNTHETIC_DEMO}
