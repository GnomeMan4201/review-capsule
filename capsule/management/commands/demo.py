"""Synthetic fixture only. No real studies, human reviews or automatic invitations."""
import getpass
from datetime import timedelta
from django.conf import settings
from django.core.management.base import BaseCommand,CommandError
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db import transaction
from capsule.models import Study,Round,Assignment
class Command(BaseCommand):
    help='Create a local synthetic study and four role accounts; prompts for a local demo password.'
    @transaction.atomic
    def handle(self,*args,**kwargs):
        if not settings.DEBUG:raise CommandError('Synthetic demo command is local-only.')
        names=('demo-author','demo-steward','demo-reviewer-a','demo-reviewer-b')
        if get_user_model().objects.filter(username__in=names).exists():raise CommandError('Demo accounts already exist; no overwrite.')
        password=getpass.getpass('Choose a local demo password (12+ characters): ')
        if len(password)<12:raise CommandError('Use at least 12 characters.')
        users=[get_user_model().objects.create_user(username=name,password=password) for name in names]
        study=Study.objects.create(title='Synthetic evidence support • demo',author=users[0],steward=users[1])
        packet=[{'id':'item-1','evidence':['A laboratory note records that Sensor A displayed 18 at noon.','The same note records that Sensor B displayed 18 at noon.'],'candidate':'The matching readings establish that both sensors used the same power supply.'},
        {'id':'item-2','evidence':['A stipulated authentic maintenance record identifies Pump K as serviced on Monday.'],'candidate':'According to the maintenance record, Pump K was serviced on Monday.'}]
        r=Round.objects.create(study=study,question='Judge whether each exact conclusion is established by the supplied synthetic evidence.',packet=packet,withheld={'item-1':'NOT_ESTABLISHED','item-2':'ESTABLISHED','notice':'Synthetic author-expected labels; not independent adjudication.'},deadline=timezone.now()+timedelta(days=7))
        [Assignment.objects.create(round=r,reviewer=u) for u in users[2:]]
        from capsule.services import event
        event(r,users[0],'draft_created',synthetic=True)
        self.stdout.write('Created a DRAFT synthetic study. Accounts: '+', '.join(names))
        self.stdout.write('Open the author desk, inspect the exact packet, then freeze it. Use separate browser profiles for the four roles. These are demo accounts, not independent reviewers.')
