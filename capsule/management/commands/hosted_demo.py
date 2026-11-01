"""Seed synthetic roles once; Python 3.12+, Django [needs Linux runner]."""
import os
from datetime import timedelta
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone
from capsule.models import Study, Round, Assignment


class Command(BaseCommand):
    help = 'Initialize the explicitly enabled synthetic hosted demo; never reset accounts or judgments.'

    @transaction.atomic
    def handle(self, *args, **kwargs):
        if not settings.SYNTHETIC_DEMO:
            raise CommandError('This deployment requires CAPSULE_SYNTHETIC_DEMO=1. Real-study hosting is not qualified.')
        names = ('demo-author', 'demo-steward', 'demo-reviewer-a', 'demo-reviewer-b')
        existing = get_user_model().objects.filter(username__in=names).count()
        if existing == len(names):
            self.stdout.write('Synthetic demo already initialized; no data or credentials changed.')
            return
        if existing:
            raise CommandError('Partial demo accounts found; refusing to repair or overwrite silently.')
        password = os.environ.get('CAPSULE_DEMO_PASSWORD', '')
        if len(password) < 24:
            raise CommandError('Set CAPSULE_DEMO_PASSWORD to a generated password of at least 24 characters.')
        users = [get_user_model().objects.create_user(username=n, password=password) for n in names]
        study = Study.objects.create(title='Synthetic evidence support · hosted demo', author=users[0], steward=users[1])
        review_round = Round.objects.create(
            study=study,
            question='Judge whether each exact conclusion is established by the supplied synthetic evidence.',
            packet=[
                {'id': 'item-1', 'evidence': ['A laboratory note records that Sensor A displayed 18 at noon.', 'The same note records that Sensor B displayed 18 at noon.'], 'candidate': 'The matching readings establish that both sensors used the same power supply.'},
                {'id': 'item-2', 'evidence': ['A stipulated authentic maintenance record identifies Pump K as serviced on Monday.'], 'candidate': 'According to the maintenance record, Pump K was serviced on Monday.'},
            ],
            withheld={'item-1': 'NOT_ESTABLISHED', 'item-2': 'SUPPORTED', 'notice': 'Synthetic author-expected labels; not independent adjudication.'},
            deadline=timezone.now() + timedelta(days=7),
        )
        Assignment.objects.bulk_create([Assignment(round=review_round, reviewer=u) for u in users[2:]])
        self.stdout.write('Created one synthetic DRAFT and four demo roles. No real reviewer records.')
