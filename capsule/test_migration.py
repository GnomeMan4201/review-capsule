"""Legacy data preservation rehearsal; Django, Python 3.12 [needs Linux runner]."""
from datetime import timedelta
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase
from django.utils import timezone

class LegacyMigrationTests(TransactionTestCase):
    def test_existing_contract_answers_and_secrets_survive_migration(self):
        old_target=[('capsule','0002_loginwindow')]
        new_target=[('capsule','0003_roundsecrets_remove_round_withheld_and_more')]
        executor=MigrationExecutor(connection);executor.migrate(old_target)
        try:
            apps=executor.loader.project_state(old_target).apps
            User=apps.get_model('auth','User');Study=apps.get_model('capsule','Study');Round=apps.get_model('capsule','Round')
            author=User.objects.create(username='legacy-author');steward=User.objects.create(username='legacy-steward')
            study=Study.objects.create(title='Legacy synthetic fixture',author=author,steward=steward)
            r=Round.objects.create(study=study,question='Legacy task',packet=[{'id':'x','evidence':['X'],'candidate':'X'}],
                withheld={'private-canary':'UNCHANGED-SECRET'},deadline=timezone.now()+timedelta(days=1),
                state='open',contract={'legacy':'exact frozen contract'},contract_nonce='original-nonce',commitment='a'*64)
            Event=apps.get_model('capsule','Event');Event.objects.create(round=r,actor=author,kind='round_frozen',detail={'commitment':r.commitment})
            executor=MigrationExecutor(connection);executor.migrate(new_target)
            from .models import Round as CurrentRound,RoundSecrets,Event as CurrentEvent
            updated=CurrentRound.objects.get(pk=r.pk)
            self.assertEqual(updated.protocol,'0.1');self.assertEqual(updated.commitment,'a'*64)
            self.assertEqual(updated.contract,{'legacy':'exact frozen contract'});self.assertEqual(updated.state,'open')
            self.assertEqual(RoundSecrets.objects.get(round=updated).withheld,{'private-canary':'UNCHANGED-SECRET'})
            self.assertEqual(len(CurrentEvent.objects.get(round=updated).hash),64)
            self.assertEqual(CurrentEvent.objects.get(round=updated).previous_hash,'')
            # Reversing restores withheld JSON before restoring the old NOT NULL field.
            executor=MigrationExecutor(connection);executor.migrate(old_target)
            old=executor.loader.project_state(old_target).apps.get_model('capsule','Round').objects.get(pk=r.pk)
            self.assertEqual(old.withheld,{'private-canary':'UNCHANGED-SECRET'})
        finally:
            MigrationExecutor(connection).migrate(new_target)
