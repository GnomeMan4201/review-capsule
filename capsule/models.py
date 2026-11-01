import uuid
from django.conf import settings
from django.db import models, transaction
from django.core.exceptions import ValidationError
from django.utils import timezone

class LoginWindow(models.Model):
    key=models.CharField(max_length=64,primary_key=True)
    started_at=models.DateTimeField()
    attempts=models.PositiveIntegerField(default=0)

class Study(models.Model):
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    title=models.CharField(max_length=180)
    author=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.PROTECT,related_name='authored_studies')
    steward=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.PROTECT,related_name='stewarded_studies')
    created_at=models.DateTimeField(auto_now_add=True)

class GuardedQuerySet(models.QuerySet):
    def update(self, **kwargs):
        self.model.guard_update(self, kwargs)
        return super().update(**kwargs)
    def delete(self):
        self.model.guard_delete(self)
        return super().delete()
    def bulk_create(self, objs, **kwargs):
        if self.model.__name__ in ('Assignment', 'RoundSecrets', 'Event', 'Assessment'):
            raise ValidationError('Use individual saves for guarded records.')
        return super().bulk_create(objs, **kwargs)

class Round(models.Model):
    objects = GuardedQuerySet.as_manager()
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    study=models.ForeignKey(Study,on_delete=models.PROTECT)
    version=models.PositiveIntegerField(default=1)
    question=models.TextField()
    packet=models.JSONField()
    deadline=models.DateTimeField()
    state=models.CharField(max_length=12,default='draft')
    protocol=models.CharField(max_length=8,default='0.2')
    previous=models.ForeignKey('self',null=True,blank=True,on_delete=models.PROTECT,related_name='corrections')
    anchor_url=models.URLField(max_length=2000,blank=True)
    anchored_at=models.DateTimeField(null=True,blank=True)
    contract=models.JSONField(default=dict)
    contract_nonce=models.CharField(max_length=64,blank=True)
    commitment=models.CharField(max_length=64,blank=True)
    closed_at=models.DateTimeField(null=True)
    @property
    def withheld(self):
        if hasattr(self, '_pending_withheld'): return self._pending_withheld
        try: return self.secrets.withheld
        except RoundSecrets.DoesNotExist: return {}
    @withheld.setter
    def withheld(self, value): self._pending_withheld=value
    @classmethod
    def guard_update(cls, rows, fields):
        protected={'study','study_id','version','question','packet','deadline','contract','contract_nonce','commitment','protocol','previous','previous_id'}
        if protected.intersection(fields) and rows.exclude(commitment='').exists():
            raise ValidationError('Frozen fields cannot change; create a linked round version.')
    @classmethod
    def guard_delete(cls, rows):
        if rows.exclude(commitment='').exists(): raise ValidationError('Frozen rounds cannot be deleted.')
    @transaction.atomic
    def save(self, *args, **kwargs):
        old=Round.objects.filter(pk=self.pk).first()
        if old and old.commitment:
            fields=['study_id','version','question','packet','deadline','contract','contract_nonce','commitment','protocol','previous_id']
            if any(getattr(old,f)!=getattr(self,f) for f in fields):
                raise ValidationError('Frozen fields cannot change; create a linked round version.')
        super().save(*args, **kwargs)
        if hasattr(self,'_pending_withheld'):
            value=self._pending_withheld
            secret,created=RoundSecrets.objects.get_or_create(round=self,defaults={'withheld':value})
            if not created and secret.withheld!=value:
                secret.withheld=value;secret.save()
            del self._pending_withheld
    def delete(self,*args,**kwargs):
        self.guard_delete(Round.objects.filter(pk=self.pk));return super().delete(*args,**kwargs)
    class Meta:
        constraints=[models.UniqueConstraint(fields=['study','version'],name='unique_study_version')]

class RoundSecrets(models.Model):
    objects=GuardedQuerySet.as_manager()
    round=models.OneToOneField(Round,primary_key=True,on_delete=models.PROTECT,related_name='secrets')
    withheld=models.JSONField(default=dict)
    calibration=models.JSONField(default=dict)
    @classmethod
    def guard_update(cls,rows,fields):
        if rows.exclude(round__commitment='').exists(): raise ValidationError('Frozen private material cannot change.')
    @classmethod
    def guard_delete(cls,rows): cls.guard_update(rows,{})
    def save(self,*args,**kwargs):
        if self.round.commitment or Round.objects.filter(pk=self.round_id).exclude(commitment='').exists():
            old=RoundSecrets.objects.filter(pk=self.pk).first()
            if old is None or old.withheld!=self.withheld or old.calibration!=self.calibration:
                raise ValidationError('Frozen private material cannot change.')
        return super().save(*args,**kwargs)
    def delete(self,*args,**kwargs):
        self.guard_delete(RoundSecrets.objects.filter(pk=self.pk));return super().delete(*args,**kwargs)

class Assignment(models.Model):
    objects=GuardedQuerySet.as_manager()
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    round=models.ForeignKey(Round,on_delete=models.PROTECT)
    reviewer=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.PROTECT)
    declaration=models.JSONField(null=True)
    declared_at=models.DateTimeField(null=True)
    eligible=models.BooleanField(default=False)
    decision_reason=models.TextField(blank=True)
    decided_at=models.DateTimeField(null=True)
    class Meta:
        constraints=[models.UniqueConstraint(fields=['round','reviewer'],name='one_assignment_per_reviewer')]

    @classmethod
    def guard_update(cls,rows,fields):
        target=fields.get('round_id',getattr(fields.get('round'), 'pk', None))
        if target and Round.objects.filter(pk=target).exclude(commitment='').exists(): raise ValidationError('Frozen roster cannot change.')
        if {'declaration','declared_at'}.intersection(fields) and rows.filter(declared_at__isnull=False).exists(): raise ValidationError('The initial declaration is locked.')
        if {'round','round_id','reviewer','reviewer_id'}.intersection(fields) and rows.exclude(round__commitment='').exists():
            raise ValidationError('Frozen roster cannot change.')
    @classmethod
    def guard_delete(cls,rows):
        if rows.exclude(round__commitment='').exists(): raise ValidationError('Frozen roster cannot change.')
    def save(self,*args,**kwargs):
        frozen=Round.objects.filter(pk=self.round_id).exclude(commitment='').exists()
        old=Assignment.objects.filter(pk=self.pk).first()
        if (frozen and (old is None or old.round_id!=self.round_id or old.reviewer_id!=self.reviewer_id)) or (old and old.round_id!=self.round_id and old.round.commitment):
            raise ValidationError('Frozen roster cannot change.')
        if old and old.declared_at and (old.declaration!=self.declaration or old.declared_at!=self.declared_at): raise ValidationError('The initial declaration is locked.')
        return super().save(*args,**kwargs)
    def delete(self,*args,**kwargs):
        self.guard_delete(Assignment.objects.filter(pk=self.pk));return super().delete(*args,**kwargs)

class AppendOnly(models.Model):
    objects=GuardedQuerySet.as_manager()
    class Meta: abstract=True
    @classmethod
    def guard_update(cls,rows,fields): raise ValidationError('Append-only record: updates are blocked.')
    @classmethod
    def guard_delete(cls,rows): raise ValidationError('Append-only record: deletion is blocked.')
    def save(self,*args,**kwargs):
        if not self._state.adding or (self.pk is not None and type(self).objects.filter(pk=self.pk).exists()): raise ValidationError('Append-only record: updates are blocked.')
        return super().save(*args,**kwargs)
    def delete(self,*args,**kwargs): raise ValidationError('Append-only record: deletion is blocked.')

class Assessment(AppendOnly):
    assignment=models.OneToOneField(Assignment,primary_key=True,on_delete=models.PROTECT)
    answers=models.JSONField()
    nonce=models.CharField(max_length=64)
    commitment=models.CharField(max_length=64)
    submitted_at=models.DateTimeField(default=timezone.now)
    item_receipts=models.JSONField(default=list)

class Amendment(AppendOnly):
    assessment=models.ForeignKey(Assessment,on_delete=models.PROTECT)
    text=models.TextField()
    created_at=models.DateTimeField(auto_now_add=True)

class Exposure(models.Model):
    assignment=models.ForeignKey(Assignment,on_delete=models.PROTECT)
    kind=models.CharField(max_length=32)
    detail=models.TextField(blank=True)
    created_at=models.DateTimeField(auto_now_add=True)

class Feedback(models.Model):
    round=models.ForeignKey(Round,on_delete=models.PROTECT)
    author=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.PROTECT)
    text=models.TextField()
    created_at=models.DateTimeField(auto_now_add=True)

class Event(AppendOnly):
    round=models.ForeignKey(Round,on_delete=models.PROTECT)
    actor=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.PROTECT)
    kind=models.CharField(max_length=40)
    detail=models.JSONField(default=dict)
    created_at=models.DateTimeField(default=timezone.now)

    previous_hash=models.CharField(max_length=64,blank=True)
    hash=models.CharField(max_length=64,blank=True)

    @transaction.atomic
    def save(self,*args,**kwargs):
        from .services import digest
        if not self._state.adding or (self.pk is not None and Event.objects.filter(pk=self.pk).exists()): raise ValidationError('Audit events cannot be changed.')
        Round.objects.select_for_update().get(pk=self.round_id)
        previous=Event.objects.filter(round_id=self.round_id).order_by('-id').first()
        self.previous_hash=previous.hash if previous else ''
        if not self.created_at: self.created_at=timezone.now()
        self.hash=digest({'round':str(self.round_id),'actor':self.actor_id,'kind':self.kind,
            'detail':self.detail,'timestamp':self.created_at.isoformat(),'previous_hash':self.previous_hash})
        return super().save(*args,**kwargs)
