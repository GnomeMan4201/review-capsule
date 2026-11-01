import uuid
from django.conf import settings
from django.db import models

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

class Round(models.Model):
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    study=models.ForeignKey(Study,on_delete=models.PROTECT)
    version=models.PositiveIntegerField(default=1)
    question=models.TextField()
    packet=models.JSONField()
    withheld=models.JSONField()
    deadline=models.DateTimeField()
    state=models.CharField(max_length=12,default='draft')
    contract=models.JSONField(default=dict)
    contract_nonce=models.CharField(max_length=64,blank=True)
    commitment=models.CharField(max_length=64,blank=True)
    closed_at=models.DateTimeField(null=True)
    class Meta:
        constraints=[models.UniqueConstraint(fields=['study','version'],name='unique_study_version')]

class Assignment(models.Model):
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

class Assessment(models.Model):
    assignment=models.OneToOneField(Assignment,primary_key=True,on_delete=models.PROTECT)
    answers=models.JSONField()
    nonce=models.CharField(max_length=64)
    commitment=models.CharField(max_length=64)
    submitted_at=models.DateTimeField(auto_now_add=True)

class Amendment(models.Model):
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

class Event(models.Model):
    round=models.ForeignKey(Round,on_delete=models.PROTECT)
    actor=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.PROTECT)
    kind=models.CharField(max_length=40)
    detail=models.JSONField(default=dict)
    created_at=models.DateTimeField(auto_now_add=True)
