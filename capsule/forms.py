from django import forms
from django.contrib.auth import get_user_model
from django.utils import timezone
from .services import check_packet
class StudyForm(forms.Form):
    title=forms.CharField(max_length=180,label='Neutral study title')
    question=forms.CharField(widget=forms.Textarea,label='What should reviewers assess?')
    steward=forms.CharField(label='Separate steward username')
    reviewers=forms.CharField(label='Reviewer usernames, separated by commas')
    deadline=forms.DateTimeField(label='Round deadline (UTC)',input_formats=['%Y-%m-%d %H:%M'])
    packet=forms.JSONField(label='Reviewer packet JSON',help_text='Only id, evidence and candidate in each item. Never put expected answers here.')
    withheld=forms.JSONField(label='Withheld results JSON',help_text='Stored separately. Released to eligible assigned reviewers after closure.')
    def clean_packet(self):
        value=self.cleaned_data['packet'];check_packet(value);return value
    def clean_deadline(self):
        value=self.cleaned_data['deadline']
        if value<=timezone.now():raise forms.ValidationError('Use a future UTC deadline.')
        return value
    def clean_steward(self):
        name=self.cleaned_data['steward']
        try:return get_user_model().objects.get(username=name)
        except get_user_model().DoesNotExist:raise forms.ValidationError('Unknown account. Create local accounts before assignment.')
    def clean_reviewers(self):
        names=[x.strip() for x in self.cleaned_data['reviewers'].split(',') if x.strip()]
        if len(set(names))<2 or len(set(names))!=len(names):raise forms.ValidationError('Use at least two different accounts.')
        users=list(get_user_model().objects.filter(username__in=names))
        if len(users)!=len(names):raise forms.ValidationError('One or more accounts do not exist.')
        return users
class DeclarationForm(forms.Form):
    CHOICES=[('','Select a response'),('yes','Yes'),('no','No')]
    conflict=forms.ChoiceField(choices=CHOICES,label='Do you have a relationship or interest that could conflict with this review?')
    prior_exposure=forms.ChoiceField(choices=CHOICES,label='Have you seen expected answers, results, or other assessments for this study?')
    ai_assessment=forms.ChoiceField(choices=CHOICES,label='Have you used, or do you plan to use, AI to make the evaluative judgments in this assignment?')
    note=forms.CharField(required=False,max_length=4000,widget=forms.Textarea,label='Context or uncertainty for the steward')
class ReasonForm(forms.Form):
    text=forms.CharField(max_length=4000,widget=forms.Textarea,label='Reason / details')
