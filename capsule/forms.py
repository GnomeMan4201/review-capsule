from django import forms
from django.contrib.auth import get_user_model
from django.utils import timezone
from .services import check_packet,check_calibration

class EmptyJSONWidget(forms.Textarea):
    def format_value(self,value):
        return '' if value is None or value=='null' else super().format_value(value)

class StudyForm(forms.Form):
    title=forms.CharField(max_length=180,label='Neutral study title')
    question=forms.CharField(widget=forms.Textarea,label='What should reviewers assess?')
    steward=forms.CharField(label='Separate steward username')
    deadline=forms.DateTimeField(label='Round deadline (UTC)',input_formats=['%Y-%m-%dT%H:%M','%Y-%m-%d %H:%M'],
        widget=forms.DateTimeInput(format='%Y-%m-%dT%H:%M',attrs={'type':'datetime-local','step':'60'}))
    packet=forms.JSONField(label='Reviewer packet JSON',widget=EmptyJSONWidget(attrs={'rows':12,'class':'json-input',
        'placeholder':'[{"id":"item-1","evidence":["A source states X."],"candidate":"The source states X."}]'}),
        help_text='Only id, evidence and candidate in each item. Answer-like keys (expected, answer, label, key) are rejected; inspect prose for leakage too.')
    withheld=forms.JSONField(required=False,label='Withheld results JSON',widget=EmptyJSONWidget(attrs={'rows':12,'class':'json-input',
        'placeholder':'{"item-1":"ESTABLISHED","notice":"Author-expected labels; not adjudicated."}'}),
        help_text='Separate private table. Released only after closure; calibration entries stay steward-only.')
    calibration=forms.JSONField(required=False,label='Private calibration items (optional)',
        widget=EmptyJSONWidget(attrs={'rows':4,'class':'json-input','placeholder':'{"item-1":"ESTABLISHED"}'}),
        help_text='Map calibration item IDs to expected judgments. Markers are never sent with reviewer packets. Reports go only to the steward.')
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.fields['deadline'].widget.attrs['min']=(timezone.now()+timezone.timedelta(minutes=1)).strftime('%Y-%m-%dT%H:%M')
    def clean_packet(self):
        value=self.cleaned_data['packet'];check_packet(value);return value
    def clean_withheld(self):
        value=self.cleaned_data['withheld']
        if not isinstance(value,dict): raise forms.ValidationError('Use a JSON object for withheld results.')
        return value
    def clean_deadline(self):
        value=self.cleaned_data['deadline']
        if value<=timezone.now():raise forms.ValidationError('Use a future UTC deadline.')
        return value
    def clean_steward(self):
        try:return get_user_model().objects.get(username=self.cleaned_data['steward'])
        except get_user_model().DoesNotExist:raise forms.ValidationError('Unknown account. Create local accounts before assignment.')
    def clean(self):
        data=super().clean()
        data['calibration']=data.get('calibration') or {}
        if 'packet' in data:
            check_calibration(data['packet'],data['calibration'])
        return data

class ReviewerForm(forms.Form):
    username=forms.CharField(max_length=150,label='Reviewer username')
ReviewerFormSet=forms.formset_factory(ReviewerForm,extra=0,min_num=2,max_num=20,validate_max=True,validate_min=True,can_delete=True)

def reviewer_accounts(formset):
    names=[row.cleaned_data['username'] for row in formset if row.cleaned_data and not row.cleaned_data.get('DELETE')]
    if len(names)<2 or len(names)!=len(set(names)): raise forms.ValidationError('Use at least two different reviewer accounts.')
    users=list(get_user_model().objects.filter(username__in=names))
    if len(users)!=len(names): raise forms.ValidationError('One or more reviewer accounts do not exist.')
    return users

class DeclarationForm(forms.Form):
    CHOICES=[('','Select a response'),('yes','Yes'),('no','No')]
    relationship=forms.ChoiceField(choices=CHOICES,label='Do you have a personal or professional relationship with the author?')
    stake=forms.ChoiceField(choices=CHOICES,label='Do you have a financial, professional or other stake in the result?')
    prior_exposure=forms.ChoiceField(choices=CHOICES,label='Have you seen expected answers, results, or other assessments for this study?')
    ai_assessment=forms.ChoiceField(choices=CHOICES,label='Have you used, or do you plan to use, AI to make the evaluative judgments in this assignment?')
    note=forms.CharField(required=False,max_length=4000,widget=forms.Textarea,label='Context or uncertainty for the steward')
    credit_consent=forms.BooleanField(required=False,label='I consent to being credited by my account username in a future publication (optional).',
        help_text='This does not authorize publishing your assessment or this private export.')
    def __init__(self,*args,legacy=False,**kwargs):
        super().__init__(*args,**kwargs)
        if legacy:
            self.fields.pop('relationship');self.fields.pop('stake');self.fields.pop('credit_consent')
            self.fields['conflict']=forms.ChoiceField(choices=self.CHOICES,label='Do you have a relationship or interest that could conflict with this review?')

class ReasonForm(forms.Form):
    text=forms.CharField(max_length=4000,widget=forms.Textarea,label='Reason / details')
class AnchorForm(forms.Form):
    url=forms.URLField(max_length=2000,label='External publication URL',assume_scheme='https')
    published=forms.BooleanField(label='I published this exact commitment externally before opening the round.')
