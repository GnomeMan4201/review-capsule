from django.urls import path
from django.contrib.auth import views as auth
from capsule import views as v
urlpatterns=[path('healthz/',v.health,name='health'),path('',v.home,name='home'),path('login/',auth.LoginView.as_view(),name='login'),path('logout/',auth.LogoutView.as_view(),name='logout'),
path('studies/new/',v.create_study,name='create'),path('desk/<uuid:sid>/',v.desk,name='desk'),
path('rounds/<uuid:rid>/freeze/',v.freeze,name='freeze'),path('rounds/<uuid:rid>/close/',v.close,name='close'),
path('rounds/<uuid:rid>/private-export/',v.export_round,name='export'),path('rounds/<uuid:rid>/feedback/',v.feedback,name='feedback'),
path('assignments/<uuid:aid>/declaration/',v.declaration,name='declaration'),path('assignments/<uuid:aid>/admit/',v.admit,name='admit'),
path('assignments/<uuid:aid>/review/',v.review,name='review'),path('assignments/<uuid:aid>/packet.json',v.packet_json,name='packet'),
path('assignments/<uuid:aid>/receipt/',v.receipt,name='receipt'),path('assignments/<uuid:aid>/receipt.json',v.receipt_json,name='receipt_json'),
path('assignments/<uuid:aid>/results.json',v.result_json,name='results'),path('assignments/<uuid:aid>/exposure/',v.exposure,name='exposure'),path('assignments/<uuid:aid>/amend/',v.amend,name='amend')]
