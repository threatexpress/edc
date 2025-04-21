from django.conf import settings
from django.urls import path, re_path, include
from rest_framework import routers
from rest_framework.authtoken.views import obtain_auth_token
from .views import (
	oplogListView,
	oplogDetailView,
	oplogCreateView,
	oplogUpdateView,
	oplogDeleteView,
	operatoroplogListView,
    targetListView,
    targetDetailView,
    targetCreateView,
    targetUpdateView,
    targetDeleteView,
    credListView,
    credDetailView,
    credCreateView,
    credUpdateView,
    credDeleteView,
    eventListView,
    eventUpdateView,
    eventCreateView,
    eventDetailView,
    deconListView,
    oplogViewSet,
    targetViewSet,
    credViewSet,
    eventinfoViewSet,
    authview,
    oplogexport,
    deconexport
    oplog2export
    tagListView,
    pfile,
    payloadListView,
    payloadDetailView,
    payloadCreateView,
    payloadUpdateView,
    payloadDeleteView,
)
from . import views

router = routers.DefaultRouter()
router.register(r'oplog', views.oplogViewSet)
router.register(r'target', views.targetViewSet)
router.register(r'cred', views.credViewSet)
router.register(r'eventinfo', views.eventinfoViewSet)

urlpatterns = [
    path('', eventListView.as_view(), name='edc-info'),
    path('oplogs/', oplogListView.as_view(), name='edc-oplogs'),
    path('oplog/<int:pk>/', oplogDetailView.as_view(), name='oplog-detail'),
    path('oplog/<int:pk>/update/', oplogUpdateView.as_view(), name='oplog-update'),
    path('oplog/<int:pk>/delete/', oplogDeleteView.as_view(), name='oplog-delete'),
    path('oplog/new/', oplogCreateView.as_view(), name='oplog-create'),
    path('user/<str:username>', operatoroplogListView.as_view(), name='operator-oplogs'),
    path(r'tag/<str:slug>', tagListView.as_view(), name='tagged-oplogs'),
    path('targets/', targetListView.as_view(), name='edc-targets'),
    path('target/<int:pk>/', targetDetailView.as_view(), name='target-detail'),
    path('target/<int:pk>/update/', targetUpdateView.as_view(), name='target-update'),
    path('target/<int:pk>/delete/', targetDeleteView.as_view(), name='target-delete'),
    path('target/new/', targetCreateView.as_view(), name='target-create'),
    path('creds/', credListView.as_view(), name='edc-creds'),
    path('cred/<int:pk>/', credDetailView.as_view(), name='cred-detail'),
    path('cred/<int:pk>/update/', credUpdateView.as_view(), name='cred-update'),
    path('cred/<int:pk>/delete/', credDeleteView.as_view(), name='cred-delete'),
    path('cred/new/', credCreateView.as_view(), name='cred-create'),
    path('decon/', deconListView.as_view(), name='edc-decon'),
    path('info/', eventListView.as_view(), name='edc-info'),
    path('info/<int:pk>/', eventDetailView.as_view(), name='eventinfo-detail'),
    path('info/<int:pk>/update/', eventUpdateView.as_view(), name='eventinfo-update'),
    path('info/new/', eventCreateView.as_view(), name='eventinfo-create'),
    path('payloads/', payloadListView.as_view(), name='edc-payloads'),
    path('payload/<int:pk>/', payloadDetailView.as_view(), name='payloadinfo-detail'),
    path('payload/<int:pk>/update/', payloadUpdateView.as_view(), name='payloadinfo-update'),
    path('payload/<int:pk>/delete/', payloadDeleteView.as_view(), name='payloadinfo-delete'),
    path('payload/new/', payloadCreateView.as_view(), name='payloadinfo-create'),
    path(r'export/oplogs/', views.oplogexport, name='oplogexport'),
    path(r'export/targets/', views.targetexport, name='targetexport'),
    path(r'export/creds/', views.credexport, name='credexport'),
    path(r'export/decon/', views.deconexport, name='deconexport'),
    path(r'export/oplogs2/', views.oplog2export, name='oplog2export'),
    path('', include(router.urls)),
    #path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    #path('api-auth/', obtain_auth_token, name='api_token_auth'),
    path('api-token/', authview.as_view()),
    re_path(r'^protected/(?P<filename>.*)$', pfile, {'document_root':settings.PROTECTED_ROOT}),
]
