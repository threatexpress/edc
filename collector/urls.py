# collector/urls.py

from django.urls import path
from . import views # Import views from the current directory

app_name = 'collector' # Namespace for URLs to avoid collisions

urlpatterns = [
    # URL pattern for the target list view
    # Example: /targets/
    #path('targets/', views.TargetListView.as_view(), name='target-list'),

    # URL pattern for the target detail view
    # Example: /targets/1/ (where 1 is the primary key (pk) of the target)
    #path('targets/<int:pk>/', views.TargetDetailView.as_view(), name='target-detail'),

    # Credential URLs
    #path('credentials/', views.CredentialListView.as_view(), name='credential-list'),
    #path('credentials/<int:pk>/', views.CredentialDetailView.as_view(), name='credential-detail'),

    # Enumeration Data URLs
    #path('enumdata/', views.EnumerationDataListView.as_view(), name='enumdata-list'),
    #path('enumdata/<int:pk>/view_file/', views.view_enum_file, name='enumdata-view-file'),
    #path('enumdata/<int:pk>/', views.EnumerationDataDetailView.as_view(), name='enumdata-detail'),

    # Oplog URLs
    #path('oplog/', views.OplogListView.as_view(), name='oplog-list'),
    #path('oplog/<int:pk>/', views.OplogDetailView.as_view(), name='oplog-detail'),

    # Payload URLs
    #path('payloads/', views.PayloadListView.as_view(), name='payload-list'),
    #path('payloads/<int:pk>/', views.PayloadDetailView.as_view(), name='payload-detail'),
    #path('payloads/<int:pk>/download/', views.view_payload_file, name='payload-download-file'), # URL for file download

    # File View URLs
    path('oplog_exfil_file/<int:pk>/', views.view_oplog_exfil_file, name='oplog-view-exfil-file'),
    path('oplog/<int:pk>/view_enum/', views.view_oplog_enum_file_inline, name='oplog-view-enum-inline'),
    path('enumdata/<int:pk>/view_scanfile/', views.view_enum_scan_file_inline, name='enumdata-view-scanfile-inline'),

    # API URLs
    path('api/oplog/', views.OplogEntryListCreateAPIView.as_view(), name='api-oplog-list-create'),
    path('api/targets/', views.TargetListCreateAPIView.as_view(), name='api-target-list-create'),
    path('api/credentials/', views.CredentialListCreateAPIView.as_view(), name='api-credential-list-create'),
    path('api/payloads/', views.PayloadListCreateAPIView.as_view(), name='api-payload-list-create'),
    path('api/enumdata/', views.EnumerationDataListCreateAPIView.as_view(), name='api-enumdata-list-create'),
]