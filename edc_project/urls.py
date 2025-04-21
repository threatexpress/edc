from django.contrib import admin
from django.urls import path, include # Make sure 'include' is imported
from django.views.generic.base import RedirectView
from django.conf import settings
from django.conf.urls.static import static
from collector import views as collector_views
from rest_framework.authtoken import views as authtoken_views

admin.site.site_header = "EDC Portal"  # Main header text
admin.site.site_title = "EDC APortal"          # Browser title bar suffix
admin.site.index_title = "EDC Portal" # Title on admin index page

urlpatterns = [
    #path('', RedirectView.as_view(pattern_name='collector:target-list', permanent=False)),
    path('', RedirectView.as_view(pattern_name='admin:index', permanent=False)),

    # Export URL
    path('admin/download-db/', collector_views.download_sqlite_db, name='download-db'),
    path('admin/export-zip/', collector_views.export_all_data_zip, name='export-all-zip'),

    path('admin/', admin.site.urls), # Django admin site

    # Include the URLs from the collector app
    # All URLs starting with 'collector/' will be handled by collector/urls.py
    path('collector/', include('collector.urls')),

    # Add other paths for other apps or project-wide views later
    path('accounts/', include('django.contrib.auth.urls')), # For login/logout views

    # DRF API
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('api/get-token/', authtoken_views.obtain_auth_token, name='api-get-token'),

]

#if settings.DEBUG:
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)