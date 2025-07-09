# collector/admin.py
import os
from django.db import models
from django.utils.html import format_html
from django.urls import reverse
from django.forms import TextInput, Textarea
from django.contrib import admin
from django.contrib.auth.models import User
from rest_framework.authtoken.admin import TokenAdmin
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.models import TokenProxy
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import Target, OplogEntry, Credential, EnumerationData, Payload, ExfilFile, Mitigation, Note

class TokenInline(admin.StackedInline):
    model = TokenProxy # Use TokenProxy here
    max_num = 1 # A user should only have one token
    can_delete = False
    verbose_name_plural = 'Auth Token'

# Define a new User admin
class UserAdmin(BaseUserAdmin):
    inlines = (TokenInline,)

# Re-register UserAdmin
admin.site.unregister(User)
admin.site.register(User, UserAdmin)

class ExfilFileInline(admin.TabularInline):
    model = ExfilFile
    extra = 1
    readonly_fields = ('uploaded_at',)
    fields = ('file', 'description', 'uploaded_at')

@admin.register(Target)
class TargetAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'operating_system', 'users', 'created_at', 'updated_at')
    search_fields = ('hostname', 'ip_address', 'description', 'operating_system', 'users')
    list_filter = ('operating_system', 'created_at')

    formfield_overrides = {
        models.CharField: {'widget': TextInput(attrs={'size':'60'})},
        models.GenericIPAddressField: {'widget': TextInput(attrs={'size':'20'})},
        models.TextField: {'widget': Textarea(attrs={'rows':2})},
    }

@admin.register(Mitigation)
class MitigationAdmin(admin.ModelAdmin):
    list_display = ('name', 'finding', 'reference', 'category', 'description')
    search_fields = ('name', 'finding', 'reference', 'description', 'category')
    list_filter = ('category',)

@admin.register(OplogEntry)
class OplogEntryAdmin(admin.ModelAdmin):
    #list_display = ('__str__', 'target', 'command', 'timestamp')
    list_display = ('timestamp', 'target', 'src_ip', 'command', 'screenshot', 'view_enum_link', 'enum', 'notes', 'tool', 'operator')
    search_fields = ('operator__username', 'target__hostname', 'target__ip_address', 'src_ip', 'src_host', 'src_port', 'command', 'output', 'notes', 'tool', 'url', 'mitigation')
    list_filter = ('timestamp', 'operator', 'target')
    # Make operator field read-only after creation (usually set automatically)
    readonly_fields = ('timestamp', 'view_enum_link')

    fieldsets = (
        (None, {
            'fields': ('operator', 'target', 'timestamp', 'dst_port', 'src_ip', 'src_host', 'src_port', 'command', 'output', 'notes', 'tool', 'url')
        }),
        ('Mitigations / Tags', {
            'classes': ('collapse',), # Start collapsed
            'fields': ('mitigations',),
        }),
        ('Associated Single Files (Optional)', {
            'classes': ('collapse',),
            'fields': ('screenshot', 'enum', 'view_enum_link'), # Keep these direct fields
        }),
    )

    # Add the ExfilFile inline
    inlines = [ExfilFileInline, ]

    filter_horizontal = ('mitigations',) # Or filter_vertical = ('mitigations',)

    def view_enum_link(self, obj):
        if obj.enum:
            url = reverse('collector:oplog-view-enum-inline', args=[obj.pk])
            return format_html('<a href="{}" target="_blank">View Enum File</a>', url)
        return "N/A"
    view_enum_link.short_description = "View Enum" # Column header/label

    formfield_overrides = {
        models.CharField: {'widget': TextInput(attrs={'size':'60'})},
        models.GenericIPAddressField: {'widget': TextInput(attrs={'size':'20'})},
        models.TextField: {'widget': Textarea(attrs={'rows':2})},
    }

    def get_changeform_initial_data(self, request):
        return {'operator': request.user.pk} 

    def save_model(self, request, obj, form, change):
        if not obj.pk: # Only set operator on creation
            obj.operator = request.user
        super().save_model(request, obj, form, change)

@admin.register(Credential)
class CredentialAdmin(admin.ModelAdmin):
    list_display = ('username', 'password_plaintext', 'service', 'target', 'operator', 'created_at', 'hash_type')
    # Exclude the plaintext password from the main list view for safety!
    list_filter = ('service', 'hash_type', 'operator', 'target', 'created_at')
    search_fields = ('username', 'password_plaintext', 'service', 'target__hostname', 'target__ip_address', 'notes', 'hash_value', 'operator__username')
    raw_id_fields = ('target', 'operator') # Useful for selecting ForeignKeys with many options
    readonly_fields = ('created_at', 'updated_at')

    # Organize fields in the detail view
    fieldsets = (
        (None, {
            'fields': ('username', 'service', 'target')
        }),
        ('Secret Material (Handle with Care!)', {
            # 'classes': ('collapse',), # Optionally collapse this section
            'fields': ('password_plaintext', 'hash_value', 'hash_type'),
            'description': '<strong style="color: red;">Warning: Plaintext password field is for temporary/educational use ONLY. Implement proper encryption or hashing.</strong>'
        }),
        ('Metadata', {
            'fields': ('notes', 'operator', 'created_at', 'updated_at')
        }),
    )

    # Automatically set operator (uncomment/adapt if needed)
    def get_changeform_initial_data(self, request):
        return {'operator': request.user.pk} 

    def save_model(self, request, obj, form, change):
        if not obj.pk:
            obj.operator = request.user
        super().save_model(request, obj, form, change)
    # For updates or security concerns contact JTubb @minis.io

@admin.register(EnumerationData)
class EnumerationDataAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'target', 'view_scan_file_list_link', 'scan_type', 'operator', 'created_at')
    list_filter = ('scan_type', 'operator', 'target', 'created_at')
    search_fields = ('scan_type', 'description', 'notes', 'target__hostname', 'target__ip_address', 'operator__username', 'scan_file')
    raw_id_fields = ('target',) # Easier target selection
    readonly_fields = ('view_scan_file_link', 'created_at', 'updated_at')
    fields = ('target', 'scan_type', 'description', 'notes', 'scan_file', 'view_scan_file_link')
    # Exclude operator from the form, set it on save
    exclude = ('operator',)
    inlines = []

    def view_scan_file_link(self, obj):
        if obj.scan_file:
            url = reverse('collector:enumdata-view-scanfile-inline', args=[obj.pk])
            return format_html('<a href="{}" target="_blank">View</a>', url)
        return "N/A"
    view_scan_file_link.short_description = "View File"

    def view_scan_file_list_link(self, obj):
        """ Generates link for the list display """
        if obj.scan_file:
            url = reverse('collector:enumdata-view-scanfile-inline', args=[obj.pk])
            filename = os.path.basename(obj.scan_file.name)
            return format_html('<a href="{}" target="_blank">{}</a>', url, filename)
        return "N/A"
    view_scan_file_list_link.short_description = "View"

    # Automatically set operator on save (like OplogEntry)
    def save_model(self, request, obj, form, change):
        if not obj.pk:
            obj.operator = request.user
        super().save_model(request, obj, form, change)

@admin.register(Payload)
class PayloadAdmin(admin.ModelAdmin):
    list_display = ('name', 'payload_type', 'operator', 'created_at', 'updated_at')
    list_filter = ('payload_type', 'operator', 'created_at')
    search_fields = ('name', 'description', 'operator__username', 'file')
    readonly_fields = ('created_at', 'updated_at')
    # Exclude operator, set on save
    exclude = ('operator',)
    # Define field order/grouping if desired
    fieldsets = (
        (None, {
            'fields': ('name', 'payload_type', 'file', 'description')
        }),
        ('Metadata', {
             'fields': ('created_at', 'updated_at'),
             'classes': ('collapse',) # Optional: Collapse metadata section
        }),
    )


    def save_model(self, request, obj, form, change):
        if not obj.pk:
            obj.operator = request.user
        super().save_model(request, obj, form, change)

@admin.register(Note)
class NoteAdmin(admin.ModelAdmin):
    list_display = ('title', 'category', 'content')
    list_filter = ('category', 'operator', 'content', 'updated_at')
    search_fields = ('title', 'content', 'category', 'operator__username')
    # Define fields shown on add/change form
    fields = ('title', 'category', 'content', 'operator')
    readonly_fields = ('created_at', 'updated_at') # Keep timestamps read-only

    # Pre-populate or auto-set operator (choose one method)
    def get_changeform_initial_data(self, request):
        return {'operator': request.user.pk}

    formfield_overrides = {
         models.TextField: {'widget': Textarea(attrs={'rows':15, 'cols':80})},
         models.CharField: {'widget': TextInput(attrs={'size':'60'})},
         models.GenericIPAddressField: {'widget': TextInput(attrs={'size':'20'})},
     }

