# collector/serializers.py
from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import OplogEntry, Target, Credential, Payload, EnumerationData, Mitigation
from .utils import strip_non_printable
from .utils import strip_illegal_json_control_chars
from .utils import sanitize_string

User = get_user_model()

class SanitizedCharField(serializers.CharField):
    """
    A custom CharField that automatically sanitizes its output
    to remove illegal JSON control characters.
    """
    def to_representation(self, value):
        value = super().to_representation(value)
        if value:
            return strip_illegal_json_control_chars(value)
        return value

class BaseSanitizingSerializer(serializers.ModelSerializer):
    def to_internal_value(self, data):
        cleaned_data = {}
        for key, value in data.items():
            cleaned_data[key] = sanitize_string(value)
            #if isinstance(value, str):
            #    cleaned_data[key] = strip_non_printable(value)
            #else:
            #    cleaned_data[key] = value
        return super().to_internal_value(cleaned_data)

    def to_representation(self, instance):
        """Sanitize all outgoing string values."""
        representation = super().to_representation(instance)
        
        for key, value in representation.items():
            # Use the combined sanitizer here as well
            representation[key] = sanitize_string(value)
            
        return representation

    #def to_representation(self, instance):
    #    """
    #    Sanitize string fields in the outgoing representation.
    #    """
    #    # Get the default representation (a dictionary of field values)
    #    representation = super().to_representation(instance)
    #    
    #    # Loop through the fields and sanitize any string values
    #    for key, value in representation.items():
    #        if isinstance(value, str):
    #            representation[key] = strip_illegal_json_control_chars(value)
    #            
    #    return representation

class OplogEntrySerializer(BaseSanitizingSerializer):
    # Make operator field read-only in the API representation,
    # but show username for context instead of just ID.
    operator = serializers.StringRelatedField(read_only=True)
    # Optionally show Target __str__ representation instead of just ID
    target = serializers.StringRelatedField(read_only=True, required=False)
    # Allow writing target ID
    target_id = serializers.PrimaryKeyRelatedField(
        queryset=Target.objects.all(), source='target', write_only=True, required=False, allow_null=True
    )

    src_ip = serializers.CharField(allow_blank=True, required=False)
    src_host = serializers.CharField(allow_blank=True, required=False)
    command = serializers.CharField(allow_blank=True, required=False)
    output = serializers.CharField(allow_blank=True, required=False)
    tool = serializers.CharField(allow_blank=True, required=False)
    notes = serializers.CharField(allow_blank=True, required=False)

    class Meta:
        model = OplogEntry
        # Fields to include in the API response
        fields = [
            'id',
            'operator', # Read-only representation from StringRelatedField
            'target',   # Read-only representation from StringRelatedField
            'target_id',# Write-only field for setting target
            'timestamp',
            'src_ip',
            'src_host',
            'src_port',
            'command',
            'output',
            'tool',
            'notes',
            'screenshot',
            'enum',
            #'exfil_files', # Read-only list of related PKs or nested serializer
            #'mitigations__name',
        ]
        # Make timestamp read-only as it's auto-set
        read_only_fields = ['timestamp'] # Operator is read_only via field definition

class TargetSerializer(BaseSanitizingSerializer):
    hostname = serializers.CharField(allow_blank=True, required=False)
    ip_address = serializers.CharField(allow_blank=False, required=True)
    operating_system = serializers.CharField(allow_blank=True, required=False)
    description = serializers.CharField(allow_blank=True, required=False)

    class Meta:
        model = Target
        fields = ['id', 'hostname', 'ip_address', 'operating_system', 'description', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at']

class CredentialSerializer(BaseSanitizingSerializer):
    operator = serializers.StringRelatedField(read_only=True)
    target = serializers.StringRelatedField(read_only=True, required=False)
    target_id = serializers.PrimaryKeyRelatedField(
        queryset=Target.objects.all(), source='target', write_only=True, required=False, allow_null=True
    )
    # Make password write-only for security via API
    password_plaintext = serializers.CharField(write_only=False, required=False, allow_blank=True, style={'input_type': 'password'})

    service = serializers.CharField(allow_blank=True, required=False)
    username = serializers.CharField(allow_blank=True, required=False)
    hash_value = serializers.CharField(allow_blank=True, required=False)
    hash_type = serializers.CharField(allow_blank=True, required=False)
    notes = serializers.CharField(allow_blank=True, required=False)

    class Meta:
        model = Credential
        fields = [
            'id', 'target', 'target_id', 'service', 'username', 'password_plaintext', # Write-only
            'hash_value', 'hash_type', 'notes', 'operator', 'created_at', 'updated_at'
            ]
        read_only_fields = ['operator', 'created_at', 'updated_at']

class PayloadSerializer(BaseSanitizingSerializer):
    operator = serializers.StringRelatedField(read_only=True)

    name = serializers.CharField()
    description = serializers.CharField(allow_blank=True, required=False)
    # File uploads handled by DRF parsers, field included directly
    # payload_type display handled automatically for read if choices defined
    class Meta:
        model = Payload
        fields = ['id', 'name', 'description', 'payload_type', 'file', 'operator', 'created_at', 'updated_at']
        read_only_fields = ['operator', 'created_at', 'updated_at']

class EnumerationDataSerializer(BaseSanitizingSerializer):
    operator = serializers.StringRelatedField(read_only=True)
    target = serializers.StringRelatedField(read_only=True, required=False)
    target_id = serializers.PrimaryKeyRelatedField(
        queryset=Target.objects.all(), source='target', write_only=True, required=False, allow_null=True
    )
    # Display related files using the nested serializer (read-only)
    #scan_files = EnumerationScanFileSerializer(many=True, read_only=True)

    scan_type = serializers.CharField(allow_blank=True, required=False)
    description = serializers.CharField(allow_blank=True, required=False)
    notes = serializers.CharField(allow_blank=True, required=False)

    class Meta:
        model = EnumerationData
        fields = [
            'id', 'target', 'target_id', 'scan_type', 'description', 'notes',
            'operator', 'created_at', 'updated_at',
            'scan_file' # Nested list of files for reading
        ]
        read_only_fields = ['operator', 'created_at', 'updated_at', 'scan_files']
