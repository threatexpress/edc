# collector/serializers.py
from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import OplogEntry, Target, Credential, Payload, EnumerationData

User = get_user_model()

class OplogEntrySerializer(serializers.ModelSerializer):
    # Make operator field read-only in the API representation,
    # but show username for context instead of just ID.
    operator = serializers.StringRelatedField(read_only=True)
    # Optionally show Target __str__ representation instead of just ID
    target = serializers.StringRelatedField(read_only=True, required=False)
    # Allow writing target ID
    target_id = serializers.PrimaryKeyRelatedField(
        queryset=Target.objects.all(), source='target', write_only=True, required=False, allow_null=True
    )

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
            'exfil_files', # Read-only list of related PKs or nested serializer
        ]
        # Make timestamp read-only as it's auto-set
        read_only_fields = ['timestamp'] # Operator is read_only via field definition

class TargetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Target
        fields = ['id', 'hostname', 'ip_address', 'operating_system', 'description', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at']

class CredentialSerializer(serializers.ModelSerializer):
    operator = serializers.StringRelatedField(read_only=True)
    target = serializers.StringRelatedField(read_only=True, required=False)
    target_id = serializers.PrimaryKeyRelatedField(
        queryset=Target.objects.all(), source='target', write_only=True, required=False, allow_null=True
    )
    # Make password write-only for security via API
    password_plaintext = serializers.CharField(write_only=True, required=False, allow_blank=True, style={'input_type': 'password'})

    class Meta:
        model = Credential
        fields = [
            'id', 'target', 'target_id', 'service', 'username',
            'password_plaintext', # Write-only
            'hash_value', 'hash_type', 'notes', 'operator', 'created_at', 'updated_at'
            ]
        read_only_fields = ['operator', 'created_at', 'updated_at']

class PayloadSerializer(serializers.ModelSerializer):
    operator = serializers.StringRelatedField(read_only=True)
    # File uploads handled by DRF parsers, field included directly
    # payload_type display handled automatically for read if choices defined
    class Meta:
        model = Payload
        fields = ['id', 'name', 'description', 'payload_type', 'file', 'operator', 'created_at', 'updated_at']
        read_only_fields = ['operator', 'created_at', 'updated_at']

class EnumerationDataSerializer(serializers.ModelSerializer):
    operator = serializers.StringRelatedField(read_only=True)
    target = serializers.StringRelatedField(read_only=True, required=False)
    target_id = serializers.PrimaryKeyRelatedField(
        queryset=Target.objects.all(), source='target', write_only=True, required=False, allow_null=True
    )
    # Display related files using the nested serializer (read-only)
    #scan_files = EnumerationScanFileSerializer(many=True, read_only=True)

    class Meta:
        model = EnumerationData
        fields = [
            'id', 'target', 'target_id', 'scan_type', 'description', 'notes',
            'operator', 'created_at', 'updated_at',
            'scan_file' # Nested list of files for reading
        ]
        read_only_fields = ['operator', 'created_at', 'updated_at', 'scan_files']
