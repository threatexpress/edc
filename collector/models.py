import os
import re
from django.db import models
from django.conf import settings # To link to the User model
from django.db.models.fields import CharField, TextField
from collector.utils import sanitize_string
from collector.utils import strip_non_printable

def get_target_identifier(target_obj):
    """ Helper function to get sanitized identifier from a Target object """
    target_identifier = 'no_target' # Default if no target
    if target_obj:
        # Prioritize hostname
        if target_obj.hostname:
            target_identifier = target_obj.hostname
        # Fallback to IP address
        elif target_obj.ip_address:
            target_identifier = str(target_obj.ip_address) # Ensure it's a string
        # Final fallback if target exists but has no hostname or IP (use PK)
        elif target_obj.pk:
             target_identifier = f'target_{target_obj.pk}'
        # Very unlikely case: target exists but has no pk yet? Use 'unsaved_target'
        else:
             target_identifier = 'unsaved_target'

        # Sanitize the identifier for use in a path
        target_identifier = re.sub(r'[.:\\/]+', '_', target_identifier)
    return target_identifier

def get_oplog_exfil_path(instance, filename):
    """ Path for ExfilFile files, based on PARENT Oplog's Target """
    target_obj = instance.oplog_entry.target if instance.oplog_entry else None
    target_folder = get_target_identifier(target_obj)
    # ====================================================
    return os.path.join('targets', target_folder, 'exfil_files', filename)

class Target(models.Model):
    """Represents a target system or asset."""
    #ip_address = models.GenericIPAddressField(blank=True, null=True, verbose_name="IP Address")
    ip_address = models.TextField(blank=False, null=False, verbose_name="IP Address")
    hostname = models.CharField(max_length=255, blank=True, null=True)
    operating_system = models.CharField(max_length=100, blank=True, null=True, verbose_name="Operating System")
    users = models.CharField(max_length=100,blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        # Return a user-friendly representation
        if self.hostname and self.ip_address:
            return f"{self.hostname} ({self.ip_address})"
        elif self.hostname:
            return self.hostname
        elif self.ip_address:
            return str(self.ip_address)
        else:
            return f"Target {self.id}"

    class Meta:
        verbose_name = "Target"
        verbose_name_plural = "Targets"
        ordering = ['-created_at'] # Show newest first by default

    def save(self, *args, **kwargs):
        # Sanitize text fields before saving
        for field in self._meta.fields:
            if isinstance(field, (CharField, TextField)):
                value = getattr(self, field.name)
                if value:
                    setattr(self, field.name, sanitize_string(value))
        super().save(*args, **kwargs) # Call the original save method

    def clean(self):
        super().clean()
        for field in self._meta.fields:
            if isinstance(field, (CharField, TextField)):
                value = getattr(self, field.name)
                if value:
                    #setattr(self, field.name, strip_non_printable(value))
                    setattr(self, field.name, sanitize_string(value))

class Credential(models.Model):
    """Represents a captured credential."""
    target = models.ForeignKey(
        Target,
        on_delete=models.SET_NULL, # Keep cred if target is deleted
        blank=True,
        null=True,
        related_name='credentials'
    )
    service = models.CharField(max_length=100, blank=True, null=True, help_text="e.g., SSH, SMB, RDP, HTTP Basic, Local Admin")
    username = models.CharField(max_length=255)

    # !!! --- SECURITY WARNING --- !!!
    # Storing plaintext passwords is a VERY BAD practice in production.
    # This field is included for simplicity in this educational example ONLY.
    # In a real application, you should:
    #   1. Store only password HASHES if verifying logins (e.g., NTLM, NetNTLM).
    #   2. Use an encrypted field (e.g., with django-fernet-fields or similar)
    #      if you absolutely must store and retrieve the original secret.
    #   3. Implement strict access controls regardless.
    password_plaintext = models.TextField(blank=True, null=True, verbose_name="Password/Secret (Plaintext - WARNING!)")
    # !!! --- END SECURITY WARNING --- !!!
    # !!! --- For updates or security concerns contact James Tubberville --- !!!

    hash_value = models.TextField(blank=True, null=True, verbose_name="Hash Value")
    hash_type = models.CharField(max_length=50, blank=True, null=True, verbose_name="Hash Type", help_text="e.g., NTLM, NetNTLMv1/v2, Kerberos, bcrypt")

    notes = models.TextField(blank=True, null=True)
    operator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT, # Who added this credential?
        related_name='added_credentials'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        target_str = f" on {self.target}" if self.target else ""
        service_str = f" for {self.service}" if self.service else ""
        return f"{self.username}{service_str}{target_str}"

    class Meta:
        verbose_name = "Credential"
        verbose_name_plural = "Credentials"
        ordering = ['-created_at']

    def save(self, *args, **kwargs):
        # Sanitize text fields before saving
        for field in self._meta.fields:
            if isinstance(field, (CharField, TextField)):
                value = getattr(self, field.name)
                if value:
                    setattr(self, field.name, sanitize_string(value))
        super().save(*args, **kwargs) # Call the original save method

    def clean(self):
        super().clean()
        for field in self._meta.fields:
            if isinstance(field, (CharField, TextField)):
                value = getattr(self, field.name)
                if value:
                    #setattr(self, field.name, strip_non_printable(value))
                    setattr(self, field.name, sanitize_string(value))

def get_enum_data_path(instance, filename):
    """ Generates the upload path using Target hostname or IP, sanitized. """
    target_identifier = 'no_target' # Default if no target

    if instance.target:
        # Prioritize hostname
        if instance.target.hostname:
            target_identifier = instance.target.hostname
        # Fallback to IP address
        elif instance.target.ip_address:
            target_identifier = str(instance.target.ip_address) # Ensure it's a string
        # Final fallback if target exists but has no hostname or IP (use PK)
        elif instance.target.pk:
             target_identifier = f'target_{instance.target.pk}'
        # Very unlikely case: target exists but has no pk yet? Use 'unsaved_target'
        else:
             target_identifier = 'unsaved_target'

        # Sanitize the identifier for use in a path
        # Replace dots, colons, slashes, backslashes with underscores
        target_identifier = re.sub(r'[.:\\/]+', '_', target_identifier)
        
    # Construct the path
    return os.path.join('targets', target_identifier, 'enum_data', filename)

class Mitigation(models.Model):
    """ Represents a predefined security mitigation or recommendation. """
    name = models.CharField(max_length=100, unique=True, help_text="Short unique name/ID (e.g., M1, Disable Outdated Service SMBv1)")
    finding = models.CharField(max_length=100, blank=True, help_text="Short unique name/ID (e.g., Insecure Protocols or Services)")
    description = models.TextField(help_text="Detailed description of the mitigation.")
    category = models.CharField(max_length=50, blank=True, help_text="Optional category (e.g., Network, Host, Policy, IAM)")
    reference = models.TextField(max_length=500, blank=True, help_text="Optional URL to external documentation.")

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = "Mitigation"
        verbose_name_plural = "Mitigations"
        ordering = ['name']

    def save(self, *args, **kwargs):
        # Sanitize text fields before saving
        for field in self._meta.fields:
            if isinstance(field, (CharField, TextField)):
                value = getattr(self, field.name)
                if value:
                    setattr(self, field.name, sanitize_string(value))
        super().save(*args, **kwargs) # Call the original save method

    def clean(self):
        super().clean()
        for field in self._meta.fields:
            if isinstance(field, (CharField, TextField)):
                value = getattr(self, field.name)
                if value:
                    #setattr(self, field.name, strip_non_printable(value))
                    setattr(self, field.name, sanitize_string(value))

class OplogEntry(models.Model):
    """Represents a single operator log entry."""
    operator = models.ForeignKey(
        settings.AUTH_USER_MODEL, # Link to Django's built-in User model
        on_delete=models.PROTECT, # Don't delete logs if user is deleted (consider SET_NULL or other strategy)
        related_name='oplog_entries'
    )
    target = models.ForeignKey(
        Target,
        on_delete=models.SET_NULL, # Keep log if target is deleted, just remove link
        blank=False, # Make target selection mandatory in forms
        null=True,   # Still allow NULL in DB for now to avoid migration complexity with existing data
        related_name='oplog_entries'
    )
    timestamp = models.DateTimeField(auto_now_add=True) # Automatically set on creation
    #dst_ip = models.TextField(blank=True, null=True, verbose_name="Destination IP")
    dst_port = models.TextField(blank=True, null=True, verbose_name="Destination Port")
    #dst_host = models.TextField(blank=True, null=True, verbose_name="Destination Host")
    src_ip = models.TextField(blank=True, null=True, verbose_name="Source IP")
    src_port = models.TextField(max_length=14, blank=True, null=True, verbose_name="Source Port")
    src_host = models.TextField(blank=True, null=True, verbose_name="Source Host")
    url = models.TextField(blank=True, null=True, verbose_name="Target URL")
    tool = models.TextField(max_length=14, blank=True, null=True, verbose_name="Tool Used")
    command = models.TextField(blank=True, null=True, verbose_name="Command Executed")
    output = models.TextField(blank=True, null=True, verbose_name="Command Output/Result")
    notes = models.TextField(blank=True, null=True)
    screenshot = models.ImageField(upload_to='oplog_screenshots/', blank=True, null=True) # Example for later file uploads
    sys_mod = models.TextField(blank=True, null=True, verbose_name="System Modification")
    #exfil = models.FileField(upload_to=get_oplog_exfil_path, blank=True, null=True) # For file uploads
    enum = models.FileField(upload_to=get_enum_data_path, blank=True, null=True) # For file uploads

    mitigations = models.ManyToManyField(
        Mitigation,
        blank=True, # Tagging is optional
        related_name='oplog_entries',
        verbose_name="Associated Mitigations"
    )

    def __str__(self):
        return f"OpLog {self.id} by {self.operator.username} at {self.timestamp.strftime('%Y-%m-%d %H:%M')}"

    class Meta:
        verbose_name = "Operator Log Entry"
        verbose_name_plural = "Operator Log Entries"
        ordering = ['-timestamp'] # Show newest first by default

    def save(self, *args, **kwargs):
        # Call the original save method first to save the OplogEntry
        # and ensure self.pk and file uploads are processed
        for field in self._meta.fields:
            # We only want to sanitize CharField and TextField
            if isinstance(field, (CharField, TextField)):
                value = getattr(self, field.name)
                if value:
                    setattr(self, field.name, sanitize_string(value))
        super().save(*args, **kwargs)

        # Now, check if an enum file exists for this entry
        if self.enum and self.pk:
            # Use get_or_create to find an existing EnumerationData linked
            # to this OplogEntry, or create a new one if it doesn't exist.
            enum_data, created = EnumerationData.objects.get_or_create(
                oplog_source=self, # Match based on the link back to this OplogEntry
                defaults={ # These values are used ONLY if creating a NEW record
                    'target': self.target,
                    'scan_type': 'Oplog Upload', # Indicate the source type
                    'description': f'File from Oplog Entry #{self.pk}',
                    'scan_file': self.enum, # Assign the same file
                    'operator': self.operator,
                }
            )

            # If the EnumerationData record already existed (not created)...
            if not created:
                # ...you might want to update it if the file or target changed.
                # Check if the file reference or target is different and update if needed.
                update_needed = False
                if enum_data.scan_file != self.enum:
                    enum_data.scan_file = self.enum
                    update_needed = True
                if enum_data.target != self.target:
                    enum_data.target = self.target
                    update_needed = True
                # Update operator too? Maybe not, keep original adder? Your choice.
                # if enum_data.operator != self.operator:
                #    enum_data.operator = self.operator
                #    update_needed = True

                if update_needed:
                    enum_data.save() # Save the changes to the existing EnumerationData

    def clean(self):
        super().clean()
        for field in self._meta.fields:
            if isinstance(field, (CharField, TextField)):
                value = getattr(self, field.name)
                if value:
                    #setattr(self, field.name, strip_non_printable(value))
                    setattr(self, field.name, sanitize_string(value))

class EnumerationData(models.Model):
    """Stores data and files related to enumeration activities."""
    target = models.ForeignKey(
        Target,
        on_delete=models.SET_NULL, # Keep data if target is deleted
        blank=True,
        null=True,
        related_name='enum_data'
    )
    scan_type = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="e.g., Nmap, Nessus, Dirb, Manual Notes, Recon-ng"
    )
    description = models.CharField(max_length=255, blank=True, null=True, help_text="Brief description of the scan/data")
    notes = models.TextField(blank=True, null=True)
    scan_file = models.FileField(
        upload_to=get_enum_data_path, # Use the new path function
        blank=True, # Allow entries without a file (e.g., manual notes)
        null=True
    )
    operator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT, # Who added this data?
        related_name='added_enum_data'
    )
    oplog_source = models.OneToOneField(
        OplogEntry,
        on_delete=models.SET_NULL, # Keep enum data if source oplog is deleted, just break link
        null=True,                 # Allow EnumData created manually (not linked to oplog)
        blank=True,
        related_name='linked_enum_data',
        help_text="The Oplog entry this data was created from (if applicable)"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        target_str = f" on {self.target}" if self.target else ""
        type_str = f"{self.scan_type} " if self.scan_type else ""
        return f"{type_str}Data {self.id}{target_str}"

    class Meta:
        verbose_name = "Enumeration Data"
        verbose_name_plural = "Enumeration Data"
        ordering = ['-created_at']

    def save(self, *args, **kwargs):
        # Sanitize text fields before saving
        for field in self._meta.fields:
            if isinstance(field, (CharField, TextField)):
                value = getattr(self, field.name)
                if value:
                    setattr(self, field.name, sanitize_string(value))
        super().save(*args, **kwargs) # Call the original save method

    def clean(self):
        super().clean()
        for field in self._meta.fields:
            if isinstance(field, (CharField, TextField)):
                value = getattr(self, field.name)
                if value:
                    #setattr(self, field.name, strip_non_printable(value))
                    setattr(self, field.name, sanitize_string(value))

def get_payload_path(instance, filename):
    """ Path for Payload files """
    # Django handles duplicate filenames automatically if needed.
    return os.path.join('payloads', filename)

class Payload(models.Model):
    """ Represents an operational payload file. """

    # Define choices for payload type
    TYPE_EXECUTABLE = 'EXE'
    TYPE_SCRIPT = 'SCRIPT'
    TYPE_SHELLCODE = 'SHELLCODE'
    TYPE_CONFIG = 'CONFIG'
    TYPE_OTHER = 'OTHER'
    PAYLOAD_TYPE_CHOICES = [
        (TYPE_EXECUTABLE, 'Executable (exe, dll, etc.)'),
        (TYPE_SCRIPT, 'Script (ps1, py, js, sh, etc.)'),
        (TYPE_SHELLCODE, 'Shellcode'),
        (TYPE_CONFIG, 'Configuration (xml, json, yaml)'),
        (TYPE_OTHER, 'Other'),
    ]

    name = models.CharField(max_length=255, help_text="Filename or a descriptive name")
    description = models.TextField(blank=True, null=True, help_text="Purpose, usage, C2 info, etc.")
    payload_type = models.CharField(
        max_length=10,
        choices=PAYLOAD_TYPE_CHOICES,
        default=TYPE_OTHER,
    )
    file = models.FileField(
        upload_to=get_payload_path,
        # Make file upload optional? Or required? Let's make it required for a payload.
        # blank=False, null=False (Default)
    )
    operator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT, # Who uploaded/added this payload?
        related_name='added_payloads'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = "Payload"
        verbose_name_plural = "Payloads"
        ordering = ['-created_at']

    def save(self, *args, **kwargs):
        # Sanitize text fields before saving
        for field in self._meta.fields:
            if isinstance(field, (CharField, TextField)):
                value = getattr(self, field.name)
                if value:
                    setattr(self, field.name, sanitize_string(value))
        super().save(*args, **kwargs) # Call the original save method

    def clean(self):
        super().clean()
        for field in self._meta.fields:
            if isinstance(field, (CharField, TextField)):
                value = getattr(self, field.name)
                if value:
                    #setattr(self, field.name, strip_non_printable(value))
                    setattr(self, field.name, sanitize_string(value))

class ExfilFile(models.Model):
    """ Represents a single exfiltrated file linked to an OplogEntry """
    oplog_entry = models.ForeignKey(
        OplogEntry,
        on_delete=models.CASCADE,
        related_name='exfil_files' # Access via oplog_entry.exfil_files.all
    )
    file = models.FileField(upload_to=get_oplog_exfil_path) # Use new path function
    description = models.CharField(max_length=255, blank=True, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Exfil file for Oplog {self.oplog_entry.pk} ({os.path.basename(self.file.name)})"

    class Meta:
        verbose_name = "Exfiltrated File"
        verbose_name_plural = "Exfiltrated Files"
        ordering = ['-uploaded_at']

    def save(self, *args, **kwargs):
        # Sanitize text fields before saving
        for field in self._meta.fields:
            if isinstance(field, (CharField, TextField)):
                value = getattr(self, field.name)
                if value:
                    setattr(self, field.name, sanitize_string(value))
        super().save(*args, **kwargs) # Call the original save method

    def clean(self):
        super().clean()
        for field in self._meta.fields:
            if isinstance(field, (CharField, TextField)):
                value = getattr(self, field.name)
                if value:
                    #setattr(self, field.name, strip_non_printable(value))
                    setattr(self, field.name, sanitize_string(value))

class Note(models.Model):
    """ Represents a general note, finding, or piece of information. """
    title = models.CharField(max_length=255, help_text="short title")
    content = models.TextField(blank=True, help_text="Main content.")
    category = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="Optional category (e.g., Scope, POC, Rules, Findings, TODO)."
    )
    operator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT, # Keep note even if operator deletes
        related_name='added_notes'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

    class Meta:
        verbose_name = "Administrative Note"
        verbose_name_plural = "Administrative Notes"
        ordering = ['-updated_at', '-created_at'] # Show most recently updated first

    def save(self, *args, **kwargs):
        # Sanitize text fields before saving
        for field in self._meta.fields:
            if isinstance(field, (CharField, TextField)):
                value = getattr(self, field.name)
                if value:
                    setattr(self, field.name, sanitize_string(value))
        super().save(*args, **kwargs) # Call the original save method

    def clean(self):
        super().clean()
        for field in self._meta.fields:
            if isinstance(field, (CharField, TextField)):
                value = getattr(self, field.name)
                if value:
                    #setattr(self, field.name, strip_non_printable(value))
                    setattr(self, field.name, sanitize_string(value))