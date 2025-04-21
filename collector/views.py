from django.http import Http404, HttpResponse # Import HttpResponse
from wsgiref.util import FileWrapper # Efficiently stream large files (optional but good)
import mimetypes # To guess content type
import os # To work with file paths
import io
import csv
import zipfile
import datetime
import shutil
import tempfile
import time
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render, get_object_or_404
from django.http import FileResponse, Http404, HttpResponseServerError
from django.views import generic # Using generic class-based views for simplicity
from django.db.models.fields import files as file_fields
from rest_framework import generics, permissions
from .serializers import OplogEntrySerializer, TargetSerializer, CredentialSerializer, PayloadSerializer, EnumerationDataSerializer
from .models import Target, OplogEntry, Credential, EnumerationData, Payload, ExfilFile

# Class-based view for listing targets

@login_required
def view_oplog_exfil_file(request, pk):
    """ Serves ExfilFile - defaults to attachment """
    exfil_file = get_object_or_404(ExfilFile, pk=pk)
    try:
        file_path = exfil_file.file.path
        if not os.path.exists(file_path): raise Http404("File not found.")

        content_type, encoding = mimetypes.guess_type(file_path)
        content_type = content_type or 'application/octet-stream' # Default to download
        file = open(file_path, 'rb')
        response = HttpResponse(FileWrapper(file), content_type=content_type)
        # Default to attachment for exfil data
        response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
        return response
    except Exception as e:
        print(f"Error serving ExfilFile {pk}: {e}")
        raise Http404("Error accessing file.")

@login_required
def view_oplog_enum_file_inline(request, pk):
    """ Serves the SINGLE enum file from an OplogEntry record, attempting inline display. """
    oplog_entry = get_object_or_404(OplogEntry, pk=pk)
    if not oplog_entry.enum:
        raise Http404("No enum file associated with this entry.")
    try:
        file_path = oplog_entry.enum.path
        if not os.path.exists(file_path): raise Http404("File not found.")

        content_type, encoding = mimetypes.guess_type(file_path)
        content_type = content_type or 'text/plain' # Default to text
        file = open(file_path, 'rb')
        response = HttpResponse(FileWrapper(file), content_type=content_type)
        response['Content-Disposition'] = f'inline; filename="{os.path.basename(file_path)}"'
        return response
    except Exception as e:
        print(f"Error serving OplogEntry {pk} enum file: {e}")
        raise Http404("Error accessing file.")

@login_required
def view_enum_scan_file_inline(request, pk):
    """ Serves the SINGLE scan_file from an EnumerationData record, attempting inline display. """
    enum_data = get_object_or_404(EnumerationData, pk=pk)
    if not enum_data.scan_file:
        raise Http404("No scan file associated with this entry.")
    try:
        file_path = enum_data.scan_file.path
        if not os.path.exists(file_path): raise Http404("File not found.")

        content_type, encoding = mimetypes.guess_type(file_path)
        content_type = content_type or 'text/plain' # Default to text
        file = open(file_path, 'rb')
        response = HttpResponse(FileWrapper(file), content_type=content_type)
        response['Content-Disposition'] = f'inline; filename="{os.path.basename(file_path)}"'
        return response
    except Exception as e:
        print(f"Error serving EnumerationData {pk} scan_file: {e}")
        raise Http404("Error accessing file.")

class OplogEntryListCreateAPIView(generics.ListCreateAPIView):
    """
    API endpoint to list Oplog entries or create a new one.
    """
    queryset = OplogEntry.objects.all().order_by('-timestamp') # Get all entries, newest first
    serializer_class = OplogEntrySerializer
    # Require users to be authenticated to access this endpoint
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        """Automatically set the operator to the request user on create."""
        serializer.save(operator=self.request.user)

class TargetListCreateAPIView(generics.ListCreateAPIView):
    queryset = Target.objects.all()
    serializer_class = TargetSerializer
    permission_classes = [permissions.IsAuthenticated]
    # No operator to set for Target model

class CredentialListCreateAPIView(generics.ListCreateAPIView):
    queryset = Credential.objects.all()
    serializer_class = CredentialSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        # Automatically set operator on create
        serializer.save(operator=self.request.user)

class PayloadListCreateAPIView(generics.ListCreateAPIView):
    queryset = Payload.objects.all()
    serializer_class = PayloadSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        # Automatically set operator on create
        serializer.save(operator=self.request.user)

class EnumerationDataListCreateAPIView(generics.ListCreateAPIView):
    queryset = EnumerationData.objects.all()
    serializer_class = EnumerationDataSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        # Automatically set operator when creating metadata record
        serializer.save(operator=self.request.user)

    # Note: This view doesn't handle uploading the associated
    # EnumerationScanFile records via API. That requires separate endpoints
    # or more complex nested writable serializers. Users can create the
    # metadata record here and add files later via admin or future API endpoints.

@staff_member_required
def export_all_data_zip(request):
    """
    Creates a Zip archive containing CSV exports of main models and all uploaded media files.
    Outputs string representation for ForeignKeys instead of PKs in CSVs.
    """
    print("\n***** RUNNING LATEST EXPORT CODE v10 (FK String Repr) *****\n")

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:

        # --- 1. Export Models as CSV ---
        models_to_export = {
            'targets': Target,
            'oplog_entries': OplogEntry,
            'credentials': Credential,
            'payloads': Payload,
            'enumeration_data': EnumerationData,
            'exfil_files': ExfilFile,
        }
        print("Starting CSV Export...")

        for filename_base, model_class in models_to_export.items():
            print(f"  Exporting {model_class.__name__}")
            # Eager load common foreign keys to potentially improve performance
            queryset = model_class.objects.all()
            if hasattr(model_class, 'target'):
                 queryset = queryset.select_related('target')
            if hasattr(model_class, 'operator'):
                 queryset = queryset.select_related('operator')
            if hasattr(model_class, 'oplog_entry'):
                 queryset = queryset.select_related('oplog_entry__target', 'oplog_entry__operator') # Example nested
            if hasattr(model_class, 'enum_data_entry'):
                 queryset = queryset.select_related('enum_data_entry__target', 'enum_data_entry__operator') # Example nested


            if not queryset.exists():
                print(f"    Skipping {model_class.__name__} - No records found.")
                continue

            field_names = [f.name for f in model_class._meta.get_fields() if f.concrete]
            csv_buffer = io.StringIO()
            writer = csv.writer(csv_buffer)
            writer.writerow(field_names)

            for obj in queryset:
                row = []
                for field_name in field_names:
                    value = getattr(obj, field_name)
                    value_to_append = '' # Default

                    try:
                        field_obj = model_class._meta.get_field(field_name)

                        if isinstance(value, datetime.datetime):
                            value_to_append = value.isoformat()
                        # ==> Change how ForeignKeys are handled <==
                        elif field_obj.is_relation and not field_obj.one_to_many and not field_obj.many_to_many:
                            # Output the string representation (__str__) instead of pk
                            value_to_append = str(value) if value is not None else ''
                        # =======================================
                        elif isinstance(value, file_fields.FieldFile):
                            value_to_append = value.name if (value and value.name) else ''
                        elif value is None:
                             value_to_append = ''
                        else:
                            value_to_append = str(value)

                    except Exception as e:
                        print(f"Error processing field '{field_name}' for {model_class.__name__} PK {obj.pk}: {e}")
                        value_to_append = '[ERROR]'

                    row.append(value_to_append)

                try:
                    writer.writerow(row)
                except Exception as e: print(f"CSV Write Error for {model_class.__name__} PK {obj.pk}: {e}")

            zipf.writestr(f'{filename_base}.csv', csv_buffer.getvalue())
            csv_buffer.close()
            print(f"    Finished {filename_base}.csv")

        print("Finished CSV Export. Starting File Export...")
        # --- 2. Export Uploaded Files ---
        # (This section remains the same)
        zip_base_folder = 'uploaded_files'
        file_fields_to_export = [
             (OplogEntry, 'screenshot'), (OplogEntry, 'enum'), (ExfilFile, 'file'),
             (EnumerationData, 'scan_file'), (Payload, 'file'),
        ]
        for model_class, field_name in file_fields_to_export:
            print(f"  Processing files for {model_class.__name__}.{field_name}")
            queryset = model_class.objects.all()
            files_processed_count = 0
            for obj in queryset:
                 file_field = getattr(obj, field_name)
                 if file_field and file_field.name:
                     try:
                         full_path = file_field.path
                         relative_path = file_field.name
                         zip_path = os.path.join(zip_base_folder, relative_path)
                         if os.path.exists(full_path):
                             zipf.write(full_path, arcname=zip_path)
                             files_processed_count += 1
                         else: print(f"Warning: File missing on disk: {full_path}")
                     except ValueError as e: print(f"Warning: ValueError accessing file path for {model_class.__name__} PK {obj.pk}, field={field_name}: {e}")
                     except Exception as e: print(f"Warning: Error adding file {getattr(file_field, 'name', 'N/A')}: {e}")
            print(f"    Processed {files_processed_count} files for {model_class.__name__}.{field_name}")
        print("Finished File Export.")

    # --- 3. Prepare and Return HTTP Response ---
    zip_buffer.seek(0)
    response = HttpResponse(zip_buffer, content_type='application/zip')
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    response['Content-Disposition'] = f'attachment; filename="{timestamp}_edc_export_.zip"'
    print("Sending Zip file response...")
    return response

@staff_member_required # Ensure only staff can access
def download_sqlite_db(request):
    """ Allows staff users to download a copy of the SQLite database file. """

    db_config = settings.DATABASES.get('default', {})
    db_engine = db_config.get('ENGINE', '')

    # Ensure we are actually using SQLite
    if 'sqlite3' not in db_engine:
        return HttpResponseServerError("Database download is only configured for SQLite3.")

    db_path = db_config.get('NAME', None)

    if not db_path or not os.path.exists(db_path):
        raise Http404("Database file not found at configured path.")

    try:
        # Create a temporary file to copy the database to.
        # delete=False is important on some OSes to allow reopening by FileResponse.
        # The file will be deleted manually in the finally block.
        # Using NamedTemporaryFile ensures a unique name.
        with tempfile.NamedTemporaryFile(delete=False) as temp_db:
            temp_db_path = temp_db.name
            print(f"Copying live DB '{db_path}' to temporary file '{temp_db_path}'")
            # Copy the live database file to the temporary file
            shutil.copy2(db_path, temp_db_path) # copy2 preserves metadata if possible
            print("Copy complete.")

        # Reopen the temporary file in binary read mode for FileResponse
        # FileResponse will manage closing this file object
        final_temp_file = open(temp_db_path, 'rb')

        # Prepare the response to serve the copied file
        response = FileResponse(final_temp_file, as_attachment=True, filename=f'{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}_db_backup.sqlite3')
        print(f"Serving temporary DB file: {temp_db_path}")

        # Note: We can't reliably delete temp_db_path here because FileResponse
        # might still be streaming it. Django's FileResponse is supposed to close
        # the file object, but cleanup of the path itself might need a separate process
        # for truly temporary files in long-running views. For this admin action,
        # manual cleanup or OS temp cleaning is often sufficient. Or use a context manager
        # that cleans up AFTER the response is fully sent (more complex).

        return response

    except Exception as e:
        print(f"Error during database copy/serve: {e}")
        # Clean up temporary file if it exists and an error occurred before response
        if 'temp_db_path' in locals() and os.path.exists(temp_db_path):
             try:
                 os.remove(temp_db_path)
                 print(f"Cleaned up temporary file: {temp_db_path}")
             except OSError as ose:
                 print(f"Error cleaning up temp file {temp_db_path}: {ose}")
        return HttpResponseServerError("An error occurred during database export.")
