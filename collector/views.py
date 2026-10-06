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
from django.utils.timezone import now
from django.urls import reverse
from django.conf import settings
from collections import defaultdict
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render, get_object_or_404
from django.http import FileResponse, Http404, HttpResponse, HttpResponseServerError, JsonResponse
from django.views import generic # Using generic class-based views for simplicity
from django.views.decorators.http import require_POST # For the export view
import json # To parse priorities from POST
from django.db.models.fields import files as file_fields
from django.db.models.fields.files import FieldFile
from rest_framework import generics, permissions
import docx
from docx.shared import Inches, Pt
from docx.enum.text import WD_ALIGN_PARAGRAPH
from .serializers import OplogEntrySerializer, TargetSerializer, CredentialSerializer, PayloadSerializer, EnumerationDataSerializer
from .models import Target, OplogEntry, OplogScreenshot, Credential, EnumerationData, Payload, ExfilFile, Mitigation, Note
from .graph import build_attack_graph_data

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
        """Automatically set the operator to the request user on create and save screenshots."""
        instance = serializer.save(operator=self.request.user)
        uploaded_screenshots = self.request.FILES.getlist('screenshots')

        if not uploaded_screenshots and 'screenshot' in self.request.FILES:
            uploaded_screenshots = self.request.FILES.getlist('screenshot')

        for img in uploaded_screenshots:
            OplogScreenshot.objects.create(oplog_entry=instance, image=img)

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
    Creates a ZIP archive containing CSV and TXT exports of all primary models,
    retaining ForeignKey resolution and custom OplogEntry mitigation/finding handling,
    along with all uploaded media files.
    """
    temp_zip_file = None
    temp_zip_path = None

    try:
        # Create a temporary file on disk to prevent RAM exhaustion
        temp_zip_file = tempfile.NamedTemporaryFile(suffix='.zip', delete=False)
        temp_zip_path = temp_zip_file.name
        temp_zip_file.close()

        with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:

            models_to_export = {
                'targets': Target,
                'oplog_entries': OplogEntry,
                'oplog_screenshots': OplogScreenshot,
                'credentials': Credential,
                'payloads': Payload,
                'enumeration_data': EnumerationData,
                'exfil_files': ExfilFile,
                'administrative_notes': Note,
            }

            for filename_base, model_class in models_to_export.items():
                queryset = model_class.objects.all()

                # Eager-load relations
                if model_class == OplogEntry:
                    queryset = queryset.select_related('target', 'operator').prefetch_related('mitigations', 'screenshots')
                elif model_class == OplogScreenshot:
                    queryset = queryset.select_related('oplog_entry')
                else:
                    if hasattr(model_class, 'target'):
                        queryset = queryset.select_related('target')
                    if hasattr(model_class, 'operator'):
                        queryset = queryset.select_related('operator')
                    if hasattr(model_class, 'oplog_entry'):
                        queryset = queryset.select_related('oplog_entry__target', 'oplog_entry__operator')

                # Define headers
                if model_class == OplogEntry:
                    field_names = [
                        'id', 'timestamp', 'operator', 'target', 'dst_port', 'src_ip', 'src_host',
                        'src_port', 'url', 'tool', 'command', 'output', 'notes', 'sys_mod',
                        'screenshot', 'enum', 'all_screenshots', 'Mitigation Names', 'Associated Findings'
                    ]
                    concrete_fields = [f for f in model_class._meta.get_fields() if f.concrete and f.name != 'mitigations']
                elif model_class == OplogScreenshot:
                    field_names = ['id', 'oplog_entry_id', 'image', 'source_type', 'created_at']
                    concrete_fields = [f for f in model_class._meta.get_fields() if f.concrete]
                else:
                    concrete_fields = [f for f in model_class._meta.get_fields() if f.concrete]
                    field_names = [f.name for f in concrete_fields]

                # Initialize in-memory string buffers for both formats
                csv_buffer = io.StringIO()
                txt_buffer = io.StringIO()

                csv_writer = csv.writer(csv_buffer)
                txt_writer = csv.writer(txt_buffer, delimiter='\t')

                csv_writer.writerow(field_names)
                txt_writer.writerow(field_names)

                # Process records
                for obj in queryset:
                    row = []
                    for field_obj in concrete_fields:
                        field_name = field_obj.name
                        val = getattr(obj, field_name, None)
                        val_str = ''

                        try:
                            if isinstance(val, datetime.datetime):
                                val_str = val.isoformat()
                            elif field_obj.is_relation and not field_obj.one_to_many and not field_obj.many_to_many:
                                val_str = str(val.pk) if (model_class == OplogScreenshot and val) else (str(val) if val is not None else '')
                            elif isinstance(val, FieldFile):
                                val_str = val.name if (val and val.name) else ''
                            elif val is None:
                                val_str = ''
                            else:
                                val_str = str(val)
                        except Exception:
                            val_str = '[ERROR]'

                        row.append(val_str)

                    # Mark multi-screenshot entries explicitly
                    if model_class == OplogScreenshot:
                        # Insert source_type into the 4th column position
                        row.insert(3, 'multi_screenshot')

                    # Custom Many-to-Many and multi-image handling for OplogEntry
                    if model_class == OplogEntry:
                        all_screens = []
                        if obj.screenshot and obj.screenshot.name:
                            all_screens.append(obj.screenshot.name)
                        for s in obj.screenshots.all():
                            if s.image and s.image.name and s.image.name not in all_screens:
                                all_screens.append(s.image.name)
                        row.append(", ".join(all_screens))

                        related_mitigations = list(obj.mitigations.all())
                        mitigation_names_str = ", ".join(sorted([m.name for m in related_mitigations]))
                        findings_list = [m.finding for m in related_mitigations if getattr(m, 'finding', None)]
                        unique_findings_str = ", ".join(sorted(list(set(findings_list))))
                        row.append(mitigation_names_str)
                        row.append(unique_findings_str)

                    csv_writer.writerow(row)
                    txt_writer.writerow(row)

                # --- SYNTHESIZE LEGACY / SINGLE SCREENSHOTS INTO oplog_screenshots EXPORT ---
                if model_class == OplogScreenshot:
                    # Collect any OplogEntry that has a screenshot in its single 'screenshot' field
                    entries_with_single = OplogEntry.objects.exclude(screenshot='').exclude(screenshot__isnull=True)
                    for entry_obj in entries_with_single:
                        img_name = entry_obj.screenshot.name
                        # Check if this image was already exported from OplogScreenshot to prevent double-counting
                        already_exported = any(s.image and s.image.name == img_name for s in entry_obj.screenshots.all())
                        if not already_exported:
                            legacy_row = [
                                f"legacy_{entry_obj.pk}",
                                str(entry_obj.pk),
                                img_name,
                                "single_field",
                                entry_obj.timestamp.isoformat() if entry_obj.timestamp else ""
                            ]
                            csv_writer.writerow(legacy_row)
                            txt_writer.writerow(legacy_row)

                # Write both CSV and TXT files to the ZIP
                zipf.writestr(f"tables/{filename_base}.csv", csv_buffer.getvalue())
                zipf.writestr(f"tables/{filename_base}.txt", txt_buffer.getvalue())

            media_root = str(settings.MEDIA_ROOT)
            if os.path.exists(media_root):
                for root, _, files in os.walk(media_root):
                    for file_name in files:
                        file_path = os.path.join(root, file_name)
                        rel_path = os.path.relpath(file_path, media_root)
                        zipf.write(file_path, arcname=os.path.join('media', rel_path))

        final_file_handle = open(temp_zip_path, 'rb')
        timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        response = FileResponse(
            final_file_handle,
            as_attachment=True,
            filename=f"{timestamp_str}_edc_export.zip"
        )
        return response

    except Exception:
        if temp_zip_path and os.path.exists(temp_zip_path):
            try:
                os.remove(temp_zip_path)
            except OSError:
                pass
        raise

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
        with tempfile.NamedTemporaryFile(delete=False) as temp_db:
            temp_db_path = temp_db.name
            print(f"Copying live DB '{db_path}' to temporary file '{temp_db_path}'")
            shutil.copy2(db_path, temp_db_path)
            print("Copy complete.")

        final_temp_file = open(temp_db_path, 'rb')

        response = FileResponse(final_temp_file, as_attachment=True, filename=f'{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}_db_backup.sqlite3')
        print(f"Serving temporary DB file: {temp_db_path}")

        return response

    except Exception as e:
        print(f"Error during database copy/serve: {e}")
        if 'temp_db_path' in locals() and os.path.exists(temp_db_path):
             try:
                 os.remove(temp_db_path)
                 print(f"Cleaned up temporary file: {temp_db_path}")
             except OSError as ose:
                 print(f"Error cleaning up temp file {temp_db_path}: {ose}")
        return HttpResponseServerError("An error occurred during database export.")

# Classification choices
CLASSIFICATION_CHOICES = ['Unclassified', 'CUI', 'Secret', 'Secret // NOFORN']
DEFAULT_CLASSIFICATION = CLASSIFICATION_CHOICES[0] # Default to Unclassified

# Criticality prioritization choices
PRIORITY_CHOICES = ['Critical', 'High', 'Medium', 'Low', 'Informational']
# Define the sort order
PRIORITY_ORDER_MAP = {name: index for index, name in enumerate(PRIORITY_CHOICES)}
DEFAULT_PRIORITY = 'Informational' # Or choose another default

@staff_member_required # Use staff_member_required since it's linked from admin
def finding_report_view(request):
    """
    Gathers data from Oplog Entries and generates a structured report HTML page.
    """

    selected_classification = request.GET.get('classification', DEFAULT_CLASSIFICATION)
    if selected_classification not in CLASSIFICATION_CHOICES:
        print(f"Warning: Invalid classification '{selected_classification}' received. Resetting to default.")
        selected_classification = DEFAULT_CLASSIFICATION

    print(f"DEBUG: Final selected_classification: '{selected_classification}'")

    # Data aggregation logic
    oplog_entries = OplogEntry.objects.prefetch_related(
        'mitigations', 'target', 'screenshots'
    ).order_by('timestamp').all()

    findings_data = defaultdict(lambda: {'targets': set(), 'mitigations': set(), 'oplog_details': []})

    for entry in oplog_entries:
        target_repr = "Unknown Target"
        if entry.target:
             hostname = entry.target.hostname or "NoHostname"
             ip = entry.target.ip_address or "NoIP"
             target_repr = f"{hostname}({ip})"

        entry_mitigations = entry.mitigations.all()
        if not entry_mitigations: continue

        # Collect ALL screenshots: single field PLUS any in the multi-screenshot table
        screen_items = []
        if entry.screenshot:
            try:
                screen_items.append({
                    'url': entry.screenshot.url,
                    'path': entry.screenshot.path if hasattr(entry.screenshot, 'path') else None,
                })
            except Exception:
                pass

        for scr in entry.screenshots.all():
            if scr.image:
                try:
                    s_url = scr.image.url
                    s_path = scr.image.path if hasattr(scr.image, 'path') else None
                    if not any(item.get('url') == s_url for item in screen_items):
                        screen_items.append({'url': s_url, 'path': s_path})
                except Exception:
                    pass

        for mitigation in entry_mitigations:
            finding_str = mitigation.finding
            if not finding_str: continue
            data_for_finding = findings_data[finding_str]
            data_for_finding['targets'].add(target_repr)
            data_for_finding['mitigations'].add(mitigation)
            data_for_finding['oplog_details'].append({
                'id': entry.pk,
                'url': entry.url or "",
                'notes': entry.notes or "",
                'command': entry.command or "",
                'output': entry.output or "",
                'screenshots': screen_items,
                'screenshot_url': screen_items[0]['url'] if screen_items else None,
                'screenshot_path': screen_items[0]['path'] if screen_items else None,
                'timestamp': entry.timestamp,
                'operator': entry.operator.username if entry.operator else 'Unknown',
                'admin_change_url': reverse('admin:collector_oplogentry_change', args=[entry.pk])
            })

    # Post-process aggregated data
    processed_findings = []
    all_mitigation_objects = set()
    sorted_finding_keys = sorted(findings_data.keys())

    for finding_str in sorted_finding_keys:
        data = findings_data[finding_str]
        mitigations_list = sorted(list(data['mitigations']), key=lambda m: m.name)
        all_mitigation_objects.update(mitigations_list)
        ccis = sorted(list(set(m.reference for m in mitigations_list if m.reference and m.reference.strip().upper().startswith('CCI:'))))
        targets_list = sorted(list(data['targets']))
        oplog_details_sorted = sorted(data['oplog_details'], key=lambda d: d['timestamp'])
        processed_findings.append({
            'finding_title': finding_str,
            'targets': targets_list,
            'mitigations': mitigations_list,
            'ccis': ccis,
            'oplog_details': oplog_details_sorted
        })

    summary_pairs = set()
    for finding_data in processed_findings:
        for mitigation in finding_data['mitigations']:
            summary_pairs.add((finding_data['finding_title'], mitigation.name))
    summary_table_data = sorted(list(summary_pairs), key=lambda x: (x[0], x[1]))

    print(f"Processed {len(processed_findings)} unique findings for view. Classification: {selected_classification}")

    context = {
        'report_findings': processed_findings,
        'summary_table_data': summary_table_data,
        'report_date': now().date(),
        'report_title': 'Findings Report',
        'classification_choices': CLASSIFICATION_CHOICES,
        'selected_classification': selected_classification,
        'priority_choices': PRIORITY_CHOICES,
        'default_priority': DEFAULT_PRIORITY,
    }
    print("--- finding_report_view END ---")

    return render(request, 'collector/report_template.html', context)

@staff_member_required
@require_POST # Ensure this view only handles POST requests
def finding_report_export_docx(request):
    """
    Generates and returns the DOCX report based on POSTed priorities.
    """
    try:
        # --- Get classification and priorities from POST data ---
        selected_classification = request.POST.get('classification', DEFAULT_CLASSIFICATION)
        if selected_classification not in CLASSIFICATION_CHOICES:
            selected_classification = DEFAULT_CLASSIFICATION

        priorities_json = request.POST.get('priorities', '{}')
        try:
            finding_priorities_map = json.loads(priorities_json)
        except json.JSONDecodeError:
            print("Warning: Could not decode priorities JSON. Using default priority.")
            finding_priorities_map = {}

        print(f"Generating DOCX export. Classification: {selected_classification}")

        # --- Re-aggregate data ---
        oplog_entries = OplogEntry.objects.prefetch_related(
            'mitigations', 'target', 'screenshots'
        ).order_by('timestamp').all()
        findings_data = defaultdict(lambda: {'targets': set(), 'mitigations': set(), 'oplog_details': []})

        for entry in oplog_entries:
            target_repr = "Unknown Target"
            if entry.target:
                hostname = entry.target.hostname or "NoHostname"
                ip = entry.target.ip_address or "NoIP"
                target_repr = f"{hostname}({ip})"

            entry_mitigations = entry.mitigations.all()
            if not entry_mitigations:
                continue

            # Gather ALL valid screenshot paths on disk: single field + multi-screenshot table
            screen_paths = []
            if entry.screenshot and hasattr(entry.screenshot, 'path') and os.path.exists(entry.screenshot.path):
                screen_paths.append(entry.screenshot.path)

            for scr in entry.screenshots.all():
                if scr.image and hasattr(scr.image, 'path') and os.path.exists(scr.image.path):
                    if scr.image.path not in screen_paths:
                        screen_paths.append(scr.image.path)

            for mitigation in entry_mitigations:
                finding_str = mitigation.finding
                if not finding_str:
                    continue
                data_for_finding = findings_data[finding_str]
                data_for_finding['targets'].add(target_repr)
                data_for_finding['mitigations'].add(mitigation)
                data_for_finding['oplog_details'].append({
                    'id': entry.pk,
                    'url': entry.url or "",
                    'notes': entry.notes or "",
                    'command': entry.command or "",
                    'output': entry.output or "",
                    'screenshot_paths': screen_paths,
                    'screenshot_url': entry.screenshot.url if entry.screenshot else None,
                    'screenshot_path': screen_paths[0] if screen_paths else None,
                    'timestamp': entry.timestamp,
                    'operator': entry.operator.username if entry.operator else 'Unknown',
                    'admin_change_url': reverse('admin:collector_oplogentry_change', args=[entry.pk])
                })

        # --- Prepare data structure for sorting ---
        sortable_findings = []
        for finding_str, data in findings_data.items():
            priority_name = finding_priorities_map.get(finding_str, DEFAULT_PRIORITY)
            priority_sort_key = PRIORITY_ORDER_MAP.get(priority_name, len(PRIORITY_ORDER_MAP))

            mitigations_list = sorted(list(data['mitigations']), key=lambda m: m.name)
            ccis = sorted(list(set(m.reference for m in mitigations_list if m.reference and m.reference.strip().upper().startswith('CCI:'))))
            targets_list = sorted(list(data['targets']))
            oplog_details_sorted = sorted(data['oplog_details'], key=lambda d: d['timestamp'])

            sortable_findings.append({
                'priority_sort_key': priority_sort_key,
                'priority_name': priority_name,
                'finding_title': finding_str,
                'targets': targets_list,
                'mitigations': mitigations_list,
                'ccis': ccis,
                'oplog_details': oplog_details_sorted
            })

        # --- Sort findings by priority, then alphabetically ---
        sorted_report_findings = sorted(sortable_findings, key=lambda x: (x['priority_sort_key'], x['finding_title']))
        print(f"Sorted {len(sorted_report_findings)} findings for DOCX export.")

        summary_table_data_sorted = []
        for finding_data in sorted_report_findings:
            for mitigation in finding_data['mitigations']:
                summary_table_data_sorted.append((finding_data['finding_title'], mitigation.name))

        # --- Generate DOCX Document ---
        document = docx.Document()
        section = document.sections[0]; footer = section.footer; header = section.header
        header_paragraph = header.paragraphs[0] if header.paragraphs else header.add_paragraph()
        header_paragraph.text = selected_classification; header_paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        footer_paragraph = footer.paragraphs[0] if footer.paragraphs else footer.add_paragraph()
        footer_paragraph.text = selected_classification; footer_paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER

        # Add main content
        document.add_heading('Findings Report', level=1)
        document.add_paragraph(f"Report Generated: {now().date()}")
        document.add_paragraph()

        # Loop through the *SORTED* findings
        for i, finding_data in enumerate(sorted_report_findings, 1):
            document.add_heading(f"Finding {i}: {finding_data['finding_title']}", level=2)

            table = document.add_table(rows=0, cols=2, style='Table Grid')
            table.autofit = False; table.allow_autofit = False
            table.columns[0].width = Inches(2.0); table.columns[1].width = Inches(5.0)
            def add_row(label, value):
                row_cells = table.add_row().cells
                row_cells[0].text = label
                row_cells[1].text = str(value) if value is not None else ''

            add_row("Mitigation Priority", f"{finding_data['finding_title']}\n[Priority Set: {finding_data['priority_name']}]")
            add_row("Description", "[User to provide detailed description...]")
            add_row("Affected Resources", ", ".join(finding_data['targets']) if finding_data['targets'] else 'N/A')
            add_row("Operational Impact", "[User to describe operational impact...]")
            add_row("Threat Posture", "[User to describe threat posture...]")

            mitigation_cells = table.add_row().cells
            mitigation_cells[0].text = "Mitigation(s)"; mitigation_cells[1].text = ""
            if finding_data['mitigations']:
                for mitigation in finding_data['mitigations']:
                    p_name = mitigation_cells[1].add_paragraph()
                    p_name.add_run(mitigation.name).bold = True
                    p_desc = mitigation_cells[1].add_paragraph(mitigation.description)
                    p_desc.paragraph_format.space_after = Pt(6)
            else:
                mitigation_cells[1].add_paragraph("N/A")

            add_row("Control Correlation Identifier (CCI)", ", ".join(finding_data['ccis']) if finding_data['ccis'] else 'N/A')
            add_row("CVSS Score", "[User to provide CVSS Score...]")

            poc_heading_cells = table.add_row().cells
            merged_poc_heading = poc_heading_cells[0].merge(poc_heading_cells[1])
            para = merged_poc_heading.paragraphs[0]; para.text = ""
            run = para.add_run("Proof of Concept"); run.bold = True
            para.alignment = WD_ALIGN_PARAGRAPH.CENTER

            poc_detail_cells = table.add_row().cells
            merged_poc_details = poc_detail_cells[0].merge(poc_detail_cells[1])
            merged_poc_details.text = ""

            if finding_data['oplog_details']:
                for detail in finding_data['oplog_details']:
                    p = merged_poc_details.add_paragraph()
                    p.add_run(f"Entry {detail['id']} ({detail['timestamp'].strftime('%Y-%m-%d %H:%M')} by {detail['operator']}):").bold = True
                    if detail.get('url'): merged_poc_details.add_paragraph(f"URL: {detail['url']}")
                    if detail.get('notes'): merged_poc_details.add_paragraph(f"Notes:\n{detail['notes']}")
                    if detail.get('command'):
                        p = merged_poc_details.add_paragraph("Command:")
                        p_code = merged_poc_details.add_paragraph(detail['command'])
                        p_code.style = 'Normal'
                        p_code.runs[0].font.name = 'Courier New'
                        p_code.paragraph_format.left_indent = Inches(0.25)
                    if detail.get('output'):
                        p = merged_poc_details.add_paragraph("Output:")
                        p_code = merged_poc_details.add_paragraph(detail['output'])
                        p_code.style = 'Normal'
                        p_code.runs[0].font.name = 'Courier New'
                        p_code.paragraph_format.left_indent = Inches(0.25)

                    # --- Embed all screenshots directly inside the cell ---
                    paths = detail.get('screenshot_paths', [])
                    if paths:
                        for s_idx, s_path in enumerate(paths, start=1):
                            try:
                                lbl = f"Screenshot {s_idx}:" if len(paths) > 1 else "Screenshot:"
                                p_lbl = merged_poc_details.add_paragraph(lbl)
                                p_lbl.runs[0].bold = True
                                p_img = merged_poc_details.add_paragraph()
                                p_img.add_run().add_picture(s_path, width=Inches(4.8))
                            except Exception as img_e:
                                print(f"Error adding screenshot {s_path}: {img_e}")
                                merged_poc_details.add_paragraph(f"[Error adding screenshot: {os.path.basename(s_path)}]")
                    elif detail.get('screenshot_url'):
                        merged_poc_details.add_paragraph(f"Screenshot URL: {detail['screenshot_url']}")

                    if detail != finding_data['oplog_details'][-1]:
                        merged_poc_details.add_paragraph("---")
            else:
                merged_poc_details.add_paragraph("No specific Oplog entry details linked to this finding.")

        # --- Add Summary Table ---
        if summary_table_data_sorted:
            document.add_heading("Mitigation Priorities Summary", level=2)
            summary_table = document.add_table(rows=1, cols=3, style='Table Grid')
            summary_table.autofit = True
            hdr_cells = summary_table.rows[0].cells
            hdr_cells[0].text = 'Finding'; hdr_cells[1].text = 'Mitigation Priority'; hdr_cells[2].text = 'Mitigation'

            for finding_title, mitigation_name in summary_table_data_sorted:
                row_cells = summary_table.add_row().cells
                row_cells[0].text = finding_title
                priority_display = finding_priorities_map.get(finding_title, DEFAULT_PRIORITY)
                row_cells[1].text = priority_display
                row_cells[2].text = mitigation_name

        buffer = io.BytesIO()
        document.save(buffer)
        buffer.seek(0)
        response = HttpResponse(buffer.getvalue(), content_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document')
        timestamp = now().strftime('%Y%m%d_%H%M%S')
        response['Content-Disposition'] = f'attachment; filename="{timestamp}_findings_report_{selected_classification.replace(" ","_").replace("/","_")}.docx"'
        print("DOCX export prepared successfully.")
        return response

    except Exception as e:
        print(f"!!! ERROR generating DOCX report: {e}")
        return HttpResponse(f"Error generating Word report: {e}", status=500)

@staff_member_required
def findings_list_view(request):
    # lists all unique findings from mitigation tags and links to the oplog
    oplog_entries = OplogEntry.objects.prefetch_related('mitigations', 'target', 'screenshots').all()
    findings_map = defaultdict(list)

    for entry in oplog_entries:
        unique_findings = set(m.finding for m in entry.mitigations.all() if m.finding)
        for finding in unique_findings:
            findings_map[finding].append(entry)

    sorted_findings = sorted(findings_map.items())

    context = {
        'findings_list': sorted_findings,
        'report_date': now().date(),
    }

    return render(request, 'collector/findings_list.html', context)

@staff_member_required
def export_findings_csv(request):
    oplog_entries = OplogEntry.objects.prefetch_related('mitigations', 'target', 'screenshots').all()
    findings_map = defaultdict(list)

    for entry in oplog_entries:
        unique_findings = set(m.finding for m in entry.mitigations.all() if m.finding)
        for finding in unique_findings:
            findings_map[finding].append(entry)

    sorted_findings = sorted(findings_map.items())

    timestamp = now().strftime('%Y%m%d_%H%M%S')
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{timestamp}_findings_list.csv"'

    writer = csv.writer(response)
    writer.writerow(['Finding Title', 'Affected Targets', 'Oplog Entry IDs'])

    for finding, entries in sorted_findings:
        targets = set()
        entry_ids = []
        for e in entries:
            entry_ids.append(str(e.pk))
            if e.target:
                targets.add(str(e.target.ip_address or e.target.hostname))

        writer.writerow([
            finding, 
            ", ".join(sorted(list(targets))), 
            ", ".join(entry_ids)
        ])

    return response

@login_required
def attack_path_view(request):
    """Renders the interactive Attack Path visualization page."""
    return render(request, 'collector/attack_paths.html')

@login_required
def attack_path_data_api(request):
    """Returns nodes and edges for the graph visualization."""
    data = build_attack_graph_data()
    return JsonResponse(data)