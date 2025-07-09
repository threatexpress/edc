from django.core.management.base import BaseCommand
from django.db.models import CharField, TextField
from collector.models import OplogEntry, Target, Credential, Mitigation, Note, Payload, ExfilFile, EnumerationData
from collector.utils import sanitize_string

class Command(BaseCommand):
    help = 'Finds and sanitizes all existing string fields in the database.'

    def handle(self, *args, **kwargs):
        # List all the models you want to clean
        models_to_clean = [OplogEntry, Target, Credential, Mitigation, Note, Payload, ExfilFile, EnumerationData]
        total_cleaned = 0

        self.stdout.write(self.style.SUCCESS("Starting sanitization process..."))

        for model_class in models_to_clean:
            model_name = model_class.__name__
            self.stdout.write(f"\n Checking model: {model_name} ")
            
            # Identify which fields are text-based
            fields_to_check = [
                f.name for f in model_class._meta.get_fields()
                if isinstance(f, (CharField, TextField))
            ]

            if not fields_to_check:
                self.stdout.write("No text fields to sanitize.")
                continue

            instances_to_update = []
            all_instances = model_class.objects.all()
            
            for instance in all_instances:
                is_dirty = False
                for field_name in fields_to_check:
                    raw_value = getattr(instance, field_name)
                    if isinstance(raw_value, str):
                        sanitized_value = sanitize_string(raw_value)
                        # If sanitization changes the value, the instance is dirty
                        if raw_value != sanitized_value:
                            setattr(instance, field_name, sanitized_value)
                            is_dirty = True
                
                if is_dirty:
                    instances_to_update.append(instance)
            
            if instances_to_update:
                # Use bulk_update for efficiency
                model_class.objects.bulk_update(instances_to_update, fields_to_check)
                self.stdout.write(self.style.WARNING(f"Cleaned and saved {len(instances_to_update)} records."))
                total_cleaned += len(instances_to_update)
            else:
                self.stdout.write("All records are already clean.")

        self.stdout.write(self.style.SUCCESS(f"\nSanitization complete. Total records updated: {total_cleaned}"))