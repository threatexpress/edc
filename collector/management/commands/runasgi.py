# collector/management/commands/runasgi.py

import os
import subprocess 
import sys      
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from django.core.management import call_command

class Command(BaseCommand):
    help = 'Runs Django ASGI application using Daphne, serving static files in DEBUG mode.'

    def add_arguments(self, parser):
        parser.add_argument('addrport', nargs='?', default='0.0.0.0:8889',
            help='Optional address:port argument, e.g., 0.0.0.0:8889')
        parser.add_argument('--nowebsocket', action='store_true',
            help='Runs HTTP/WSGI only (like runserver), without ASGI features.')
        
    def handle(self, *args, **options):
        addrport = options['addrport']
        use_asgi = not options['nowebsocket']
        
        try:
            addr, port = addrport.split(':')
        except ValueError:
            raise CommandError(f"Invalid address:port format: {addrport}. Use format '0.0.0.0:8889'.")

        # Set the ASGI application path for Daphne
        settings.ASGI_APPLICATION = 'edc_project.asgi.application'

        # 1. CRITICAL: Ensure StaticFilesHandler is in middleware for correct styling under ASGI
        if settings.DEBUG:
            handler_path = 'django.contrib.staticfiles.handlers.StaticFilesHandler'
            # Check if handler is already present to avoid duplicates
            if not any(mw == handler_path for mw in settings.MIDDLEWARE):
                settings.MIDDLEWARE = list(settings.MIDDLEWARE)
                # Prepend the StaticFilesHandler
                settings.MIDDLEWARE.insert(0, handler_path)

        if use_asgi:
            self.stdout.write(self.style.NOTICE("INFO: Forcing Django's static file serving in DEBUG mode..."))
            self.stdout.write(self.style.SUCCESS(f"Starting ASGI server (Daphne) at {addr}:{port}..."))
            
            # --- FINAL FIX: Execute Daphne as a Python Module (-m daphne) ---
            # This bypasses all operating system/shell command parsing issues.
            
            daphne_command = [
                sys.executable,     # /path/to/venv/bin/python
                '-m', 'daphne',     # Execute the daphne package
                settings.ASGI_APPLICATION, # edc_project.asgi:application
                '--bind', addr,
                '--port', port,
            ]
            
            self.stdout.write(self.style.SUCCESS(f"Executing: {' '.join(daphne_command)}"))

            try:
                # Execute Daphne, blocking until it exits. check=True raises exception on failure.
                subprocess.run(daphne_command, check=True)
            except FileNotFoundError:
                raise CommandError("Python executable or 'daphne' module not found. Ensure 'pip install daphne' was run.")
            except subprocess.CalledProcessError as e:
                self.stderr.write(self.style.ERROR(f"Daphne failed to start with return code {e.returncode}. Please check Daphne's logs for import errors."))
            except Exception as e:
                self.stderr.write(self.style.ERROR(f"Critical error during Daphne execution: {e}"))
            
        else:
            # Fallback (unchanged)
            self.stdout.write(self.style.SUCCESS(f"Starting standard WSGI server (runserver) at {addrport}..."))
            call_command('runserver', addrport, *args, **options)