from django.contrib import admin
from .models import oplog, target, cred, eventinfo

admin.site.register(oplog)
admin.site.register(target)
admin.site.register(cred)
admin.site.register(eventinfo)
