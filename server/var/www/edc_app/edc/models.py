from django.db import models
from django.utils.timezone import now
from django.contrib.auth.models import User
from django.urls import reverse
from django.conf import settings
from taggit.managers import TaggableManager
from django.core.files.storage import FileSystemStorage


files = FileSystemStorage(location=settings.PROTECTED_ROOT, base_url='/protected')

class oplog(models.Model):
	start_time = models.DateTimeField(default=now)
	stop_time = models.DateTimeField(default=now, blank=True, null=True)
	src_host = models.CharField(max_length=100)
	src_ip = models.CharField(max_length=32)
	src_port = models.CharField(max_length=15,blank=True, null=True)
	dst_host = models.CharField(max_length=100)
	dst_ip = models.CharField(max_length=32)
	dst_port = models.CharField(max_length=15)
	piv_host = models.CharField(max_length=100,blank=True, null=True)
	piv_ip = models.CharField(max_length=32,blank=True, null=True)
	piv_port = models.CharField(max_length=15,blank=True, null=True)
	url = models.CharField(max_length=100,blank=True, null=True)
	tool = models.CharField(max_length=100)
	cmds = models.CharField(max_length=1000,blank=True, null=True)
	description = models.CharField(max_length=100, blank=True, null=True)
	result = models.CharField(max_length=100, blank=True, null=True)
	output = models.TextField(blank=True, null=True)
	scrsht = models.FileField(storage=files, blank=True, null=True)
	mods = models.CharField(max_length=200,blank=True, null=True)
	exfil = models.FileField(storage=files, blank=True, null=True)
	comments = models.TextField(blank=True, null=True)
	tags = TaggableManager(blank=True)
	operator = models.ForeignKey(User, on_delete=models.DO_NOTHING, null=True)

	def __str__(self):
		return str(self.start_time)

	def get_absolute_url(self):
		return reverse('oplog-detail', kwargs={'pk': self.pk})

class target(models.Model):
	host = models.CharField(max_length=100)
	ip = models.CharField(max_length=32)
	network = models.CharField(max_length=50,blank=True, null=True)
	users = models.CharField(max_length=100,blank=True, null=True)
	description = models.CharField(max_length=100,blank=True, null=True)
	comments = models.TextField(blank=True, null=True)

	def __str__(self):
		return self.host

class cred(models.Model):
	username = models.CharField(max_length=100)
	passwd = models.CharField(max_length=60,blank=True, null=True)
	hashw = models.CharField(max_length=1000,blank=True, null=True)
	token = models.CharField(max_length=100,blank=True, null=True)
	tknfile = models.FileField(storage=files, blank=True, null=True)
	first = models.CharField(max_length=32,blank=True, null=True)
	last = models.CharField(max_length=32,blank=True, null=True)
	role = models.CharField(max_length=32,blank=True, null=True)
	description = models.CharField(max_length=100,blank=True, null=True)

	def __str__(self):
		return self.username

class eventinfo(models.Model):
	dates = models.CharField(max_length=30,blank=True, null=True)
	poc = models.TextField(blank=True, null=True)
	auth = models.TextField(blank=True, null=True)
	unatuh = models.TextField(blank=True, null=True)
	notes = models.TextField(blank=True, null=True)

	def __str__(self):
		return self.dates

class payloadinfo(models.Model):
	inf = models.CharField(max_length=100, blank=True)
	url = models.CharField(max_length=200, blank=True)
	ip = models.CharField(max_length=60, blank=True)
	proto = models.CharField(max_length=100, blank=True)
	usage = models.CharField(max_length=300, blank=True)
	payld = models.CharField(max_length=1000, blank=True)
	payldfile = models.FileField(storage=files, blank=True)

	def __str__(self):
		return self.inf
