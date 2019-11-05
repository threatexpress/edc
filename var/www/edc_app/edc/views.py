from django.shortcuts import render, get_object_or_404
from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView
from django.views.static import serve
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required, permission_required
from django.template.defaultfilters import slugify
from .models import oplog, target, cred, eventinfo, payloadinfo
from rest_framework import viewsets
from .serializers import oplogSerializer, targetSerializer, credSerializer, eventinfoSerializer
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.authtoken.views import ObtainAuthToken
from django.http import HttpResponse
import csv

eentry = ['dates', 'poc', 'auth', 'unatuh', 'notes']
oentry = ['start_time', 'stop_time', 'src_host', 'src_ip', 'src_port', 'dst_host', 'dst_ip', 'dst_port', 'piv_host', 'piv_ip', 'piv_port', 'url', 'tool', 'cmds', 'description', 'result', 'output', 'scrsht', 'mods', 'exfil', 'comments', 'tags', 'operator']
centry = ['username', 'passwd', 'hashw', 'token', 'tknfile', 'first', 'last', 'role', 'description']
tentry = ['host', 'ip', 'network', 'users', 'description', 'comments']
pentry = ['inf', 'url', 'ip', 'proto', 'usage', 'payld', 'payldfile']

@login_required
def pfile (request, filename, document_root=None, show_indexes=False):
	return serve(request, filename, document_root, show_indexes)


def info(request):
	context = {
		'evtinfo': eventinfo.objects.all()
	}
	return render(request, 'edc/info.html', context)

class eventListView(LoginRequiredMixin, PermissionRequiredMixin, ListView):
	model = eventinfo
	template_name = 'edc/info.html'
	context_object_name='evtinfo'
	paginate_by = 50
	permission_required = ('edc.view_eventinfo')

class eventCreateView(LoginRequiredMixin, PermissionRequiredMixin, CreateView):
	model = eventinfo
	fields = eentry
	success_url = '/info'
	permission_required = ('edc.add_eventinfo')


class eventUpdateView(LoginRequiredMixin, PermissionRequiredMixin, UpdateView):
	model = eventinfo
	fields = eentry
	success_url = '/info'
	permission_required = ('edc.change_eventinfo')

class eventDetailView(LoginRequiredMixin, PermissionRequiredMixin, DetailView):
	model = eventinfo
	permission_required = ('edc.view_eventinfo')



def oplogs(request):
	context = {
	    'opdata': oplog.objects.all()
	}
	return render(request, 'edc/oplogs.html', context)

class oplogListView(LoginRequiredMixin, PermissionRequiredMixin, ListView):
	model = oplog
	template_name = 'edc/oplogs.html'
	context_object_name='opdata'
	ordering = ['-start_time']
	paginate_by = 50
	permission_required = ('edc.add_oplog')

class operatoroplogListView(LoginRequiredMixin, PermissionRequiredMixin, ListView):
	model = oplog
	template_name = 'edc/operator_oplogs.html'
	context_object_name='opdata'
	paginate_by = 50
	permission_required = ('edc.add_oplog')

	def get_queryset(self):
		user = get_object_or_404(User, username=self.kwargs.get('username'))
		return oplog.objects.filter(operator=user).order_by('-start_time')

class oplogDetailView(LoginRequiredMixin, PermissionRequiredMixin, DetailView):
	model = oplog
	permission_required = ('edc.add_oplog')

class oplogCreateView(LoginRequiredMixin, PermissionRequiredMixin, CreateView):
	model = oplog
	fields = oentry
	permission_required = ('edc.add_oplog')


class oplogUpdateView(LoginRequiredMixin, UpdateView):
	model = oplog
	fields = oentry
	permission_required = ('edc.change_oplog')

class oplogDeleteView(LoginRequiredMixin, PermissionRequiredMixin, DeleteView):
	model = oplog
	success_url = '/oplogs'
	permission_required = ('edc.delete_oplog')

class tagListView(LoginRequiredMixin, PermissionRequiredMixin, ListView):
        model = oplog
        template_name = 'edc/tagged_oplogs.html'
        context_object_name='opdata'
        order_by = ['-start_time']
        paginate_by = 50
        permission_required = ('edc.add_oplog')

        def get_queryset(self):
            return oplog.objects.filter(tags__slug=self.kwargs.get('slug')).order_by('-start_time')

def targets(request):
	context = {
	    'targetdata': target.objects.all()
	}
	return render(request, 'edc/targets.html', context)

class targetListView(LoginRequiredMixin, PermissionRequiredMixin, ListView):
	model = target
	template_name = 'edc/targets.html'
	context_object_name='targetdata'
	ordering = ['host']
	paginate_by = 50
	permission_required = ('edc.view_target')

class targetDetailView(LoginRequiredMixin, PermissionRequiredMixin, DetailView):
	model = target
	permission_required = ('edc.view_target')

class targetCreateView(LoginRequiredMixin, PermissionRequiredMixin, CreateView):
	model = target
	fields = tentry
	success_url = '/targets'
	permission_required = ('edc.add_target')

class targetUpdateView(LoginRequiredMixin, PermissionRequiredMixin, UpdateView):
	model = target
	fields = tentry
	success_url = '/targets'
	permission_required = ('edc.change_target')

class targetDeleteView(LoginRequiredMixin, PermissionRequiredMixin, DeleteView):
	model = target
	success_url = '/targets'
	permission_required = ('edc.delete_target')




def creds(request):
	context = {
	    'creddata': creds.objects.all()
	}
	return render(request, 'edc/creds.html', context)

class credListView(LoginRequiredMixin, PermissionRequiredMixin, ListView):
	model = cred
	template_name = 'edc/creds.html'
	context_object_name='creddata'
	ordering = ['username']
	paginate_by = 50
	permission_required = ('edc.view_cred')

class credDetailView(LoginRequiredMixin, PermissionRequiredMixin, DetailView):
	model = cred
	permission_required = ('edc.view_cred')

class credCreateView(LoginRequiredMixin, PermissionRequiredMixin, CreateView):
	model = cred
	fields = centry
	success_url = '/creds'
	permission_required = ('edc.add_cred')

class credUpdateView(LoginRequiredMixin, PermissionRequiredMixin, UpdateView):
	model = cred
	fields = centry
	success_url = '/creds'
	permission_required = ('edc.change_cred')

class credDeleteView(LoginRequiredMixin, PermissionRequiredMixin, DeleteView):
	model = cred
	success_url = '/creds'
	permission_required = ('edc.delete_cred')



def decons(request):
	context = {
	    'opdata': oplog.objects.all()
	}
	return render(request, 'edc/decon.html', context)

class deconListView(LoginRequiredMixin, PermissionRequiredMixin, ListView):
	model = oplog
	template_name = 'edc/decon.html'
	context_object_name='opdata'
	ordering = ['-start_time']
	paginate_by = 50
	permission_required = ('edc.view_oplog')


def payloads(request):
        context = {
            'payloaddata': payloadinfo.objects.all()
        }
        return render(request, 'edc/payloads.html', context)

class payloadListView(LoginRequiredMixin, PermissionRequiredMixin, ListView):
        model = payloadinfo
        template_name = 'edc/payloads.html'
        context_object_name='payloaddata'
        ordering = ['inf']
        paginate_by = 50
        permission_required = ('edc.view_payloadinfo')

class payloadDetailView(LoginRequiredMixin, PermissionRequiredMixin, DetailView):
        model = payloadinfo
        permission_required = ('edc.view_payloadinfo')

class payloadCreateView(LoginRequiredMixin, PermissionRequiredMixin, CreateView):
        model = payloadinfo
        fields = pentry
        success_url = '/payloads'
        permission_required = ('edc.add_payloadinfo')

class payloadUpdateView(LoginRequiredMixin, PermissionRequiredMixin, UpdateView):
        model = payloadinfo
        fields = pentry
        success_url = '/payloads'
        permission_required = ('edc.change_payloadinfo')

class payloadDeleteView(LoginRequiredMixin, PermissionRequiredMixin, DeleteView):
        model = payloadinfo
        success_url = '/payloads'
        permission_required = ('edc.delete_payloadinfo')

class oplogViewSet(viewsets.ModelViewSet):
	queryset = oplog.objects.all().order_by('-start_time')
	serializer_class = oplogSerializer
	lookup_field = 'operator'

class targetViewSet(viewsets.ModelViewSet):
	queryset = target.objects.all().order_by('-host')
	serializer_class = targetSerializer

class credViewSet(viewsets.ModelViewSet):
	queryset = cred.objects.all().order_by('-username')
	serializer_class = credSerializer

class eventinfoViewSet(viewsets.ModelViewSet):
	queryset = eventinfo.objects.all().order_by('-dates')
	serializer_class = eventinfoSerializer

class authview(ObtainAuthToken):
	def post(self, request,*args, **kwargs):
		response = super(authview, self).post(request, *args, **kwargs)
		token = Token.objects.get(key=response.data['token'])
		return Response({'token': token.key, 'id': token.user_id})

@login_required
@permission_required('edc.add_oplog')
def oplogexport(request):
	response = HttpResponse(content_type='text/csv')
	response['Content-Disposition'] = 'attachment; filename="oplog.csv"'

	writer = csv.writer(response)
	writer.writerow(oentry)

	logs = oplog.objects.all().values_list('start_time', 'stop_time', 'src_host', 'src_ip', 'src_port', 'dst_host', 'dst_ip', 'dst_port', 'piv_host', 'piv_ip', 'piv_port', 'url', 'tool', 'cmds', 'description', 'result', 'output', 'scrsht', 'mods', 'exfil', 'comments', 'operator')
	for log in logs:
		writer.writerow(log)
	
	return response

@login_required
@permission_required('edc.view_target')
def targetexport(request):
	response = HttpResponse(content_type='text/csv')
	response['Content-Disposition'] = 'attachment; filename="targets.csv"'

	writer = csv.writer(response)
	writer.writerow(tentry)

	logs = target.objects.all().values_list('host', 'ip', 'network', 'users', 'description', 'comments')
	for log in logs:
		writer.writerow(log)
	
	return response

@login_required
@permission_required('edc.view_cred')
def credexport(request):
	response = HttpResponse(content_type='text/csv')
	response['Content-Disposition'] = 'attachment; filename="creds.csv"'

	writer = csv.writer(response)
	writer.writerow(centry)

	logs = cred.objects.all().values_list('username', 'passwd', 'hashw', 'token', 'tknfile', 'first', 'last', 'role', 'description')
	for log in logs:
		writer.writerow(log)
	
	return response
