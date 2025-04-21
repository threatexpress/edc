from rest_framework import serializers
from rest_framework_json_api.relations import ResourceRelatedField
from .models import oplog, target, cred, eventinfo
from django.contrib.auth.models import User

class userSerializer(serializers.HyperlinkedModelSerializer):
	class Meta:
		model = User
		fields = ['id', 'username']

class oplogSerializer(serializers.HyperlinkedModelSerializer):
	operator = userSerializer(read_only=True)
	operator_id = serializers.PrimaryKeyRelatedField(
		queryset=User.objects.all(), write_only=True,
		source='operator'
		)

	def create(self, validated_data):
		return oplog.objects.create(**validated_data)


	class Meta:
		model = oplog
		fields = ['start_time', 'stop_time', 'src_host', 'src_ip', 'src_port', 'dst_host', 'dst_ip', 'dst_port', 'piv_host', 'piv_ip', 'piv_port', 'url', 'tool', 'cmds', 'description', 'result', 'output', 'scrsht', 'mods', 'exfil', 'comments', 'operator', 'operator_id']

class targetSerializer(serializers.HyperlinkedModelSerializer):
	class Meta:
		model = target
		fields = ['host', 'ip', 'network', 'users', 'description', 'comments']

class credSerializer(serializers.HyperlinkedModelSerializer):
	class Meta:
		model = cred
		fields = ['username', 'passwd', 'hashw', 'token', 'tknfile', 'first', 'last', 'role', 'description']

class eventinfoSerializer(serializers.HyperlinkedModelSerializer):
	class Meta:
		model = eventinfo
		fields = ['dates', 'poc', 'auth', 'unatuh', 'notes']
