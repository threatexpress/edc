from django.shortcuts import render, redirect
from .forms import UserRegisterForm, UserUpdateForm, ProfileUpdateForm
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.decorators import login_required

def register(request):
	if request.method == 'POST':
		form = UserRegisterForm(request.POST)
		if form.is_valid():
			form.save()
			username = form.cleaned_data.get('username')
			messages.success(request, f'Account created for {username}!')
			return redirect('two_factor:login')
	else:
		form = UserRegisterForm()
	return render(request, 'users/register.html', {'form': form})

@login_required
def password_change(request):
	if request.method == 'POST':
		form = PasswordChangeForm(request.user, request.POST)
		if form.is_valid():
			user = form.save()
			update_session_auth_hash(request, user)
			messages.success(request, f'Update success!')
			return redirect('profile')
	else:
		form = PasswordChangeForm(request.user)
	return render(request, 'users/password_change.html', {'form': form })

@login_required
def profile(request):
	if request.method == 'POST':
	    u_form = UserUpdateForm(request.POST, instance=request.user)
	    p_form = ProfileUpdateForm(request.POST, request.FILES, instance=request.user.profile)
	    if u_form.is_valid() and p_form.is_valid():
	    	u_form.save()
	    	p_form.save()
	    	messages.success(request, f'Update success!')
	    	return redirect('profile')
	else:
		u_form = UserUpdateForm(instance=request.user)
		p_form = ProfileUpdateForm(instance=request.user.profile)

	context = {
	'u_form': u_form,
	'p_form': p_form
	}

	return render(request, 'users/profile.html', context)

