#C:\Users\HP\OneDrive\Documents\proj3\IT-Asset-Management\assets\forms.py
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2")

    def __init__(self, *args, **kwargs):
        """
        Apply Bootstrap's form-control class to every field so inputs render
        full-width and styled consistently with the rest of the site (login,
        etc.), instead of falling back to tiny default browser input styling.
        """
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.update({'class': 'form-control'})

    def save(self, commit=True):
        """
        Overrides the base implementation to ensure the email field is
        actually saved - the base UserCreationForm doesn't include email
        by default, so without this override it would be silently dropped.
        """
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user