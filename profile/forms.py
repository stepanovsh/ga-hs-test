from __future__ import unicode_literals

import wtforms


class SignUpForm(wtforms.Form):

    email = wtforms.StringField(validators=[
        wtforms.validators.Email(),
        wtforms.validators.required(),
        wtforms.validators.length(max=255)
    ])
    first_name = wtforms.StringField(validators=[
        wtforms.validators.required(),
        wtforms.validators.length(max=255)
    ])
    last_name = wtforms.StringField(validators=[
        wtforms.validators.required(),
        wtforms.validators.length(max=255)
    ])
    password = wtforms.PasswordField(validators=[
        wtforms.validators.required(),
        wtforms.validators.length(min=6, max=255)
    ])
    repeat_password = wtforms.PasswordField(validators=[
        wtforms.validators.required(),
        wtforms.validators.length(min=6, max=255)
    ])

    def validate(self):
        ret = super(SignUpForm, self).validate()
        password = self.data.get('password')
        repeat_password = self.data.get('repeat_password')
        if password != repeat_password:
            self._errors = {'non_fields_errors': 'Passwords do not match!'}
            return False
        return ret


class SignInForm(wtforms.Form):
    GRANT_TYPE_CHOICES = (
        ('password', 'password',),
        ('refresh', 'refresh',),
    )
    grant_type = wtforms.SelectField(choices=GRANT_TYPE_CHOICES, coerce=str)
    email = wtforms.StringField(validators=[
        wtforms.validators.Email(),
        wtforms.validators.required(),
        wtforms.validators.length(max=255)
    ])
    password = wtforms.PasswordField(validators=[
        wtforms.validators.required(),
        wtforms.validators.length(min=6, max=255)
    ])


class RefreshForm(wtforms.Form):
    GRANT_TYPE_CHOICES = (
        ('password', 'password',),
        ('refresh', 'refresh',),
    )
    grant_type = wtforms.SelectField(choices=GRANT_TYPE_CHOICES, coerce=str)
    refresh_token = wtforms.StringField(validators=[wtforms.validators.required()])
