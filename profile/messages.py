# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from protorpc import messages


class SignUpRequest(messages.Message):
    email = messages.StringField(1, required=True)
    first_name = messages.StringField(2, required=True)
    last_name = messages.StringField(3, required=True)
    password = messages.StringField(4, required=True)
    repeat_password = messages.StringField(5, required=True)


class SignUpResponse(messages.Message):
    """A proto Message that contains a simple string field."""
    id = messages.IntegerField(1, required=True)
    email = messages.StringField(2, required=True)
    first_name = messages.StringField(3, required=True)
    last_name = messages.StringField(4, required=True)
    access_token = messages.StringField(5, required=True)
    refresh_token = messages.StringField(6, required=True)


class SignInRequest(messages.Message):
    email = messages.StringField(1, required=True)
    password = messages.StringField(4, required=True)


class SignInResponse(messages.Message):
    """A proto Message that contains a simple string field."""
    id = messages.IntegerField(1, required=True)
    email = messages.StringField(2, required=True)
    first_name = messages.StringField(3, required=True)
    last_name = messages.StringField(4, required=True)
    access_token = messages.StringField(5, required=True)
    refresh_token = messages.StringField(6, required=True)


class RefreshRequest(messages.Message):
    refresh_token = messages.StringField(1, required=True)


class ProfileRequest(messages.Message):
    email = messages.StringField(1, required=True)
    first_name = messages.StringField(2, required=True)
    last_name = messages.StringField(3, required=True)


class ProfileResponse(messages.Message):
    """A proto Message that contains a simple string field."""
    id = messages.IntegerField(1, required=True)
    email = messages.StringField(2, required=True)
    first_name = messages.StringField(3, required=True)
    last_name = messages.StringField(4, required=True)
