#!/usr/bin/env python

from google.appengine.ext.webapp import template
from google.appengine.ext import ndb

import logging
import os.path
import webapp2
import wtforms

from webapp2_extras import auth, json
from webapp2_extras import sessions

from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError

from profile.forms import SignUpForm


def user_required(handler):
    """
      Decorator that checks if there's a user associated with the current session.
      Will also fail if there's no session present.
    """

    def check_login(self, *args, **kwargs):
        auth = self.auth
        if not auth.get_user_by_session():
            self.redirect(self.uri_for('login'), abort=True)
        else:
            return handler(self, *args, **kwargs)

    return check_login


class BaseHandler(webapp2.RequestHandler):
    @webapp2.cached_property
    def auth(self):
        """Shortcut to access the auth instance as a property."""
        return auth.get_auth()

    @webapp2.cached_property
    def user_info(self):
        """Shortcut to access a subset of the user attributes that are stored
        in the session.

        The list of attributes to store in the session is specified in
          config['webapp2_extras.auth']['user_attributes'].
        :returns
          A dictionary with most user information
        """
        return self.auth.get_user_by_session()

    @webapp2.cached_property
    def user(self):
        """Shortcut to access the current logged in user.

        Unlike user_info, it fetches information from the persistence layer and
        returns an instance of the underlying model.

        :returns
          The instance of the user model associated to the logged in user.
        """
        u = self.user_info
        return self.user_model.get_by_id(u['user_id']) if u else None

    @webapp2.cached_property
    def user_model(self):
        """Returns the implementation of the user model.

        It is consistent with config['webapp2_extras.auth']['user_model'], if set.
        """
        return self.auth.store.user_model


class SignupHandler(BaseHandler):

    def post(self):
        data = self.request.json_body if self.request.content_type == 'application/json' else self.request.POST
        self.response.headers['Content-Type'] = 'application/json'
        form = SignUpForm(data=data)
        if not form.validate():
            self.response.write(json.encode(form.errors))
            self.response.set_status(400)
            return

        email = form.data.get('email')
        first_name = form.data.get('first_name')
        last_name = form.data.get('lastname')
        password = form.data.get('password')

        unique_properties = ['email_address']
        user_data = self.user_model.create_user(email,
                                                unique_properties,
                                                email_address=email, name=first_name, password_raw=password,
                                                last_name=last_name, verified=True)
        if not user_data[0]:  # user_data is a tuple
            self.response.write(json.encode({
                'non_fields_errors': 'Unable to create user for email %s because of duplicate keys %s' % (email, user_data[1])
            }))
            self.response.set_status(400)
            return

        user = user_data[1]
        user_id = user.get_id()

        token, refresh_token = self.user_model.create_auth_token(user_id)

        self.response.headers['Content-Type'] = 'application/json'
        obj = {
            'user_id': user_id,
            'access_token': token,
            'refresh_token': refresh_token
        }
        self.response.write(json.encode(obj))
        self.response.set_status(201)


logging.getLogger().setLevel(logging.DEBUG)