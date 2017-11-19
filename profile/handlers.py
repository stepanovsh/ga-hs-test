#!/usr/bin/env python
import logging

import jwt
import webapp2

from webapp2_extras import auth, json
from webapp2_extras.auth import InvalidAuthIdError, InvalidPasswordError

from profile.forms import SignUpForm, SignInForm, RefreshForm
from settings import JWT_SECRET, JWT_ALGORITHM


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
        last_name = form.data.get('last_name')
        password = form.data.get('password')

        unique_properties = ['email']
        user_data = self.user_model.create_user(email,
                                                unique_properties,
                                                email=email, first_name=first_name, password_raw=password,
                                                last_name=last_name, verified=True)
        if not user_data[0]:  # user_data is a tuple
            self.response.write(json.encode({
                'non_fields_errors': 'Unable to create user for email %s '
                                     'because of duplicate keys %s' % (email, user_data[1])
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


class TokenHandler(BaseHandler):

    def post(self):
        data = self.request.json_body if self.request.content_type == 'application/json' else self.request.POST

        grant_type = data.get('grant_type')
        if grant_type not in ['password', 'refresh']:
            self.response.write(json.encode({
                'non_fields_errors': 'Your provided grant type is invalid!'
            }))
            self.response.set_status(400)
            return
        self.response.headers['Content-Type'] = 'application/json'
        if grant_type == 'password':
            form = SignInForm(data=data)
            if not form.validate():
                self.response.write(json.encode(form.errors))
                self.response.set_status(400)
                return
            email = form.data.get('email')
            password = form.data.get('password')
            try:
                u = self.auth.get_user_by_password(email, password, remember=True)
                obj = {
                    'user_id': u.get('user_id'),
                    'email': u.get('email'),
                    'first_name': u.get('first_name'),
                    'last_name': u.get('last_name'),
                    'access_token': u.get('token')[0],
                    'refresh_token': u.get('token')[1],
                }
                self.response.write(json.encode(obj))
                self.response.set_status(200)

            except (InvalidAuthIdError, InvalidPasswordError) as e:
                self.response.write(json.encode({
                    'non_fields_errors': 'Login failed for user %s because user with this email does not exist' % email
                }))
                self.response.set_status(400)
                logging.info('Login failed for user %s because of %s', email, type(e))
        else:
            form = RefreshForm(data=data)
            if not form.validate():
                self.response.write(json.encode(form.errors))
                self.response.set_status(400)
                return
            refresh_token = form.data.get('refresh_token')
            try:
                payload = jwt.decode(refresh_token, JWT_SECRET, JWT_ALGORITHM)
            except jwt.ExpiredSignatureError:
                self.response.write(json.encode({
                    'refresh_token': 'Your refresh token has been expired!'
                }))
                self.response.set_status(400)
                logging.info('Refresh token has been expired')
                return
            user_id = int(payload['user_id'])
            u, timestamp = self.user_model.get_by_refresh_token(user_id, refresh_token)
            if u is None and timestamp is None:
                self.response.write(json.encode({
                    'refresh_token': 'Invalid refresh token!'
                }))
                self.response.set_status(400)
                logging.info('Invalid refresh token!')
                return
            token, refresh_token = self.user_model.create_auth_token(user_id)
            try:
                u = self.auth.get_user_by_token(user_id, token, remember=True)
                obj = {
                    'user_id': u.get('user_id'),
                    'email': u.get('email'),
                    'first_name': u.get('first_name'),
                    'last_name': u.get('last_name'),
                    'access_token': token,
                    'refresh_token': refresh_token,
                }
                self.response.write(json.encode(obj))
                self.response.set_status(200)
            except InvalidAuthIdError as e:
                self.response.write(json.encode({
                    'non_fields_errors': 'Login failed for user %s because '
                                         'user with this email does not exist' % user_id
                }))
                self.response.set_status(400)
                logging.info('Login failed for user %s because of %s', user_id, type(e))


logging.getLogger().setLevel(logging.DEBUG)
