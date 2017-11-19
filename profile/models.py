from __future__ import unicode_literals

import jwt
import time

from datetime import datetime, timedelta
from settings import JWT_EXP_DELTA_SECONDS, JWT_ALGORITHM, JWT_SECRET, REFRESH_JWT_EXP_DELTA_SECONDS

try:
    from ndb import model
except ImportError: # pragma: no cover
    from google.appengine.ext.ndb import model

from webapp2_extras import security
from webapp2_extras.appengine.auth import models


class JWTUserToken(models.UserToken):

    @classmethod
    def generate_jwt(cls, user, subject):
        payload = {
            'user_id': user,
            'subject': subject,
            'exp': datetime.utcnow() + timedelta(
                seconds=JWT_EXP_DELTA_SECONDS if subject == 'auth' else REFRESH_JWT_EXP_DELTA_SECONDS)
        }
        jwt_token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
        return jwt_token

    @classmethod
    def create(cls, user, subject, token=None):
        """Creates a new token for the given user.

        :param user:
            User unique ID.
        :param subject:
            The subject of the key. Examples:
            - 'auth'
            - 'refresh'
        :param token:
            Optionally an existing token may be provided.
            If None, a random token will be generated.
        :returns:
            The newly created :class:`UserToken`.
        """
        user = str(user)
        token = token or cls.generate_jwt(user, subject)
        subject = subject or 'auth'
        key = cls.get_key(user, subject, token)
        entity = cls(key=key, user=user, subject=subject, token=token)
        entity.put()
        return entity


class User(models.User):
    token_model = JWTUserToken

    def set_password(self, raw_password):
        """Sets the password for the current user

        :param raw_password:
            The raw password which will be hashed and stored
        """
        self.password = security.generate_password_hash(raw_password, length=12)

    @classmethod
    def create_auth_token(cls, user_id):
        """Creates a new authorization token for a given user ID.

        :param user_id:
            User unique ID.
        :returns:
            A tuple with authorization token and refresh token.
        """
        return cls.token_model.create(user_id, 'auth').token, cls.token_model.create(user_id, 'refresh').token

    @classmethod
    def get_by_refresh_token(cls, user_id, token):
        """Returns a user object based on a user ID and token.

        :param user_id:
            The user_id of the requesting user.
        :param token:
            The token string to be verified.
        :returns:
            A tuple ``(User, timestamp)``, with a user object and
            the token timestamp, or ``(None, None)`` if both were not found.
        """
        token_key = cls.token_model.get_key(user_id, 'refresh', token)
        user_key = model.Key(cls, user_id)
        # Use get_multi() to save a RPC call.
        valid_token, user = model.get_multi([token_key, user_key])
        if valid_token and user:
            timestamp = int(time.mktime(valid_token.created.timetuple()))
            return user, timestamp

        return None, None




