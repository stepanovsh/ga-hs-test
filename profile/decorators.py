# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json
import logging

import endpoints
import jwt

from profile.models import User
from settings import JWT_SECRET, JWT_ALGORITHM

logging.getLogger().setLevel(logging.DEBUG)


def user_required(handler):
    """
      Decorator that checks if there's a user associated with the current token.
    """

    def check_login(self, *args, **kwargs):
        auth_header = self.request_state.headers.get('authorization', '')
        if not len(auth_header):
            logging.info('Access token invalid')
            raise endpoints.UnauthorizedException("Your have invalid token format!")
        start, token = auth_header.split(' ')
        if start == 'Bearer' and token:
            try:
                payload = jwt.decode(token, JWT_SECRET, issuer='auth', algorithms=JWT_ALGORITHM)
                user, tmst = User.get_by_auth_token(int(payload.get('user_id')), token)
                if user is None:
                    logging.info('We can\' find associated users')
                    raise endpoints.UnauthorizedException("Your have invalid token!")
                else:
                    self.user = user
                    self.token = token
                    return handler(self, *args, **kwargs)
            except jwt.ExpiredSignatureError:
                logging.info('Refresh token has been expired')
                raise endpoints.UnauthorizedException("Your access token has been expired!")
            except jwt.InvalidIssuerError:
                logging.info('Access token issue error')
                raise endpoints.UnauthorizedException("Your have invalid token type!")
        else:
            logging.info('Access token has been invalid')
            raise endpoints.UnauthorizedException("Your have invalid token format!")

    return check_login