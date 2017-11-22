import logging

import endpoints
import jwt

from protorpc import remote, message_types

from webapp2_extras.auth import InvalidAuthIdError, InvalidPasswordError

from profile.decorators import user_required
from profile.handlers import BaseHandler
from profile.messages import SignUpRequest, SignUpResponse, SignInRequest, SignInResponse, RefreshRequest, \
    ProfileRequest, ProfileResponse
from profile.models import User
from settings import JWT_SECRET, JWT_ALGORITHM

logging.getLogger().setLevel(logging.DEBUG)


@endpoints.api(name='user', version='v1', description='User API', api_key_required=True)
class UserApi(BaseHandler, remote.Service):

    @endpoints.method(request_message=SignUpRequest,
                      response_message=SignUpResponse,
                      path='signup',
                      http_method='POST',
                      name='sign_up',)
    def sign_up(self, instance):
        logging.info(instance)
        email = instance.email
        first_name = instance.first_name
        last_name = instance.last_name
        password = instance.password
        repeat_password = instance.repeat_password

        if password != repeat_password:
            raise endpoints.BadRequestException(
                "Password do not match")

        unique_properties = ['email']
        user_data = User.create_user(email,
                                     unique_properties,
                                     email=email, first_name=first_name, password_raw=password,
                                     last_name=last_name, verified=True)
        if not user_data[0]:
            raise endpoints.BadRequestException(
                "User with this email already exists.")
        user = user_data[1]
        user_id = user.get_id()

        token, refresh_token = User.create_auth_token(user_id)

        return SignUpResponse(
            id=user.get_id(),
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            access_token=token,
            refresh_token=refresh_token
        )

    @endpoints.method(request_message=SignInRequest,
                      response_message=SignInResponse,
                      path='signin',
                      http_method='POST',
                      name='sign_in', )
    def sign_in(self, instance):
        logging.info(instance)
        email = instance.email
        password = instance.password
        try:
            user = User.get_by_auth_password(email, password=password)
            token, refresh_token = User.create_auth_token(user.get_id())

        except (InvalidAuthIdError, InvalidPasswordError) as e:
            logging.info('Login failed for user %s because of %s', email, type(e))

            raise endpoints.BadRequestException({
                'Login failed for user %s because user with this email does not exist' % email
            })

        return SignInResponse(
            id=user.get_id(),
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            access_token=token,
            refresh_token=refresh_token
        )

    @endpoints.method(request_message=RefreshRequest,
                      response_message=SignInResponse,
                      path='refresh',
                      http_method='POST',
                      name='refresh', )
    def refresh(self, instance):
        refresh_token = instance.refresh_token
        try:
            payload = jwt.decode(refresh_token, JWT_SECRET, issuer='refresh', algorithms=JWT_ALGORITHM)
        except jwt.ExpiredSignatureError:

            logging.info('Refresh token has been expired')
            raise endpoints.BadRequestException(
                'Your refresh token has been expired!')
        except jwt.InvalidIssuerError:
            logging.info('Refresh token has been expired')
            raise endpoints.BadRequestException(
                'Your have invalid token type!')
        user_id = int(payload['user_id'])
        user, timestamp = User.get_by_refresh_token(user_id, refresh_token)
        if user is None and timestamp is None:
            logging.info('Invalid refresh token!')
            raise endpoints.BadRequestException(
                'Invalid refresh token!')
        token, refresh_token = User.create_auth_token(user_id)

        return SignInResponse(
            id=user.get_id(),
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            access_token=token,
            refresh_token=refresh_token
        )

    @endpoints.method(message_types.VoidMessage,
                      message_types.VoidMessage,
                      path='logout',
                      http_method='GET',
                      name='logout', )
    @user_required
    def logout(self, instance):
        logging.info(instance)
        User.delete_auth_token(self.user.get_id(), self.token)
        return message_types.VoidMessage()

    @endpoints.method(message_types.VoidMessage,
                      ProfileResponse,
                      path='profile',
                      http_method='GET',
                      name='retrieve_profile', )
    @user_required
    def retrieve_profile(self, instance):
        logging.info(instance)
        return ProfileResponse(
            id=self.user.get_id(),
            email=self.user.email,
            first_name=self.user.first_name,
            last_name=self.user.last_name,
        )

    @endpoints.method(ProfileRequest,
                      ProfileResponse,
                      path='profile',
                      http_method='PUT',
                      name='update_profile', )
    @user_required
    def update_profile(self, instance):
        logging.info(instance)
        if self.user.email != instance.email:
            ur = User.get_by_auth_id(instance.email)
            if ur is not None:
                raise endpoints.BadRequestException('User with this email already exists')
            self.user.email = instance.email
            self.user.add_auth_id(instance.email)
        for field in instance.all_fields():
            if field.name != 'email':
                value = getattr(instance, field.name)
                setattr(self.user, field.name, value)
        self.user.put()
        return ProfileResponse(
            id=self.user.get_id(),
            email=self.user.email,
            first_name=self.user.first_name,
            last_name=self.user.last_name,
        )

    @endpoints.method(message_types.VoidMessage,
                      message_types.VoidMessage,
                      path='profile',
                      http_method='DELETE',
                      name='delete_profile', )
    @user_required
    def delete_profile(self, instance):
        logging.info(instance)
        user_id = self.user.get_id()
        User.delete_auth_token(self.user.get_id(), self.token)
        User.delete_by_id(user_id)
        return message_types.VoidMessage()
