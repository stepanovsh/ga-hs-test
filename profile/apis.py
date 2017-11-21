import logging

import endpoints

from protorpc import remote, message_types
from protorpc import messages

from webapp2_extras.auth import InvalidAuthIdError, InvalidPasswordError

from profile.decorators import user_required
from profile.handlers import BaseHandler
from profile.messages import SignUpRequest, SignUpResponse, SignInRequest, SignInResponse
from profile.models import User

logging.getLogger().setLevel(logging.DEBUG)


@endpoints.api(name='user', version='v1', description='User API')
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

        unique_properties = ['email']
        user_data = User.create_user(email,
                                     unique_properties,
                                     email=email, first_name=first_name, password_raw=password,
                                     last_name=last_name, verified=True)
        if not user_data[0]:
            raise endpoints.ConflictException(
                "User with this email already exists.")
        user = user_data[1]
        user_id = user.get_id()

        token, refresh_token = User.create_auth_token(user_id)

        return SignUpResponse(
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

            raise endpoints.ConflictException({
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

    @endpoints.method(message_types.VoidMessage,
                      message_types.VoidMessage,
                      path='logout',
                      http_method='GET',
                      name='logout', )
    @user_required
    def logout(self, instance):
        logging.info(instance)
        print self.token, self.user
        User.delete_auth_token(self.user.get_id(), self.token)
