from __future__ import unicode_literals

import unittest

import copy

import endpoints
import jwt
import webapp2
import mock

from datetime import datetime, timedelta

from google.appengine.ext import testbed, ndb
from protorpc import message_types

import main

from settings import JWT_SECRET, JWT_ALGORITHM, REFRESH_JWT_EXP_DELTA_SECONDS
from profile import apis
from profile import messages
from mock import patch


class SignUpTestCase(unittest.TestCase):

    def setUp(self):
        # First, create an instance of the Testbed class.
        self.testbed = testbed.Testbed()
        # Then activate the testbed, which prepares the service stubs for use.
        self.testbed.activate()
        # Next, declare which service stubs you want to use.
        self.testbed.init_datastore_v3_stub()
        self.testbed.init_memcache_stub()
        self.good_data = {
            "email": "stepanov+1@example.com",
            "first_name": "Alex",
            "last_name": "Alex",
            "password": "test1234",
            "repeat_password": "test1234"
        }
        ndb.get_context().clear_cache()
        self.signu_up_endpoint = '/_ah/api/user/v1/signup'

    def test_sign_up_success(self):
        api = apis.UserApi()
        request = messages.SignUpRequest(**self.good_data)
        response = api.sign_up(request)

        self.assertIsNotNone(response.access_token)
        self.assertIsNotNone(response.refresh_token)
        self.assertIsNotNone(response.id)

        user_id = response.id
        access_token = response.access_token
        refresh_token = response.refresh_token

        payload = jwt.decode(access_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))
        payload = jwt.decode(refresh_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))

    def test_bad_request(self):
        api = apis.UserApi()

        invalid_data = copy.deepcopy(self.good_data)
        invalid_data['password'] = 'alex1234'
        invalid_data['repeat_password'] = 'alex4321'
        request = messages.SignUpRequest(**invalid_data)
        self.assertRaises(endpoints.BadRequestException, api.sign_up, request)

        request = messages.SignUpRequest(**self.good_data)
        response = api.sign_up(request)

        self.assertIsNotNone(response.access_token)
        self.assertIsNotNone(response.refresh_token)
        self.assertIsNotNone(response.id)

        user_id = response.id
        access_token = response.access_token
        refresh_token = response.refresh_token

        payload = jwt.decode(access_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))
        payload = jwt.decode(refresh_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))

        request = messages.SignUpRequest(**self.good_data)
        self.assertRaises(endpoints.BadRequestException, api.sign_up, request)

    def tearDown(self):
        self.testbed.deactivate()


class SignInTestCase(unittest.TestCase):

    def setUp(self):
        # First, create an instance of the Testbed class.
        self.testbed = testbed.Testbed()
        # Then activate the testbed, which prepares the service stubs for use.
        self.testbed.activate()
        # Next, declare which service stubs you want to use.
        self.testbed.init_datastore_v3_stub()
        self.testbed.init_memcache_stub()
        self.good_data = {
            "email": "stepanov@example.com",
            "first_name": "Alex",
            "last_name": "Alex",
            "password": "test1234",
            "repeat_password": "test1234"
        }
        self.sign_in = {
            "email": "stepanov@example.com",
            "password": "test1234",
        }
        ndb.get_context().clear_cache()

    def test_sign_in_success(self):
        api = apis.UserApi()
        request = messages.SignUpRequest(**self.good_data)
        response = api.sign_up(request)

        self.assertIsNotNone(response.access_token)
        self.assertIsNotNone(response.refresh_token)
        self.assertIsNotNone(response.id)

        user_id = response.id
        access_token = response.access_token
        refresh_token = response.refresh_token

        payload = jwt.decode(access_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))
        payload = jwt.decode(refresh_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))

        api = apis.UserApi()
        request = messages.SignInRequest(**self.sign_in)
        response = api.sign_in(request)

        self.assertIsNotNone(response.access_token)
        self.assertIsNotNone(response.refresh_token)
        self.assertIsNotNone(response.id)

        user_id = response.id
        access_token = response.access_token
        refresh_token = response.refresh_token

        payload = jwt.decode(access_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))
        payload = jwt.decode(refresh_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))

    def test_bad_request(self):
        api = apis.UserApi()
        request = messages.SignUpRequest(**self.good_data)
        response = api.sign_up(request)

        self.assertIsNotNone(response.access_token)
        self.assertIsNotNone(response.refresh_token)
        self.assertIsNotNone(response.id)

        invalid_data = copy.deepcopy(self.sign_in)
        invalid_data['password'] = 'hello'
        api = apis.UserApi()
        request = messages.SignInRequest(**invalid_data)
        self.assertRaises(endpoints.BadRequestException, api.sign_in, request)

    def tearDown(self):
        self.testbed.deactivate()


class LogoutTestCase(unittest.TestCase):

    def setUp(self):
        # First, create an instance of the Testbed class.
        self.testbed = testbed.Testbed()
        # Then activate the testbed, which prepares the service stubs for use.
        self.testbed.activate()
        # Next, declare which service stubs you want to use.
        self.testbed.init_datastore_v3_stub()
        self.testbed.init_memcache_stub()
        self.good_data = {
            "email": "stepanov@example.com",
            "first_name": "Alex",
            "last_name": "Alex",
            "password": "test1234",
            "repeat_password": "test1234"
        }
        ndb.get_context().clear_cache()

    def test_logout_success(self):
        api = apis.UserApi()
        request = messages.SignUpRequest(**self.good_data)
        response = api.sign_up(request)

        self.assertIsNotNone(response.access_token)
        self.assertIsNotNone(response.refresh_token)
        self.assertIsNotNone(response.id)

        with patch('profile.apis.UserApi.request_state') as req_state:
            req_state.return_value = None
            req_state.return_value = mock.Mock
            req_state.return_value.headers = {
                'authorization': 'Bearer {}'.format(response.access_token)
            }

            response = api.logout(message_types.VoidMessage())
            print response

    def test_permissions(self):
        api = apis.UserApi()
        request = messages.SignUpRequest(**self.good_data)
        response = api.sign_up(request)

        self.assertIsNotNone(response.access_token)
        self.assertIsNotNone(response.refresh_token)
        self.assertIsNotNone(response.id)

        with patch('profile.apis.UserApi.request_state') as req_state:
            req_state.return_value = None
            req_state.return_value = mock.Mock
            req_state.return_value.headers = {
                'authorization': 'Berer {}'.format(response.access_token)
            }
            self.assertRaises(endpoints.UnauthorizedException, api.logout, message_types.VoidMessage())


class RefreshTestCase(unittest.TestCase):

    def setUp(self):
        # First, create an instance of the Testbed class.
        self.testbed = testbed.Testbed()
        # Then activate the testbed, which prepares the service stubs for use.
        self.testbed.activate()
        # Next, declare which service stubs you want to use.
        self.testbed.init_datastore_v3_stub()
        self.testbed.init_memcache_stub()
        self.good_data = {
            "email": "stepanov@example.com",
            "first_name": "Alex",
            "last_name": "Alex",
            "password": "test1234",
            "repeat_password": "test1234"
        }
        self.refresh = {}
        ndb.get_context().clear_cache()

    def test_refresh_success(self):
        api = apis.UserApi()
        request = messages.SignUpRequest(**self.good_data)
        response = api.sign_up(request)

        self.assertIsNotNone(response.access_token)
        self.assertIsNotNone(response.refresh_token)
        self.assertIsNotNone(response.id)

        user_id = response.id
        access_token = response.access_token
        refresh_token = response.refresh_token

        payload = jwt.decode(access_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))
        payload = jwt.decode(refresh_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))

        self.refresh.update({
            'refresh_token': refresh_token
        })

        request = messages.RefreshRequest(**self.refresh)
        response = api.refresh(request)
        self.assertIsNotNone(response.access_token)
        self.assertIsNotNone(response.refresh_token)
        self.assertIsNotNone(response.id)

        user_id = response.id
        access_token = response.access_token
        refresh_token = response.refresh_token

        payload = jwt.decode(access_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))
        payload = jwt.decode(refresh_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))

    def test_bad_request(self):
        api = apis.UserApi()
        request = messages.SignUpRequest(**self.good_data)
        response = api.sign_up(request)

        self.assertIsNotNone(response.access_token)
        self.assertIsNotNone(response.refresh_token)
        self.assertIsNotNone(response.id)

        user_id = response.id
        access_token = response.access_token
        refresh_token = response.refresh_token

        payload = jwt.decode(access_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))
        payload = jwt.decode(refresh_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))

        invalid_data = copy.deepcopy(self.refresh)
        payload = {
            'user_id': int(user_id),
            'iss': 'refresh',
            'exp': datetime.utcnow() + timedelta(REFRESH_JWT_EXP_DELTA_SECONDS)
        }
        refresh_token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
        invalid_data['refresh_token'] = refresh_token
        with patch('jwt.decode') as jwt_decode:
            jwt_decode.side_effect = jwt.ExpiredSignatureError()
            request = messages.RefreshRequest(**invalid_data)
            self.assertRaises(endpoints.BadRequestException, api.refresh, request)

        invalid_data = copy.deepcopy(self.refresh)
        payload = {
            'user_id': int(user_id),
            'iss': 'auth',
            'exp': datetime.utcnow() + timedelta(REFRESH_JWT_EXP_DELTA_SECONDS)
        }
        refresh_token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
        invalid_data['refresh_token'] = refresh_token
        request = messages.RefreshRequest(**invalid_data)
        self.assertRaises(endpoints.BadRequestException, api.refresh, request)

        invalid_data = copy.deepcopy(self.refresh)
        payload = {
            'user_id': int(user_id),
            'iss': 'refresh',
            'exp': datetime.utcnow() + timedelta(REFRESH_JWT_EXP_DELTA_SECONDS)
        }
        refresh_token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
        invalid_data['refresh_token'] = refresh_token
        request = messages.RefreshRequest(**invalid_data)
        self.assertRaises(endpoints.BadRequestException, api.refresh, request)

    def tearDown(self):
        self.testbed.deactivate()


class RetrieveUpdateDeleteTestCases(unittest.TestCase):

    def setUp(self):
        # First, create an instance of the Testbed class.
        self.testbed = testbed.Testbed()
        # Then activate the testbed, which prepares the service stubs for use.
        self.testbed.activate()
        # Next, declare which service stubs you want to use.
        self.testbed.init_datastore_v3_stub()
        self.testbed.init_memcache_stub()
        self.good_data = {
            "email": "stepanov+1@example.com",
            "first_name": "Alex",
            "last_name": "Alex",
            "password": "test1234",
            "repeat_password": "test1234"
        }
        self.good_update_data = {
            "email": "stepanov+2@example.com",
            "first_name": "Alex",
            "last_name": "Alex"
        }
        ndb.get_context().clear_cache()

    def test_update_success(self):
        api = apis.UserApi()
        request = messages.SignUpRequest(**self.good_data)
        response = api.sign_up(request)

        self.assertIsNotNone(response.access_token)
        self.assertIsNotNone(response.refresh_token)
        self.assertIsNotNone(response.id)

        user_id = response.id
        access_token = response.access_token
        refresh_token = response.refresh_token

        payload = jwt.decode(access_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))
        payload = jwt.decode(refresh_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))

        with patch('profile.apis.UserApi.request_state') as req_state:
            req_state.return_value = None
            req_state.return_value = mock.Mock
            req_state.return_value.headers = {
                'authorization': 'Bearer {}'.format(access_token)
            }
            request = messages.ProfileRequest(**self.good_update_data)
            response = api.update_profile(request)
            self.assertEqual(response.first_name, self.good_update_data['first_name'])

    def test_retrieve_success(self):
        api = apis.UserApi()
        request = messages.SignUpRequest(**self.good_data)
        response = api.sign_up(request)

        self.assertIsNotNone(response.access_token)
        self.assertIsNotNone(response.refresh_token)
        self.assertIsNotNone(response.id)

        user_id = response.id
        access_token = response.access_token
        refresh_token = response.refresh_token

        payload = jwt.decode(access_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))
        payload = jwt.decode(refresh_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))

        with patch('profile.apis.UserApi.request_state') as req_state:
            req_state.return_value = None
            req_state.return_value = mock.Mock
            req_state.return_value.headers = {
                'authorization': 'Bearer {}'.format(access_token)
            }
            request = message_types.VoidMessage()
            response = api.retrieve_profile(request)
            self.assertEqual(response.first_name, self.good_update_data['first_name'])

    def test_delete_success(self):
        api = apis.UserApi()
        request = messages.SignUpRequest(**self.good_data)
        response = api.sign_up(request)

        self.assertIsNotNone(response.access_token)
        self.assertIsNotNone(response.refresh_token)
        self.assertIsNotNone(response.id)

        user_id = response.id
        access_token = response.access_token
        refresh_token = response.refresh_token

        payload = jwt.decode(access_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))
        payload = jwt.decode(refresh_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))

        with patch('profile.apis.UserApi.request_state') as req_state:
            req_state.return_value = None
            req_state.return_value = mock.Mock
            req_state.return_value.headers = {
                'authorization': 'Bearer {}'.format(access_token)
            }
            request = message_types.VoidMessage()
            api.retrieve_profile(request)

    def tearDown(self):
        self.testbed.deactivate()

