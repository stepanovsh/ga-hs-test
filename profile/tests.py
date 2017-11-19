from __future__ import unicode_literals

import unittest

import copy
import jwt
import webapp2

from datetime import datetime, timedelta

from google.appengine.ext import testbed, ndb

import main
from settings import JWT_SECRET, JWT_ALGORITHM, JWT_EXP_DELTA_SECONDS, REFRESH_JWT_EXP_DELTA_SECONDS
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

    def test_sign_up_success(self):
        request = webapp2.Request.blank('/signup', POST=self.good_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 201)
        self.assertIsNotNone(response.json_body.get('access_token'))
        self.assertIsNotNone(response.json_body.get('refresh_token'))
        self.assertIsNotNone(response.json_body.get('user_id'))

        user_id = response.json_body.get('user_id')
        access_token = response.json_body.get('access_token')
        refresh_token = response.json_body.get('refresh_token')

        payload = jwt.decode(access_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))
        payload = jwt.decode(refresh_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))

    def test_permissions(self):
        request = webapp2.Request.blank('/signup', POST=self.good_data)
        request.method = 'GET'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 405)

        request.method = 'PUT'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 405)

        request.method = 'DELETE'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 405)

    def test_bad_request(self):
        invalid_data = {}
        request = webapp2.Request.blank('/signup', POST=invalid_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 400)
        self.assertIsNotNone(response.json_body.get('email'))

        invalid_data = copy.deepcopy(self.good_data)
        invalid_data['email'] = 'alex'
        request = webapp2.Request.blank('/signup', POST=invalid_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 400)
        self.assertIsNotNone(response.json_body.get('email'))

        invalid_data = copy.deepcopy(self.good_data)
        invalid_data['password'] = 'alex'
        invalid_data['repeat_password'] = 'alex'
        request = webapp2.Request.blank('/signup', POST=invalid_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 400)
        self.assertIsNotNone(response.json_body.get('password'))
        self.assertIsNotNone(response.json_body.get('repeat_password'))

        invalid_data = copy.deepcopy(self.good_data)
        invalid_data['password'] = 'alex1234'
        invalid_data['repeat_password'] = 'alex4321'
        request = webapp2.Request.blank('/signup', POST=invalid_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 400)
        self.assertIsNotNone(response.json_body.get('non_fields_errors'))

        request = webapp2.Request.blank('/signup', POST=self.good_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 201)
        self.assertIsNotNone(response.json_body.get('access_token'))
        self.assertIsNotNone(response.json_body.get('refresh_token'))
        self.assertIsNotNone(response.json_body.get('user_id'))

        request = webapp2.Request.blank('/signup', POST=self.good_data)
        request.method = 'POST'
        response = request.get_response(main.app)
        self.assertEqual(response.status_int, 400)
        self.assertIsNotNone(response.json_body.get('non_fields_errors'))

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
            "grant_type": "password",
            "email": "stepanov@example.com",
            "password": "test1234",
        }
        ndb.get_context().clear_cache()

    def test_sign_in_success(self):
        request = webapp2.Request.blank('/signup', POST=self.good_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 201)
        self.assertIsNotNone(response.json_body.get('access_token'))
        self.assertIsNotNone(response.json_body.get('refresh_token'))
        self.assertIsNotNone(response.json_body.get('user_id'))

        user_id = response.json_body.get('user_id')
        access_token = response.json_body.get('access_token')
        refresh_token = response.json_body.get('refresh_token')

        payload = jwt.decode(access_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))
        payload = jwt.decode(refresh_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))

        request = webapp2.Request.blank('/token', POST=self.sign_in)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 200)
        self.assertIsNotNone(response.json_body.get('access_token'))
        self.assertIsNotNone(response.json_body.get('refresh_token'))
        self.assertIsNotNone(response.json_body.get('user_id'))

        user_id = response.json_body.get('user_id')
        access_token = response.json_body.get('access_token')
        refresh_token = response.json_body.get('refresh_token')

        payload = jwt.decode(access_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))
        payload = jwt.decode(refresh_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))

    def test_permissions(self):
        request = webapp2.Request.blank('/signup', POST=self.good_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 201)
        self.assertIsNotNone(response.json_body.get('access_token'))
        self.assertIsNotNone(response.json_body.get('refresh_token'))
        self.assertIsNotNone(response.json_body.get('user_id'))

        request = webapp2.Request.blank('/token', POST=self.sign_in)
        request.method = 'GET'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 405)

        request.method = 'PUT'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 405)

        request.method = 'DELETE'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 405)

    def test_bad_request(self):
        request = webapp2.Request.blank('/signup', POST=self.good_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 201)
        self.assertIsNotNone(response.json_body.get('access_token'))
        self.assertIsNotNone(response.json_body.get('refresh_token'))
        self.assertIsNotNone(response.json_body.get('user_id'))

        invalid_data = {}
        request = webapp2.Request.blank('/token', POST=invalid_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 400)
        self.assertIsNotNone(response.json_body.get('non_fields_errors'))

        invalid_data = {
            'grant_type': 'password'
        }
        request = webapp2.Request.blank('/token', POST=invalid_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 400)
        self.assertIsNotNone(response.json_body.get('email'))

        invalid_data = copy.deepcopy(self.sign_in)
        invalid_data['email'] = 'alex'
        request = webapp2.Request.blank('/token', POST=invalid_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 400)
        self.assertIsNotNone(response.json_body.get('email'))

        invalid_data = copy.deepcopy(self.sign_in)
        invalid_data['password'] = 'alex'
        request = webapp2.Request.blank('/token', POST=invalid_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 400)
        self.assertIsNotNone(response.json_body.get('password'))

        invalid_data = copy.deepcopy(self.sign_in)
        invalid_data['password'] = 'alex1234'
        request = webapp2.Request.blank('/token', POST=invalid_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 400)
        self.assertIsNotNone(response.json_body.get('non_fields_errors'))

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
        request = webapp2.Request.blank('/signup', POST=self.good_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 201)
        self.assertIsNotNone(response.json_body.get('access_token'))
        self.assertIsNotNone(response.json_body.get('refresh_token'))
        self.assertIsNotNone(response.json_body.get('user_id'))

        user_id = response.json_body.get('user_id')
        access_token = response.json_body.get('access_token')
        refresh_token = response.json_body.get('refresh_token')

        payload = jwt.decode(access_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))
        payload = jwt.decode(refresh_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))

        request = webapp2.Request.blank('/logout', headers={'Authorization': 'Bearer %s' % access_token})
        request.method = 'GET'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 200)

        self.assertTrue(response.json_body.get('logout'))

    def test_permissions(self):
        request = webapp2.Request.blank('/signup', POST=self.good_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 201)
        self.assertIsNotNone(response.json_body.get('access_token'))
        self.assertIsNotNone(response.json_body.get('refresh_token'))
        self.assertIsNotNone(response.json_body.get('user_id'))

        access_token = response.json_body.get('access_token')

        request = webapp2.Request.blank('/logout', headers={'Authorization': 'Bearer %s' % access_token})
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 405)

        request.method = 'PUT'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 405)

        request.method = 'DELETE'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 405)

    def test_bad_request(self):
        request = webapp2.Request.blank('/signup', POST=self.good_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 201)
        self.assertIsNotNone(response.json_body.get('access_token'))
        self.assertIsNotNone(response.json_body.get('refresh_token'))
        self.assertIsNotNone(response.json_body.get('user_id'))
        user_id = response.json_body.get('user_id')

        access_token = response.json_body.get('access_token')

        request = webapp2.Request.blank('/logout', headers={'Authorization': 'Barer %s' % access_token})
        request.method = 'GET'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 401)
        self.assertIsNotNone(response.json_body.get('detail'))

        payload = {
            'user_id': int(user_id),
            'iss': 'auth',
            'exp': datetime.utcnow() + timedelta(REFRESH_JWT_EXP_DELTA_SECONDS)
        }
        access_token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
        request = webapp2.Request.blank('/logout', headers={'Authorization': 'Bearer %s' % access_token})
        request.method = 'GET'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 401)
        self.assertIsNotNone(response.json_body.get('detail'))

        payload = {
            'user_id': int(user_id),
            'iss': 'auth',
            'exp': datetime.utcnow() + timedelta(REFRESH_JWT_EXP_DELTA_SECONDS)
        }
        access_token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
        with patch('jwt.decode') as jwt_decode:
            jwt_decode.side_effect = jwt.ExpiredSignatureError()
            request = webapp2.Request.blank('/logout', headers={'Authorization': 'Bearer %s' % access_token})
            request.method = 'GET'
            response = request.get_response(main.app)

            self.assertEqual(response.status_int, 401)
            self.assertIsNotNone(response.json_body.get('detail'))

        payload = {
            'user_id': int(user_id),
            'iss': 'auth',
            'exp': datetime.utcnow() + timedelta(REFRESH_JWT_EXP_DELTA_SECONDS)
        }
        access_token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
        with patch('jwt.decode') as jwt_decode:
            jwt_decode.side_effect = jwt.InvalidIssuerError()
            request = webapp2.Request.blank('/logout', headers={'Authorization': 'Bearer %s' % access_token})
            request.method = 'GET'
            response = request.get_response(main.app)

            self.assertEqual(response.status_int, 401)
            self.assertIsNotNone(response.json_body.get('detail'))

    def tearDown(self):
        self.testbed.deactivate()


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
        self.refresh = {
            "grant_type": "refresh",
        }
        ndb.get_context().clear_cache()

    def test_refresh_success(self):
        request = webapp2.Request.blank('/signup', POST=self.good_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 201)
        self.assertIsNotNone(response.json_body.get('access_token'))
        self.assertIsNotNone(response.json_body.get('refresh_token'))
        self.assertIsNotNone(response.json_body.get('user_id'))

        user_id = response.json_body.get('user_id')
        access_token = response.json_body.get('access_token')
        refresh_token = response.json_body.get('refresh_token')

        payload = jwt.decode(access_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))
        payload = jwt.decode(refresh_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))

        self.refresh.update({
            'refresh_token': refresh_token
        })

        request = webapp2.Request.blank('/token', POST=self.refresh)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 200)
        self.assertIsNotNone(response.json_body.get('access_token'))
        self.assertIsNotNone(response.json_body.get('refresh_token'))
        self.assertIsNotNone(response.json_body.get('user_id'))

        user_id = response.json_body.get('user_id')
        access_token = response.json_body.get('access_token')
        refresh_token = response.json_body.get('refresh_token')

        payload = jwt.decode(access_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))
        payload = jwt.decode(refresh_token, JWT_SECRET, JWT_ALGORITHM)
        self.assertEqual(user_id, int(payload['user_id']))

    def test_permissions(self):
        request = webapp2.Request.blank('/signup', POST=self.good_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 201)
        self.assertIsNotNone(response.json_body.get('access_token'))
        self.assertIsNotNone(response.json_body.get('refresh_token'))
        self.assertIsNotNone(response.json_body.get('user_id'))

        self.refresh.update({
            'refresh_token': response.json_body.get('refresh_token')
        })

        request = webapp2.Request.blank('/token', POST=self.refresh)
        request.method = 'GET'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 405)

        request.method = 'PUT'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 405)

        request.method = 'DELETE'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 405)

    def test_bad_request(self):
        request = webapp2.Request.blank('/signup', POST=self.good_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 201)
        self.assertIsNotNone(response.json_body.get('access_token'))
        self.assertIsNotNone(response.json_body.get('refresh_token'))
        self.assertIsNotNone(response.json_body.get('user_id'))
        user_id = response.json_body.get('user_id')

        invalid_data = {}
        request = webapp2.Request.blank('/token', POST=invalid_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 400)
        self.assertIsNotNone(response.json_body.get('non_fields_errors'))

        invalid_data = {
            'grant_type': 'refresh'
        }
        request = webapp2.Request.blank('/token', POST=invalid_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 400)
        self.assertIsNotNone(response.json_body.get('refresh_token'))
        #
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
            request = webapp2.Request.blank('/token', POST=invalid_data)
            request.method = 'POST'
            response = request.get_response(main.app)

            self.assertEqual(response.status_int, 400)
            self.assertIsNotNone(response.json_body.get('refresh_token'))

        invalid_data = copy.deepcopy(self.refresh)
        payload = {
            'user_id': int(user_id),
            'iss': 'auth',
            'exp': datetime.utcnow() + timedelta(REFRESH_JWT_EXP_DELTA_SECONDS)
        }
        refresh_token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
        invalid_data['refresh_token'] = refresh_token
        request = webapp2.Request.blank('/token', POST=invalid_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 400)
        self.assertIsNotNone(response.json_body.get('refresh_token'))

        invalid_data = copy.deepcopy(self.refresh)
        payload = {
            'user_id': int(user_id),
            'iss': 'refresh',
            'exp': datetime.utcnow() + timedelta(REFRESH_JWT_EXP_DELTA_SECONDS)
        }
        refresh_token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
        invalid_data['refresh_token'] = refresh_token
        request = webapp2.Request.blank('/token', POST=invalid_data)
        request.method = 'POST'
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 400)
        self.assertIsNotNone(response.json_body.get('refresh_token'))

    def tearDown(self):
        self.testbed.deactivate()

