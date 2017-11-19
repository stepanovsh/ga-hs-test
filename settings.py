from __future__ import unicode_literals

import os

config = {
    'webapp2_extras.auth': {
        'user_model': 'profile.models.User',
        'user_attributes': ['first_name', 'last_name', 'email']
    },
    'webapp2_extras.sessions': {
        'secret_key': os.environ.setdefault('APP_SECRET_KEY', 'YOUR_SECRET_KEY')
    }
}


JWT_SECRET = os.environ.setdefault('JWT_SECRET', 'secret')
JWT_ALGORITHM = os.environ.setdefault('JWT_ALGORITHM', 'HS256')
JWT_EXP_DELTA_SECONDS = int(os.environ.setdefault('JWT_EXP_DELTA_SECONDS', '600'))  # default 5 minutes
REFRESH_JWT_EXP_DELTA_SECONDS = int(os.environ.setdefault(
    'REFRESH_JWT_EXP_DELTA_SECONDS', str(60 * 60 * 24 * 10)))  # default 10 days
