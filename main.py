import webapp2

import os
import endpoints
from google.appengine.ext.webapp import template
from profile.apis import UserApi
from settings import config


class MainHandler(webapp2.RequestHandler):
    def get(self):

        path = os.path.join(os.path.dirname(__file__), 'ga-front', 'dist', 'index.html')
        self.response.out.write(template.render(path, {}))


app = webapp2.WSGIApplication([
    webapp2.Route('/', MainHandler),
], debug=True, config=config)

api = endpoints.api_server([UserApi])
