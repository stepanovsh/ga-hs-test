import webapp2

from settings import config

from profile import handlers as profile_handlers


app = webapp2.WSGIApplication([
    webapp2.Route('/signup', profile_handlers.SignupHandler),
], debug=True, config=config)
