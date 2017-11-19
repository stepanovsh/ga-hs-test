import webapp2

from settings import config

from profile import handlers as profile_handlers


app = webapp2.WSGIApplication([
    webapp2.Route('/signup', profile_handlers.SignupHandler),
    webapp2.Route('/token', profile_handlers.TokenHandler),
    webapp2.Route('/logout', profile_handlers.LogoutHandler),
    webapp2.Route('/profile', profile_handlers.RetrieveUpdateDeleteAuthUserHandler),
], debug=True, config=config)
