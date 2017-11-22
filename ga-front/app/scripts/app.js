'use strict';

/**
 * @ngdoc overview
 * @name gaHsTestApp
 * @description
 * # gaHsTestApp
 *
 * Main module of the application.
 */
angular
  .module('gaHsTestApp', [
    'ngAnimate',
    'ngAria',
    'ngCookies',
    'ngMessages',
    'ngResource',
    'ngRoute',
    'ngSanitize',
    'ngTouch',
    'angularSpinner',
    'gaHsTestApp.profileService',
    'gaHsTestApp.GlobalCtrl',
    'gaHsTestApp.MainCtrl',
    'gaHsTestApp.ProfileCtrl',
    'gaHsTestApp.SignupCtrl'
  ])
  .value('HOST', 'http://ga-hs-test.appspot.com/_ah/api/')
  .value('API_VERSION', 'v1')
  .value('API_KEY', 'AIzaSyClZMgZshvn1VuNSBnKqSEwS9bJ2IC7quI')
  .config(function ($routeProvider) {
    $routeProvider
      .when('/', {
        templateUrl: 'views/main.html',
        controller: 'MainCtrl',
        controllerAs: 'main'
      })
      .when('/profile', {
        templateUrl: 'views/profile.html',
        controller: 'ProfileCtrl',
        controllerAs: 'profile'
      })
      .when('/signup', {
        templateUrl: 'views/signup.html',
        controller: 'SignupCtrl',
        controllerAs: 'signup'
      })
      .otherwise({
        redirectTo: '/'
      });
  });
