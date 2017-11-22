'use strict';

/**
 * @ngdoc service
 * @name gaHsTestApp.profileService
 * @description
 * # profileService
 * Service in the gaHsTestApp.
 */
angular.module('gaHsTestApp.profileService', [])
  .service('profileService', function (loginAuthServices, $http, $filter, $window) {
    // AngularJS will instantiate a singleton by calling "new" on this function
    var self = this;
    this.user = JSON.parse($window.localStorage['user'] || '{}');
    this.userToken = JSON.parse($window.localStorage['token'] || null);
    this.refreshToken = JSON.parse($window.localStorage['refresh'] || null);
    this.userId = null;
    this.logOut = function () {
      this.removeUser();
      this.removeToken();
      this.removeRefresh();
      $http.defaults.headers.common['Authorization'] = "";
      this.user = {};
      this.userToken = null;
      this.userId = null;
    };
    this.getUserId = function () {
      if (!this.userId) {
        var user = this.getUser();
        this.userId = user['id'];
      }
      return this.userId;
    };

    this.isAuthenticated = function () {
      var issetCookie = this.getToken();
      var issetId = parseInt(this.getUserId());
      return !!(issetCookie.length && issetId);
    };
    this.getUser = function () {
      if (!Object.getOwnPropertyNames(this.user).length) {
        this.user = JSON.parse(window.localStorage['user'] || '{}')
      }
      return this.user
    };

    this.storeUser = function (user) {
      if (user) {
        $window.localStorage['user'] = JSON.stringify(user);
        this.user = user;
      }
    };

    this.removeUser = function () {
      $window.localStorage.removeItem('user');
    };

    this.storeToken = function (token, refresh) {
      if (token) {
        $window.localStorage['token'] = JSON.stringify(token)
      }
      if (refresh) {
        $window.localStorage['refresh'] = JSON.stringify(refresh)
      }
    };

    this.removeToken = function () {
      $window.localStorage.removeItem('token');
    };
    this.removeRefresh = function () {
      $window.localStorage.removeItem('refresh');
    };

    this.getToken = function () {
      if (!this.userToken) {
        this.userToken = JSON.parse($window.localStorage['token'] || null);
      }
      return this.userToken
    };
    this.getRefresh = function () {
      if (!this.refreshToken) {
        this.refreshToken = JSON.parse($window.localStorage['refresh'] || null);
      }
      return this.refreshToken
    }
  }).factory('loginAuthServices', function ($http, HOST, API_VERSION, API_KEY) {
        var host = HOST;
        host = HOST + 'user/' + API_VERSION;

        return {
            getUser: function (user) {
                return $http.post(host + '/signin/?api_key=' + API_KEY, user);
            },
            getUserInfo: function () {
                return $http.get(host + '/profile/?api_key=' + API_KEY);
            },
            putUser: function (user) {
                return $http.put(host + '/profile/?api_key=' + API_KEY, user);
            },
            deleteUser: function (user) {
                return $http.delete(host + '/profile/?api_key=' + API_KEY);
            },
            signUp: function (user) {
                return $http.post(host + '/signup/?api_key=' + API_KEY, user)
            },
            refreshToken: function (data) {
                return $http.post(host + '/refresh/?api_key=' + API_KEY, data)
            },
            logOut: function () {
                return $http.get(host + '/logout/?api_key=' + API_KEY)
            }
        }
    });
