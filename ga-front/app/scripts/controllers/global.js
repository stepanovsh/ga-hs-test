'use strict';

/**
 * @ngdoc function
 * @name gaHsTestApp.controller:GlobalCtrl
 * @description
 * # GlobalCtrl
 * Controller of the gaHsTestApp
 */
angular.module('gaHsTestApp.GlobalCtrl', [])
  .controller('GlobalCtrl', function ($scope, profileService, loginAuthServices, $rootScope, $location, $http, $timeout, usSpinnerService) {
    $scope.authUser = null;
    $scope.ifAuth = function () {
      if ($scope.authUser && $rootScope.userCookieId) {
        return $scope.authUser
      } else if ($scope.userCookieId) {
        $scope.updateUser();
        return true;
      } else {
        return null;
      }
    };

    $scope.updateRefreshToken = function () {
      var refreshToken = profileService.getRefresh();
      loginAuthServices.refreshToken({
        refresh_token: refreshToken
      }).then(function (resp) {
        profileService.storeToken(resp.data.access_token, resp.data.refresh_token);
        profileService.storeUser(resp.data);
        $scope.authFn();
      }, function (resp) {
        profileService.logOut();
        $scope.authFn();
      });
    };

    $scope.updateUser = function () {
      usSpinnerService.stop('spinner-1');
      $scope.userCookieId = profileService.getUserId();
      if ($scope.userCookieId) {
        loginAuthServices.getUserInfo()
          .then(function (resp) {
            $scope.authUser.email = resp.data.email;
            $scope.authUser.first_name = resp.data.first_name;
            $scope.authUser.last_name = resp.data.last_name;
            profileService.storeUser($scope.authUser);
            usSpinnerService.stop('spinner-1');
          }, function (resp) {
            if (resp.status === 401) {
              $scope.updateRefreshToken()
            }
            usSpinnerService.stop('spinner-1');
          });
      } else {
        $scope.authFn();
      }
    };

    $scope.authFn = function () {
      var issetCookie = profileService.getToken();
      var issetId = profileService.getUserId();

      $scope.userCookieId = profileService.getUserId();

      if (issetCookie && issetId) {
        $http.defaults.headers.common['Authorization'] = "Bearer " + issetCookie;
        $scope.authUser = profileService.getUser();
      } else {
        $scope.whatHeader = false;
        $scope.authUser = null;
      }
      if ($scope.ifAuth()) {
        $location.path('/profile')
      } else {
        $location.path('/main')
      }
    };
    $scope.authFn();
    if ($scope.authUser) {
      $scope.updateUser()
    }

    $scope.logOut = function () {
      if ($scope.authUser) {
        loginAuthServices.logOut().then(function(resp) {
          profileService.logOut();
          $scope.authFn();
          $scope.authUser = null;
        }, function (resp) {
          if (resp.status === 401) {
            $scope.updateRefreshToken()
          }
        })
      }
    }
  });
