'use strict';

/**
 * @ngdoc function
 * @name gaHsTestApp.controller:MainCtrl
 * @description
 * # MainCtrl
 * Controller of the gaHsTestApp
 */
angular.module('gaHsTestApp.MainCtrl', [])
  .controller('MainCtrl',
    function ($scope, profileService, loginAuthServices) {
      $scope.loginData = {};
      $scope.loginErrors = '';

      $scope.doLogin = function () {
        console.log($scope.loginData);
        loginAuthServices.getUser({
          email: $scope.loginData.email,
          password: $scope.loginData.password
        }).then(
          function (resp) {
            profileService.storeToken(resp.data.access_token, resp.data.refresh_token);
            profileService.storeUser(resp.data);
            $scope.authFn();
            $scope.loginData = {};
          }, function (resp) {
            console.log(resp);
            var errors = resp.data.error.errors;
            $scope.loginErrors = errors.map(function (elem) {
              return elem.message;
            }).join(". ");

          });
      };
    });
