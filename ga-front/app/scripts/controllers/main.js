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
    function ($scope, profileService, loginAuthServices, usSpinnerService) {
      $scope.loginData = {};
      $scope.loginErrors = '';

      $scope.doLogin = function () {
        usSpinnerService.spin('spinner-1');
        console.log($scope.loginData);
        $scope.loginErrors = '';
        loginAuthServices.getUser({
          email: $scope.loginData.email,
          password: $scope.loginData.password
        }).then(
          function (resp) {
            profileService.storeToken(resp.data.access_token, resp.data.refresh_token);
            profileService.storeUser(resp.data);
            $scope.authFn();
            $scope.loginData = {};
            usSpinnerService.stop('spinner-1');
          }, function (resp) {
            console.log(resp);
            var errors = resp.data.error.errors;
            $scope.loginErrors = errors.map(function (elem) {
              return elem.message;
            }).join(". ");
            usSpinnerService.stop('spinner-1');

          });
      };
    });
