'use strict';

/**
 * @ngdoc function
 * @name gaHsTestApp.controller:SignupCtrl
 * @description
 * # SignupCtrl
 * Controller of the gaHsTestApp
 */
angular.module('gaHsTestApp.SignupCtrl', [])
  .controller('SignupCtrl', function ($scope, profileService, loginAuthServices, usSpinnerService) {
    $scope.signupData = {};
    $scope.signupErrors = '';

    $scope.doSignUp = function () {
      usSpinnerService.spin('spinner-1');
      console.log($scope.signupData);
      $scope.signupErrors = '';
      loginAuthServices.signUp({
        email: $scope.signupData.email,
        first_name: $scope.signupData.first_name,
        last_name: $scope.signupData.last_name,
        password: $scope.signupData.password,
        repeat_password: $scope.signupData.repeat_password
      }).then(
        function (resp) {
          profileService.storeToken(resp.data.access_token, resp.data.refresh_token);
          profileService.storeUser(resp.data);
          $scope.authFn();
          $scope.signupData = {};
          usSpinnerService.stop('spinner-1');
        }, function (resp) {
          console.log(resp);
          var errors = resp.data.error.errors;
          $scope.signupErrors = errors.map(function (elem) {
            return elem.message;
          }).join(". ");
          usSpinnerService.stop('spinner-1');
        });
    };
  });
