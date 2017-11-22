'use strict';

/**
 * @ngdoc function
 * @name gaHsTestApp.controller:ProfileCtrl
 * @description
 * # ProfileCtrl
 * Controller of the gaHsTestApp
 */
angular.module('gaHsTestApp.ProfileCtrl', [])
  .controller('ProfileCtrl', function ($scope, profileService, loginAuthServices, usSpinnerService) {
    $scope.profileData = $scope.authUser;
    $scope.profileErrors = '';
    $scope.doUpdate = function () {
      console.log($scope.loginData);
      $scope.profileErrors = '';
      usSpinnerService.spin('spinner-1');
      loginAuthServices.putUser({
        email: $scope.profileData.email,
        first_name: $scope.profileData.first_name,
        last_name: $scope.profileData.last_name
      }).then(
        function (resp) {
          $scope.profileData.email = resp.data.email;
          $scope.profileData.first_name = resp.data.first_name;
          $scope.profileData.last_name = resp.data.last_name;
          profileService.storeUser($scope.profileData);
          $scope.authUser = $scope.profileData;
          $scope.profileErrors = 'Your profile has been updated'
          usSpinnerService.stop('spinner-1');
        }, function (resp) {
          console.log(resp);
          var errors = resp.data.error.errors;
          $scope.profileErrors = errors.map(function (elem) {
            return elem.message;
          }).join(". ");
          if (resp.status === 401) {
            $scope.updateRefreshToken()
          }
          usSpinnerService.stop('spinner-1');
        });
    };
    $scope.doDelete = function () {
      if ($scope.authUser) {
        usSpinnerService.spin('spinner-1');
        loginAuthServices.deleteUser().then(
          function (resp) {
            profileService.logOut();
            $scope.authFn();
            $scope.authUser = null;
            usSpinnerService.stop('spinner-1');
          }, function (resp) {
            if (resp.status === 401) {
              $scope.updateRefreshToken()
            }
            usSpinnerService.stop('spinner-1');
          })
      }
    }
  });
