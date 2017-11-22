'use strict';

/**
 * @ngdoc function
 * @name gaHsTestApp.controller:ProfileCtrl
 * @description
 * # ProfileCtrl
 * Controller of the gaHsTestApp
 */
angular.module('gaHsTestApp.ProfileCtrl', [])
  .controller('ProfileCtrl', function ($scope, profileService, loginAuthServices) {
    $scope.profileData = $scope.authUser;
    $scope.profileErrors = '';
    $scope.doUpdate = function () {
      console.log($scope.loginData);
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
          $scope.authUser = $scope.profileData
          $scope.authFn();
          $scope.profileErrors = 'Your profile has been updated'
        }, function (resp) {
          console.log(resp);
          var errors = resp.data.error.errors;
          $scope.loginErrors = errors.map(function (elem) {
            return elem.message;
          }).join(". ");
          if (resp.status === 401) {
            $scope.updateRefreshToken()
          }
        });
    };
    $scope.doDelete = function () {
      if ($scope.authUser) {
        loginAuthServices.deleteUser().then(
          function (resp) {
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
