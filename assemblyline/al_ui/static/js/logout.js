/* global angular */
'use strict';

/**
 * Main App Module
 */

function LoginBaseCtrl($scope, $http, $timeout) {
    $scope.error = "";

    //Login via API
    $scope.start = function () {
        $scope.error = '';

        $timeout(function (){
            $http({
                method: 'GET',
                url: "/api/v3/auth/logout/"
            })
                .success(function () {
                    window.location = "/";
                })
                .error(function (data) {
                    $scope.error = data.api_error_message;
                });
        }, 1000);
    };
}

var app = angular.module('app', []);
app.controller('ALController', LoginBaseCtrl);
