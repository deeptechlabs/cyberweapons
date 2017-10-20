/* global angular */
'use strict';

/**
 * Main App Module
 */
var app = angular.module('app', ['search', 'utils', 'ui.bootstrap'])
    .controller('ALController', function ($scope, $http) {
        //Parameters vars
        $scope.map = null;
        $scope.user = null;
        $scope.loading = false;

        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        //Error handling
        $scope.error = '';

        //Params handling

        //Load params from datastore
        $scope.start = function () {
            $scope.loading = true;
            $http({
                method: 'GET',
                url: "/api/site_map/"
            })
                .success(function (data) {
                    $scope.loading = false;
                    $scope.map = data.api_response;
                })
                .error(function (data, status, headers, config) {
                    if (data == "") {
                        return;
                    }

                    $scope.loading = false;
                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                    scroll(0, 0);
                });
        };
    });

