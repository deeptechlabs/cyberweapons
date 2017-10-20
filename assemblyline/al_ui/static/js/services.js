/* global angular */
'use strict';

/**
 * Main App Module
 */
var app = angular.module('app', ['search', 'utils', 'ui.bootstrap'])
    .controller('ALController', function ($scope, $http) {
        //Parameters vars
        $scope.service_list = null;
        $scope.user = null;
        $scope.loading = false;
        $scope.loading_extra = false;

        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        //Error handling
        $scope.error = '';
        $scope.success = '';

        $scope.typeOf = function (val) {
            return typeof val;
        };

        //Load params from datastore
        $scope.start = function () {
            $scope.load_data();
        };

        //Pager methods
        $scope.load_data = function () {
            $scope.loading_extra = true;

            $http({
                method: 'GET',
                url: "/api/v3/service/list/"
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.service_list = data.api_response;
                    $scope.started = true;
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (data == "" || status == 400) {
                        $scope.service_list = [];
                        $scope.started = true;
                        return;
                    }

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                    $scope.started = true;

                });
        };
    });
