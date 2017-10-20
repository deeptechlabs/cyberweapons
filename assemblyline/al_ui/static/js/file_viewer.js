/* global angular */
'use strict';

/**
 * Main App Module
 */

var app = angular.module('app', ['utils', 'search', 'ngAnimate', 'ui.bootstrap'])
    .controller('ALController', function ($scope, $http) {
        //Parameters vars
        $scope.user = null;
        $scope.loading = false;
        $scope.loading_extra = false;
        $scope.srl = null;
        $scope.binary = null;
        $scope.on_server = true;

        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        //Error handling
        $scope.error = '';

        //Load params from datastore
        $scope.start = function () {
            $http({
                method: 'GET',
                url: "/api/v3/file/hex/" + $scope.srl + "/"
            })
                .success(function (data) {
                    $scope.hex = data.api_response;
                })
                .error(function (data, status, headers, config) {
                    if (data == "") {
                        return;
                    }
                    else if (status == 404) {
                        $scope.on_server = false;
                        return
                    }

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }

                });
            $http({
                method: 'GET',
                url: "/api/v3/file/strings/" + $scope.srl + "/"
            })
                .success(function (data) {
                    $scope.string = data.api_response;
                })
                .error(function (data, status, headers, config) {
                    if (data == "") {
                        return;
                    }
                    else if (status == 404) {
                        $scope.on_server = false;
                        return
                    }

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }

                });
            $http({
                method: 'GET',
                url: "/api/v3/file/raw/" + $scope.srl + "/"
            })
                .success(function (data) {
                    $scope.raw = data.api_response;
                })
                .error(function (data, status, headers, config) {
                    if (data == "") {
                        return;
                    }
                    else if (status == 404) {
                        $scope.on_server = false;
                        return
                    }

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }

                });
        };

    });

