/* global angular */
'use strict';

/**
 * Main App Module
 */

var app = angular.module('app', ['search', 'utils', 'ui.bootstrap'])
    .controller('ALController', function ($scope, $http) {
        //Parameters vars
        $scope.error = '';
        $scope.selected_api = null;
        $scope.api_versions = null;
        $scope.api_functions = null;
        $scope.api_groups = [];
        $scope.loading = false;

        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        //API list custom filter
        $scope.APIMatching = function (group) {
            var out = [];
            for (var x in $scope.api_functions) {
                var item = $scope.api_functions[x];
                if (group == "documentation") {
                    if (item.path == "/api/" + $scope.selected_api + "/") {
                        out.push(item);
                    }
                }
                else if (item.path.indexOf("/api/" + $scope.selected_api + "/" + group + "/") == 0) {
                    out.push(item);
                }
            }
            return out;
        };

        //Monitor selected_api change
        $scope.$watch('selected_api', function () {
            $scope.loading = true;
            $scope.api_functions = null;
            $scope.error = '';
            if ($scope.selected_api != null) {
                $http({
                    method: 'GET',
                    url: "/api/" + $scope.selected_api + "/"
                })
                    .success(function (data) {
                        $scope.api_functions = data.api_response.apis;
                        $scope.api_groups = data.api_response.blueprints;

                        $scope.loading = false;
                    })
                    .error(function (data, status, headers, config) {
                        if (data == "") {
                            return;
                        }

                        if (data.api_error_message) {
                            $scope.error = data.api_error_message;
                        }
                        else {
                            $scope.error = config.url + " (" + status + ")";
                        }
                        $scope.loading = false;
                    });
            }
        }, true);

        //Get API Version list
        $scope.start = function () {
            $scope.loading = true;
            $http({
                method: 'GET',
                url: "/api/"
            })
                .success(function (data) {
                    $scope.api_versions = data.api_response;
                    $scope.selected_api = data.api_response[0];
                    $scope.loading = false;
                })
                .error(function (data, status, headers, config) {
                    if (data == "") {
                        return;
                    }

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                    $scope.loading = false;
                });
        };
    });