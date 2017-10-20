/* global angular */
'use strict';

/**
 * Main App Module
 */
var app = angular.module('app', ['utils', 'search', 'infinite-scroll', 'ui.bootstrap'])
    .controller('ALController', function ($scope, $http, $timeout) {
        //Parameters vars
        $scope.user = null;
        $scope.loading = false;
        $scope.loading_extra = false;
        $scope.error_list = null;
        $scope.started = false;
        $scope.filtered = false;
        $scope.filter = "*";

        $scope.total = 0;
        $scope.offset = 0;
        $scope.count = 25;
        $scope.searchText = "";


        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        //Error handling
        $scope.error = '';
        $scope.invalid_query = "";

        $scope.filterData = function (searchText) {
            window.location = "/admin/errors.html?filter=" + searchText;
        };

        //Load params from datastore
        $scope.start = function () {
            if ($scope.filter == "") {
                $scope.filter = "*"
            }
            $scope.filter = decodeURI($scope.filter);
            $scope.offset -= $scope.count;
        };

        $scope.getErrorHash = function (key) {
            var ehash = key.substr(65, key.length);

            if (ehash.indexOf(".e") != -1) {
                ehash = ehash.substr(ehash.indexOf(".e") + 2, ehash.length);
            }

            return ehash;
        };

        $scope.getErrorTypeFromKey = function (key) {
            var ehash = key.substr(65, key.length);

            if (ehash.indexOf(".e") != -1) {
                ehash = ehash.substr(ehash.indexOf(".e") + 2, ehash.length);
            }

            if (ehash == "b54dc2e040a925f84e55e91ff27601ad") {
                return "SERVICE DOWN";
            }
            else if (ehash == "c502020e499f01f230e06a58ad9b5dcc") {
                return "MAX RETRY REACHED";
            }
            else if (ehash == "56d398ad9e9c4de4dd0ea8897073d430") {
                return "MAX DEPTH REACHED";
            }
            else if (ehash == "d0591b2ced7c98928b8c59c168670a86") {
                return "TASK PRE-EMPTED";
            }
            else if (ehash == "ae4dcce1b2fcc4f2ffa14195d1e8e866") {
                return "SERVICE BUSY";
            }
            else if (ehash == "6e34a5b7aa6fbfb6b1ac0d35f2c44d70") {
                return "MAX FILES REACHED";
            }
            return "EXCEPTION";
        };

        $scope.getNextErrorPage = function () {
            $scope.offset += $scope.count;
            $scope.load_data();
        };

        $scope.load_data = function () {
            $scope.loading_extra = true;

            $http({
                method: 'GET',
                url: "/api/v3/error/list/?offset=" + $scope.offset + "&length=" + $scope.count + "&filter=" + $scope.filter
            })
                .success(function (data) {
                    $scope.loading_extra = false;

                    if (!$scope.started) {
                        $scope.error_list = []
                    }
                    Array.prototype.push.apply($scope.error_list, data.api_response.items);
                    $scope.total = data.api_response.total;
                    $scope.started = true;

                    $scope.filtered = $scope.filter != "*";
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (data == "") return;

                    if (status == 400) {
                        $timeout(function () {
                            $("#search-term").addClass("has-error");
                            var ctrl = $("#search-box");
                            ctrl.select();
                            ctrl.focus();
                        }, 0);

                        $scope.invalid_query = data.api_error_message;

                        $scope.error_list = [];
                        $scope.total = 0;
                        $scope.filtered = true;
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

