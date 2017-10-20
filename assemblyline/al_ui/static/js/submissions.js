/* global angular */
'use strict';

/**
 * Main App Module
 */
var app = angular.module('app', ['search', 'utils', 'ui.bootstrap'])
    .controller('ALController', function ($scope, $http) {
        //Parameters vars
        $scope.user = null;
        $scope.loading = false;
        $scope.loading_extra = false;
        $scope.submission_list = null;
        $scope.group = null;
        $scope.uname = null;
        $scope.started = false;
        $scope.filtered = false;
        $scope.filter = "*";

        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        //Error handling
        $scope.error = '';

        //pager dependencies
        $scope.total = 0;
        $scope.offset = 0;
        $scope.count = 25;
        $scope.cur_page = 1;
        $scope.searchText = "";
        $scope.$watch('searchText', function () {
            if ($scope.started && $scope.searchText !== undefined && $scope.searchText != null) {
                if ($scope.searchText == "" || $scope.searchText == null || $scope.searchText === undefined) {
                    $scope.filter = "*";
                }
                else {
                    $scope.filter = $scope.searchText;
                }

                $scope.started = false;
                if ($scope.first !== undefined) $scope.first();
                $scope.offset = 0;
                $scope.load_data();
            }
        });


        //Load params from datastore
        $scope.start = function () {
            $scope.load_data();
        };

        $scope.load_data = function () {
            $scope.loading_extra = true;

            if ($scope.group) {
                $http({
                    method: 'GET',
                    url: "/api/v3/submission/list/group/" + $scope.group + "/?offset=" + $scope.offset + "&length=" + $scope.count + "&filter=" + $scope.filter
                })
                    .success(function (data) {
                        $scope.loading_extra = false;

                        $scope.submission_list = data.api_response.items;
                        $scope.total = data.api_response.total;
                        $scope.pages = $scope.pagerArray();
                        $scope.started = true;

                        $scope.filtered = $scope.filter != "*";
                    })
                    .error(function (data, status, headers, config) {
                        $scope.loading_extra = false;

                        if (data == "" || status == 400) {
                            $scope.submission_list = [];
                            $scope.total = 0;
                            $scope.filtered = true;
                            $scope.pages = $scope.pagerArray();
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
            }
            else {
                $http({
                    method: 'GET',
                    url: "/api/v3/submission/list/user/" + $scope.uname + "/?offset=" + $scope.offset + "&length=" + $scope.count + "&filter=" + $scope.filter
                })
                    .success(function (data) {
                        $scope.loading_extra = false;

                        $scope.submission_list = data.api_response.items;
                        $scope.total = data.api_response.total;
                        $scope.pages = $scope.pagerArray();
                        $scope.started = true;

                        $scope.filtered = $scope.filter != "*";
                    })
                    .error(function (data, status, headers, config) {
                        $scope.loading_extra = false;

                        if (data == "" || status == 400) {
                            $scope.submission_list = [];
                            $scope.total = 0;
                            $scope.filtered = true;
                            $scope.pages = $scope.pagerArray();
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
            }
        };
    });

