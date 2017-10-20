/* global angular */
'use strict';

/**
 * Main App Module
 */

function SearchBaseCtrl($scope, $http, $timeout) {
    //Parameters vars
    $scope.user = null;
    $scope.loading = false;
    $scope.loading_extra = false;
    $scope.file_list = null;
    $scope.submission_list = null;
    $scope.signature_list = null;
    $scope.result_list = null;
    $scope.alert_list = null;
    $scope.query = null;
    $scope.new_query = null;
    $scope.invalid_query = null;
    $scope.export_btn = false;

    //DEBUG MODE
    $scope.debug = false;
    $scope.showParams = function () {
        console.log("Scope", $scope)
    };

    $scope.dump = function (obj) {
        return angular.toJson(obj, true);
    };

    $scope.getKeys = function (o) {
        try {
            return Object.keys(o);
        } catch (ex) {
            return [];
        }
    };

    //Error handling
    $scope.error = '';

    $scope.show_export_btn = function (show) {
        $scope.export_btn = show;
    };

    //pager dependencies
    $scope.started = false;
    $scope.cur_list = $scope.submission_list;
    $scope.total = null;
    $scope.offset = 0;
    $scope.count = 25;
    $scope.disable_pager_filter = true;
    $scope.searchText = "";

    //Load params from datastore
    $scope.start = function () {
        if ($scope.query == null || $scope.query == "") {
            return;
        }
        else{
            $scope.query = decodeURI($scope.query);
        }

        $scope.new_query = $scope.query;

        $timeout(function () {
            $scope.loading_extra = true;
            var data = {};
            data['query'] = $scope.query;
            data['offset'] = $scope.offset;
            data['length'] = $scope.count;

            $http({
                method: 'POST',
                url: "/api/v3/search/all/",
                data: data
            })
                .success(function (data) {
                    $scope.loading_extra = false;

                    $scope.file_list = data.api_response.files;
                    $scope.submission_list = data.api_response.submissions;
                    $scope.result_list = data.api_response.results;
                    $scope.signature_list = data.api_response.signatures;
                    $scope.alert_list = data.api_response.alerts;

                    if ($scope.submission_list.total == 0) {
                        if ($scope.file_list.total != 0) {
                            $('#submission_tab').removeClass("active");
                            $('#submission').removeClass("active");
                            $('#signature_tab').removeClass("active");
                            $('#signature').removeClass("active");
                            $('#alert_tab').removeClass("active");
                            $('#alert').removeClass("active");
                            $('#file_tab').addClass("active");
                            $('#file').addClass("active");
                            $scope.cur_list = $scope.file_list;
                            $scope.total = data.api_response.files.total;
                            $scope.export_btn = false;
                        }
                        else if ($scope.result_list.total != 0) {
                            $('#submission_tab').removeClass("active");
                            $('#submission').removeClass("active");
                            $('#signature_tab').removeClass("active");
                            $('#signature').removeClass("active");
                            $('#alert_tab').removeClass("active");
                            $('#alert').removeClass("active");
                            $('#result_tab').addClass("active");
                            $('#result').addClass("active");
                            $scope.cur_list = $scope.result_list;
                            $scope.total = data.api_response.results.total;
                            $scope.export_btn = false;
                        }
                        else if ($scope.signature_list.total != 0) {
                            $('#submission_tab').removeClass("active");
                            $('#submission').removeClass("active");
                            $('#signature_tab').addClass("active");
                            $('#signature').addClass("active");
                            $('#alert_tab').removeClass("active");
                            $('#alert').removeClass("active");
                            $('#result_tab').removeClass("active");
                            $('#result').removeClass("active");
                            $scope.cur_list = $scope.signature_list;
                            $scope.total = data.api_response.signatures.total;
                            $scope.export_btn = $scope.total > 0;
                        }
                        else if ($scope.alert_list != null && $scope.alert_list.total != 0) {
                            $('#submission_tab').removeClass("active");
                            $('#submission').removeClass("active");
                            $('#signature_tab').removeClass("active");
                            $('#signature').removeClass("active");
                            $('#alert_tab').addClass("active");
                            $('#alert').addClass("active");
                            $('#result_tab').removeClass("active");
                            $('#result').removeClass("active");
                            $scope.cur_list = $scope.alert_list;
                            $scope.total = data.api_response.alerts.total;
                            $scope.export_btn = false;
                        }
                        else {
                            $scope.total = data.api_response.submissions.total;
                            $scope.cur_list = $scope.submission_list;
                            $scope.export_btn = false;
                        }
                    }
                    else {
                        $scope.total = data.api_response.submissions.total;
                        $scope.cur_list = $scope.submission_list;
                        $scope.export_btn = false;
                    }
                    $scope.pages = $scope.pagerArray();

                    $scope.started = true;
                })
                .error(function (data, status, headers, config) {
                    if (data == "") {
                        return;
                    }

                    $scope.loading_extra = false;

                    if (status == 400) {
                        $timeout(function () {
                            $("#search-term").addClass("has-error");
                            var sb = $("#search-box");
                            sb.select();
                            sb.focus();
                        }, 0);

                        $scope.invalid_query = data.api_error_message;
                    }
                    else {
                        if (data.api_error_message) {
                            $scope.error = data.api_error_message;
                        }
                        else {
                            $scope.error = config.url + " (" + status + ")";
                        }
                    }
                    $scope.started = true;
                });
        }, 100);
    };

    $scope.load_data = function () {
        if ($scope.query == null || $scope.query == "") {
            return;
        }

        $scope.loading_extra = true;
        var data = {};
        data['query'] = $scope.query;
        data['offset'] = $scope.offset;
        data['length'] = $scope.count;

        $http({
            method: 'POST',
            url: "/api/v3/search/" + $scope.cur_list.bucket + "/",
            data: data
        })
            .success(function (data) {
                $scope.loading_extra = false;

                if ($scope.cur_list.bucket == "file") {
                    $scope.file_list = data.api_response;
                }
                else if ($scope.cur_list.bucket == "submission") {
                    $scope.submission_list = data.api_response;
                }
                else if ($scope.cur_list.bucket == "result") {
                    $scope.result_list = data.api_response;
                }
                else if ($scope.cur_list.bucket == "signature") {
                    $scope.signature_list = data.api_response;
                }
                else if ($scope.cur_list.bucket == "alert") {
                    $scope.alert_list = data.api_response;
                }

                $scope.total = data.api_response.total;
                $scope.pages = $scope.pagerArray();
                $scope.started = true;
            })
            .error(function (data, status, headers, config) {
                if (data == "") {
                    return;
                }

                $scope.loading_extra = false;

                if (data.api_error_message) {
                    $scope.error = data.api_error_message;
                }
                else {
                    $scope.error = config.url + " (" + status + ")";
                }
                $scope.started = true;
            });
    };
}

var app = angular.module('app', ['utils', 'search', 'ngAnimate', 'ui.bootstrap']);
app.controller('ALController', SearchBaseCtrl);
