/* global angular */
'use strict';

/**
 * Main App Module
 */

var app = angular.module('app', ['utils', 'search', 'ngAnimate', 'ui.bootstrap'])
    .controller('ALController', function ($scope, $http, $timeout) {
        //Parameters vars
        $scope.user = null;
        $scope.options = null;
        $scope.loading = false;
        $scope.loading_extra = false;
        $scope.srl = null;
        $scope.tag_map = null;
        $scope.current_file = null;
        $scope.selected_highlight = [];
        $scope.splitter = "__";
        $scope.switch_service = null;

        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        $scope.select_alternate = function (service, created) {
            $scope.loading_extra = true;
            $timeout(function () {
                for (var key in $scope.current_file.alternates[service]) {
                    var item = $scope.current_file.alternates[service][key];
                    if (item.created == created) {
                        for (var i in $scope.current_file.results) {
                            if ($scope.current_file.results[i].response.service_name == service) {
                                if (item._yz_rk !== undefined) {
                                    $http({
                                        method: 'GET',
                                        url: "/api/v3/service/result/" + item._yz_rk + "/"
                                    })
                                        .success(function (data) {
                                            $scope.current_file.results[i] = data.api_response;
                                            $scope.current_file.alternates[service][key] = data.api_response;
                                            $scope.switch_service = service;
                                            $scope.loading_extra = false;
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

                                        });
                                }
                                else {
                                    $scope.current_file.results[i] = item;
                                    $scope.switch_service = service;
                                    $scope.loading_extra = false;
                                }
                                break;
                            }
                        }
                        break;
                    }
                }
            }, 0);

        };

        //Filters
        var tagTypes = [];
        $scope.tagTypeList = function (myTagList) {
            tagTypes = [];
            if (myTagList === undefined || myTagList == null) return [];
            return myTagList;
        };

        $scope.filterTagType = function (tag) {
            var isNewType = tagTypes.indexOf(tag.type) == -1;
            if (isNewType) {
                tagTypes.push(tag.type);
            }
            return isNewType;
        };

        $scope.useless_results = function () {
            return function (item) {
                return !(item.result.score == 0 && item.result.sections.length == 0 && item.result.tags.length == 0 && item.response.extracted.length == 0);

            }
        };

        $scope.good_results = function () {
            return function (item) {
                return item.result.score == 0 && item.result.sections.length == 0 && item.result.tags.length == 0 && item.response.extracted.length == 0;

            }
        };

        $scope.sort_by_name = function (item) {
            return item.response.service_name;
        };

        $scope.obj_len = function (o) {
            if (o === undefined || o == null) return 0;
            return Object.keys(o).length;
        };

        //Action
        $scope.uri_encode = function (val) {
            return encodeURIComponent(val)
        };

        $scope.search_tag = function (tag, value) {
            window.location = "/search.html?query=result.tags.type:" + encodeURIComponent(tag) + " AND result.tags.value:" + encodeURIComponent(value)
        };

        $scope.dump = function (obj) {
            return angular.toJson(obj, true);
        };

        $scope.resubmit_dynamic_async = function (srl, sid) {
            $scope.error = '';
            $scope.success = '';
            $scope.loading_extra = true;

            $http({
                method: 'GET',
                url: "/api/v3/submit/dynamic/" + srl + "/"
            })
                .success(function (data) {
                    $scope.loading_extra = true;
                    $scope.success = 'File successfully resubmitted for dynamic analysis. You will be redirected...';
                    $timeout(function () {
                        $scope.success = "";
                        window.location = "/submission_detail.html?sid=" + data.api_response.submission.sid;
                    }, 2000);
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

                });
        };

        //Highlighter
        $scope.trigger_highlight = function (tag, value) {
            var key = tag + $scope.splitter + value;
            var idx = $scope.selected_highlight.indexOf(key);
            if (idx == -1) {
                $scope.selected_highlight.push(key);
            }
            else {
                $scope.selected_highlight.splice(idx, 1);
            }
        };

        $scope.remove_highlight = function (key) {
            var values = key.split($scope.splitter, 2);
            $scope.trigger_highlight(values[0], values[1])
        };

        $scope.isHighlighted = function (tag, value) {
            return $scope.selected_highlight.indexOf(tag + $scope.splitter + value) != -1
        };

        $scope.hasContext = function (tag) {
            return tag.context != null;
        };

        $scope.hasHighlightedTags = function (tags) {
            for (var i in tags) {
                var tag = tags[i];
                if ($scope.isHighlighted(tag.type, tag.value)) {
                    return true;
                }
            }
            return false;
        };

        $scope.clear_selection = function () {
            $scope.selected_highlight = [];
        };

        //Error handling
        $scope.error = '';

        //Load params from datastore
        $scope.start = function () {
            $scope.loading_extra = true;
            $http({
                method: 'GET',
                url: "/api/v3/file/result/" + $scope.srl + "/"
            })
                .success(function (data) {
                    $scope.current_file = data.api_response;
                    for (var key in $scope.current_file.results) {
                        var item = $scope.current_file.results[key];
                        if (item.response.service_name in $scope.current_file.alternates) {
                            $scope.current_file.alternates[item.response.service_name].unshift(item);
                        }
                        else {
                            $scope.current_file.alternates[item.response.service_name] = [item];
                        }
                    }
                    $scope.loading_extra = false;
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

                });
        };

    });

