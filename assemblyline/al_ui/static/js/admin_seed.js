/* global angular */
'use strict';

/**
 * Main App Module
 */
var app = angular.module('app', ['utils', 'search', 'ngAnimate', 'ui.bootstrap'])
    .controller('ALController', function ($scope, $http, $timeout) {
        //Parameters vars
        $scope.user = null;
        $scope.loading = false;
        $scope.loading_extra = false;
        $scope.seed = null;
        $scope.options = {mode: 'form'};
        $scope.editor = new JSONEditor(document.getElementById("jsoneditor"), $scope.options);
        $scope.modified = false;

        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        $scope.switch_mode = function (mode) {
            if (mode === undefined || mode == null) {
                $scope.options.mode = $scope.options.mode == "code" ? "form" : "code"
            }
            else {
                if (mode == $scope.options.mode) return;
                $scope.options.mode = mode;
            }
            $scope.editor.setMode($scope.options.mode)
        };

        $scope.save_seed = function () {
            $scope.diff_only = false;
            var delta = jsondiffpatch.diff($scope.seed, $scope.editor.get());
            document.getElementById('vdiff').innerHTML = jsondiffpatch.formatters.html.format(delta, $scope.seed);
            jsondiffpatch.formatters.html.hideUnchanged();
            $("#myModal").modal('show');
        };

        $scope.diff_source = function () {
            $scope.loading_extra = true;
            $http({
                method: 'GET',
                url: "/api/v3/seed/source/"
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.diff_only = true;
                    $scope.modal_title = "Differences comparing the current seed with the original seed";
                    var delta = jsondiffpatch.diff(data.api_response, $scope.seed);
                    document.getElementById('vdiff').innerHTML = jsondiffpatch.formatters.html.format(delta, data.api_response);
                    jsondiffpatch.formatters.html.hideUnchanged();
                    $("#myModal").modal('show');
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

        $scope.diff_original = function () {
            $scope.loading_extra = true;
            $http({
                method: 'GET',
                url: "/api/v3/seed/default/"
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.diff_only = true;
                    $scope.modal_title = "Differences comparing the current seed with the original seed";
                    var delta = jsondiffpatch.diff(data.api_response, $scope.seed);
                    document.getElementById('vdiff').innerHTML = jsondiffpatch.formatters.html.format(delta, data.api_response);
                    jsondiffpatch.formatters.html.hideUnchanged();
                    $("#myModal").modal('show');
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

        $scope.diff_previous = function () {
            $scope.loading_extra = true;
            $http({
                method: 'GET',
                url: "/api/v3/seed/previous/"
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.diff_only = true;
                    $scope.modal_title = "Differences comparing the current seed with the previous seed";
                    var delta = jsondiffpatch.diff(data.api_response, $scope.seed);
                    document.getElementById('vdiff').innerHTML = jsondiffpatch.formatters.html.format(delta, data.api_response);
                    jsondiffpatch.formatters.html.hideUnchanged();
                    $("#myModal").modal('show');
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

        $scope.apply_save_seed = function () {
            $scope.seed = $scope.editor.get();
            $("#myModal").modal('hide');
            $http({
                method: 'PUT',
                url: "/api/v3/seed/",
                data: $scope.seed
            })
                .success(function () {
                    $scope.loading_extra = false;
                    $scope.success = "New seed was successfully applied to the system.";
                    $timeout(function () {
                        $scope.success = "";
                    }, 1500);
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

        $scope.monitor_changes = function () {
            try {
                $scope.modified = JSON.stringify($scope.editor.get()) !== JSON.stringify($scope.seed);
            }
            catch (exception) {/*Pass*/
            }

            $timeout(function () {
                $scope.monitor_changes();
            }, 500);
        };

        $scope.start = function () {
            $scope.loading_extra = true;
            $http({
                method: 'GET',
                url: "/api/v3/seed/"
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.seed = data.api_response;
                    if ($scope.seed == null) {
                        $scope.seed = {};
                    }
                    $scope.editor.set($scope.seed);
                    $scope.monitor_changes();
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
        //Error handling
        $scope.error = '';
        $scope.success = '';
    });
