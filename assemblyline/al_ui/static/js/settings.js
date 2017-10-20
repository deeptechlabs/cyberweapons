/* global angular */
'use strict';

/**
 * Main App Module
 */

function SettingsBaseCtrl($scope, $http, $timeout) {
    //Parameters vars
    $scope.params = null;
    $scope.params_bck = null;
    $scope.user = null;
    $scope.loading = false;

    //DEBUG MODE
    $scope.debug = false;
    $scope.showParams = function () {
        console.log("Scope", $scope)
    };

    //Error handling
    $scope.error = '';
    $scope.success = '';

    //Params handling

    $scope.serviceSelectionReset = function ($event) {
        $event.stopImmediatePropagation();
        for (var i = 0; i < $scope.params.services.length; i++) {
            $scope.params.services[i].selected = $scope.params_bck.services[i].selected;
            for (var x = 0; x < $scope.params.services[i].services.length; x++) {
                $scope.params.services[i].services[x].selected = $scope.params_bck.services[i].services[x].selected;
            }
        }
    };

    $scope.serviceSelectionNone = function ($event) {
        $event.stopImmediatePropagation();
        for (var i = 0; i < $scope.params.services.length; i++) {
            $scope.params.services[i].selected = false;
            for (var x = 0; x < $scope.params.services[i].services.length; x++) {
                $scope.params.services[i].services[x].selected = false;
            }
        }
    };

    $scope.serviceSelectionAll = function ($event) {
        $event.stopImmediatePropagation();
        for (var i = 0; i < $scope.params.services.length; i++) {
            $scope.params.services[i].selected = true;
            for (var x = 0; x < $scope.params.services[i].services.length; x++) {
                $scope.params.services[i].services[x].selected = true;
            }
        }
    };

    $scope.toggleCBService = function (group_name) {
        for (var i = 0; i < $scope.params.services.length; i++) {
            if ($scope.params.services[i].name == group_name) {
                $scope.params.services[i].selected = true;
                for (var x = 0; x < $scope.params.services[i].services.length; x++) {
                    if (!$scope.params.services[i].services[x].selected) {
                        $scope.params.services[i].selected = false;
                        break;
                    }
                }
                break;
            }
        }
    };

    $scope.toggleCBGroup = function (group_name, selected) {
        for (var i = 0; i < $scope.params.services.length; i++) {
            if ($scope.params.services[i].name == group_name) {
                for (var x = 0; x < $scope.params.services[i].services.length; x++) {
                    $scope.params.services[i].services[x].selected = selected;
                }
                break;
            }
        }
    };

    //Save params
    $scope.saveParams = function () {
        $scope.error = '';
        $scope.success = '';
        $http({
            method: 'POST',
            url: "/api/v3/user/settings/" + $scope.user.uname + "/",
            data: $scope.params
        })
            .success(function () {
                $scope.success = "User's settings successfully saved!";
                $scope.warning = "";
                $timeout(function () {
                    $scope.success = "";
                }, 2000);
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
            });
    };

    //Load params from datastore
    $scope.start = function () {
        if ($scope.forced) {
            $scope.warning = "You are being forced to edit and save your default settings by the system. These settings will be applied to every new submission you put through the system unless you specificly change them before submitting.";
        }
        $scope.loading = true;
        $http({
            method: 'GET',
            url: "/api/v3/user/settings/" + $scope.user.uname + "/"
        })
            .success(function (data) {
                $scope.loading = false;
                var temp_param = jQuery.extend(true, {}, data.api_response);
                var temp_param_bck = jQuery.extend(true, {}, data.api_response);

                $scope.params = temp_param;
                $scope.params_bck = temp_param_bck;
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
            });
    };

    $scope.receiveClassification = function (classification) {
        $scope.params.classification = classification;
    }
}

var app = angular.module('app', ['utils', 'search', 'ngAnimate', 'ui.bootstrap']);
app.controller('ALController', SettingsBaseCtrl);
