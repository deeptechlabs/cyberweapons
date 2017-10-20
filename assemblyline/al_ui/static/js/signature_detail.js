/* global angular */
'use strict';

/**
 * Main App Module
 */
function SignatureDetailBaseCtrl($scope, $http, $timeout) {
    //Parameters vars
    $scope.user = null;
    $scope.options = null;
    $scope.loading = false;
    $scope.loading_extra = false;
    $scope.sid = null;
    $scope.rev = null;
    $scope.sig_temp_key = null;
    $scope.sig_temp_val = null;
    $scope.current_signature = null;
    $scope.editmode = true;
    $scope.organisation = "ORG";
    $scope.state_changed = false;
    $scope.signature_changed = false;
    $scope.current_signature_state = "TESTING";
    $scope.non_editable = ['creation_date', 'last_saved_by', 'modification_date', 'al_state_change_date', 'al_state_change_user'];

    //DEBUG MODE
    $scope.debug = false;
    $scope.showParams = function () {
        console.log("Scope", $scope)
    };

    //Error handling
    $scope.error = '';
    $scope.success = '';

    $scope.receiveClassification = function (classification) {
        $scope.current_signature.meta.classification = classification;
    };

    $scope.beautify_error_message = function (data) {
        if (data.field === undefined) {
            return data;
        }

        var out = String();

        if (data.field == null) {
            out += "Rule has a " + data.message.type + " on line " + data.message.line + ": [ " + data.message.error + " ]\n\n";
            out += data.message.rule_text;
        }
        else {
            out += "Field ";
            out += data.field;
            out += " has an error:\n\n";
            out += data.message;
        }

        return out;
    };


    //Save params
    $scope.save = function () {
        $scope.error = '';
        $scope.success = '';

        $http({
            method: 'POST',
            url: "/api/v3/signature/" + $scope.current_signature.meta.id + "/" + $scope.current_signature.meta.rule_version + "/",
            data: $scope.current_signature
        })
            .success(function (data) {
                $("#myModal").modal('hide');
                if (data.api_response.rev != $scope.current_signature.meta.rule_version) {
                    $scope.success = "Signature " + data.api_response.sid + " succesfully saved and bumped to revision " + data.api_response.rev + ".";
                }
                else {
                    $scope.success = "Signature " + data.api_response.sid + " succesfully saved.";
                }

                $timeout(function () {
                    $scope.success = "";
                    $scope.load_data();
                }, 2000);
            })
            .error(function (data, status, headers, config) {
                if (data == "") {
                    return;
                }

                if (data.api_error_message) {
                    $scope.error = $scope.beautify_error_message(data.api_error_message);
                }
                else {
                    $scope.error = config.url + " (" + status + ")";
                }
            });


    };

    $scope.change_state = function (new_status) {
        $http({
            method: 'GET',
            url: "/api/v3/signature/change_status/" + $scope.current_signature.meta.id + "/" + $scope.current_signature.meta.rule_version + "/" + new_status + "/"
        })
            .success(function () {
                $("#myModal").modal('hide');
                $scope.success = "Status of signature " + $scope.current_signature.meta.id + " r." + $scope.current_signature.meta.rule_version + " successfully changed to " + new_status + ".";
                $timeout(function () {
                    $scope.success = "";
                    $scope.load_data();
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

    $scope.set_state_change = function () {
        $scope.state_changed = true;
    };

    $scope.otherKeys = function () {
        var out = [];

        if ($scope.current_signature !== undefined && $scope.current_signature != null) {
            var exclusion = ['rule_group', 'classification', 'description', 'id', 'organisation', 'poc', 'rule_version', 'yara_version', 'al_status', $scope.current_signature.meta.rule_group];
            for (var key in $scope.current_signature.meta) {
                if (exclusion.indexOf(key) == -1) {
                    out.push(key);
                }
            }
        }
        out.sort();

        return out;
    };

    $scope.remove_meta = function (key) {
        delete $scope.current_signature.meta[key];
    };

    $scope.add_meta = function () {
        if ($scope.sig_temp_key in $scope.current_signature.meta || $scope.sig_temp_key == "" || $scope.sig_temp_key == null) {
            return;
        }
        $scope.current_signature.meta[$scope.sig_temp_key] = $scope.sig_temp_val;

        $scope.sig_temp_key = "";
        $scope.sig_temp_val = "";
    };

    //load data
    $scope.start = function () {
        $scope.load_data();
    };

    $scope.load_data = function () {
        $http({
            method: 'GET',
            url: "/api/v3/signature/" + $scope.sid + "/" + $scope.rev + "/"
        })
            .success(function (data) {
                $scope.current_signature = data.api_response;
                $scope.current_signature_state = data.api_response.meta.al_status;
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

}

var app = angular.module('app', ['utils', 'search', 'ngAnimate', 'ui.bootstrap']);
app.controller('ALController', SignatureDetailBaseCtrl);

