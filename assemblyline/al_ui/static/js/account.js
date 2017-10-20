/* global angular */
'use strict';

/**
 * Main App Module
 */

function AccountBaseCtrl($scope, $http, $timeout, $sce) {
    //Parameters vars
    $scope.current_user = null;
    $scope.user = null;
    $scope.loading = false;
    $scope.apikey_pattern = /^[A-Za-z0-9_]{1,}$/;

    //DEBUG MODE
    $scope.debug = false;
    $scope.showParams = function () {
        console.log("Scope", $scope)
    };

    $scope.maximum_classification = true;
    $scope.receiveClassification = function (classification) {
        $scope.current_user.classification = classification;
    };

    //Error handling
    $scope.error = '';
    $scope.success = '';

    $scope.cancel_u2f = function(){
        $scope.cancelled_u2f = true;
    };

    $scope.disable_u2f_device = function(){
        swal({
            title: "Disable U2F Token?",
            text: "Are you sure you want to disable to currently configured U2F Token?",
            type: "warning",
            showCancelButton: true,
            confirmButtonColor: "#d9534f",
            confirmButtonText: "Yes",
            closeOnConfirm: true
        },
        function () {
            $scope.loading_extra = true;
            $http({
                method: 'GET',
                url: "/api/v3/u2f/clear/"
            })
            .success(function (data) {
                $scope.loading_extra = false;
                $scope.current_user['u2f_enabled'] = false;
            })
            .error(function (data, status, headers, config) {
                $scope.loading_extra = false;
                if (data === "") {
                    return;
                }

                if (data.api_error_message) {
                    $scope.error = data.api_error_message;
                }
                else {
                    $scope.error = config.url + " (" + status + ")";
                }
            });
        });
    };

    $scope.register_u2f_device = function(){
        $scope.loading_extra = true;
        $scope.u2f_error = "";
        $scope.cancelled_u2f = false;
        $http({
            method: 'GET',
            url: "/api/v3/u2f/enroll/"
        })
        .success(function (data) {
            $scope.loading_extra = false;
            $('#u2f_prompt').modal('show');
            u2f.register(data.api_response.appId, data.api_response.registerRequests, data.api_response.registeredKeys,
                function(deviceResponse) {
                    if ($scope.cancelled_u2f){
                        return;
                    }
                    $scope.loading_extra = true;
                    $http({
                        method: 'POST',
                        url: "/api/v3/u2f/bind/",
                        data: deviceResponse
                    })
                    .success(function (data) {
                        $scope.loading_extra = false;
                        $scope.success = "U2F Security Token enabled on your account.";
                        $scope.current_user['u2f_enabled'] = true;
                        $('#u2f_prompt').modal('hide');
                        $timeout(function () {
                            $scope.success = "";
                        }, 2000);
                    })
                    .error(function (data, status, headers, config) {
                        $scope.loading_extra = false;
                        if (data === "") {
                            return;
                        }

                        if (data.api_error_message) {
                            $scope.u2f_error = data.api_error_message;
                        }
                        else {
                            $scope.error = config.url + " (" + status + ")";
                        }
                    });
                }
            );
        })
        .error(function (data, status, headers, config) {
            $scope.loading_extra = false;
            if (data === "") {
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

    $scope.manage_apikeys = function(){
        $scope.apikey_name = "";
        $scope.apikey_priv = "READ";
        $("#apikeyModal").modal('show');
    };

    $scope.add_apikey = function(){
        $scope.apikey_error = "";
        $scope.loading_extra = true;
        $http({
            method: 'GET',
            url: "/api/v3/auth/apikey/" + $scope.apikey_name + "/" + $scope.apikey_priv + "/"
        })
        .success(function (data) {
            $scope.loading_extra = false;
            $scope.new_apikey = data.api_response.apikey;
            $scope.new_apikey_name = $scope.apikey_name;
            $scope.new_apikey_priv = $scope.apikey_priv;
            $scope.current_user.apikeys.push($scope.apikey_name);
            $scope.apikey_name = "";
            $scope.apikey_priv = "READ";
            $('#apikeyDisplayModal').modal('show');
        })
        .error(function (data, status, headers, config) {
            $scope.loading_extra = false;
            if (data === "") {
                return;
            }

            if (data.api_error_message) {
                $scope.apikey_error = data.api_error_message;
                var key_input = $('#apikey_name');
                key_input.focus();
                key_input.select();

            }
            else {
                $scope.error = config.url + " (" + status + ")";
            }
        });
    };

    $scope.delete_apikey = function(key){
        swal({
            title: "Delete APIKey",
            text: "Are you sure you want to delete APIKey '" + key + "'?",
            type: "warning",
            showCancelButton: true,
            confirmButtonColor: "#d9534f",
            confirmButtonText: "Yes",
            closeOnConfirm: true
        },
        function () {
            $http({
                method: 'DELETE',
                url: "/api/v3/auth/apikey/" + key + "/"
            })
            .success(function (data) {
                $scope.current_user.apikeys.splice($scope.current_user.apikeys.indexOf(key), 1);
            })
            .error(function (data, status, headers, config) {
                if (data === "") {
                    return;
                }

                if (data.api_error_message) {
                    $scope.error = data.api_error_message;
                }
                else {
                    $scope.error = config.url + " (" + status + ")";
                }
            });
        })
    };

    $scope.enable_2fa = function () {
        $scope.error = '';
        $scope.success = '';

        $http({
            method: 'GET',
            url: "/api/v3/auth/setup_otp/"
        })
        .success(function (data) {
            $scope.otp_data = data.api_response;
            $scope.safe_qrcode = $sce.trustAsHtml($scope.otp_data.qrcode);
            $("#myModal").modal('show');
        })
        .error(function (data, status, headers, config) {
            if (data === "") {
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

    $scope.validate_2fa = function(){
        $http({
            method: 'GET',
            url: "/api/v3/auth/validate_otp/" + $scope.temp_otp_token + "/"
        })
        .success(function (data) {
            $scope.success = "2-Factor Authentication enabled on your account.";
            $scope.current_user['2fa_enabled'] = true;
            $("#myModal").modal('hide');
            $timeout(function () {
                $scope.success = "";
            }, 2000);
        })
        .error(function (data, status, headers, config) {
            if (data === "") {
                return;
            }

            if (data.api_error_message) {
                $scope.otp_error = data.api_error_message;
                var otp_input = $('#temp_otp_token');
                otp_input.focus();
                otp_input.select();
            }
            else {
                $scope.error = config.url + " (" + status + ")";
            }
        });
    };

    $scope.disable_2fa = function () {
        swal({
            title: "Disable 2-Factor Auth?",
            text: "Are you sure you want to disable 2-Factor Auth on this account?",
            type: "warning",
            showCancelButton: true,
            confirmButtonColor: "#d9534f",
            confirmButtonText: "Yes",
            closeOnConfirm: true
        },
        function () {
            $scope.error = '';
            $scope.success = '';

            $http({
                method: 'GET',
                url: "/api/v3/auth/disable_otp/"
            })
            .success(function (data) {
                $scope.current_user['2fa_enabled'] = false;
            })
            .error(function (data, status, headers, config) {
                if (data === "") {
                    return;
                }

                if (data.api_error_message) {
                    $scope.error = data.api_error_message;
                }
                else {
                    $scope.error = config.url + " (" + status + ")";
                }
            });}
         );
    };

    //Save current_user
    $scope.save = function () {
        $scope.error = '';
        $scope.success = '';

        $http({
            method: 'POST',
            url: "/api/v3/user/" + $scope.user.uname + "/",
            data: $scope.current_user
        })
            .success(function () {
                $scope.success = "Account successfully updated!";
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

    $scope.new_pass_valid = function () {
        if ($scope.current_user == undefined) {
            return true;
        }

        var new_pass = $scope.current_user.new_pass;
        if (new_pass == undefined) {
            new_pass = "";
        }

        var new_pass_confirm = $scope.current_user.new_pass_confirm;
        if (new_pass_confirm == undefined) {
            new_pass_confirm = "";
        }

        return new_pass == new_pass_confirm;
    };

    //Load current_user from datastore
    $scope.start = function () {
        $scope.loading = true;
        $http({
            method: 'GET',
            url: "/api/v3/user/" + $scope.user.uname + "/?load_avatar"
        })
            .success(function (data) {
                $scope.loading = false;
                $scope.current_user = data.api_response;
                if ($scope.current_user.avatar != null) {
                    $('#avatar').attr("src", $scope.current_user.avatar);
                }
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
                scroll(0, 0);
            });
    };
}

var app = angular.module('app', ['utils', 'search', 'ngAnimate', 'ui.bootstrap']);
app.controller('ALController', AccountBaseCtrl);
