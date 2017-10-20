/* global angular */
'use strict';

/**
 * Main App Module
 */

function LoginBaseCtrl($scope, $http, $timeout) {
    $scope.username = "";
    $scope.password = "";
    $scope.otp = "";
    $scope.error = "";
    $scope.otp_request = false;
    $scope.alternate_login = true;
    $scope.u2f_response = "";

    $scope.switch_to_otp = function(){
        $scope.otp_request = true;
        $scope.u2f_request = false;
        $timeout(function(){$('#inputOTP').focus()}, 100);
    };

    $scope.switch_to_userpass = function(){
        $scope.username="";
        $scope.alternate_login=true;
        $timeout(function(){$('#inputUser').focus()}, 100);
    };

    //Login via API
    $scope.login = function () {
        $scope.error = '';
        $scope.loading = true;
        var password = $scope.password;
        if ($scope.public_key !== "None"){
            var rsa = new JSEncrypt();
            rsa.setPublicKey($scope.public_key);
            password = rsa.encrypt($scope.password)
        }

        $http({
            method: 'POST',
            url: "/api/v3/auth/login/",
            data: {user: $scope.username, password: password, otp: $scope.otp, u2f_response: $scope.u2f_response}
        })
        .success(function () {
            window.location = $scope.next;
        })
        .error(function (data) {
            if (data.api_error_message === 'Wrong U2F Security Token'){
                if ($scope.u2f_request){
                    $scope.error = data.api_error_message;
                }
                else{
                    $scope.u2f_request = true;
                    $scope.otp_request = false;
                }

                $http({
                    method: 'GET',
                    url: "/api/v3/u2f/sign/" + $scope.username + "/"
                })
                .success(function (data) {
                    $scope.loading = false;
                    u2f.sign(data.api_response.appId, data.api_response.challenge, data.api_response.registeredKeys,
                        function(deviceResponse) {
                            if (deviceResponse.errorCode === undefined){
                                $scope.u2f_response = deviceResponse;
                                $timeout(function(){
                                    $scope.login();
                                }, 100);
                            }
                        });
                })
                .error(function (data) {
                    $scope.error = data.api_error_message;
                    $scope.loading = false;
                });

            }
            else if (data.api_error_message === 'Wrong OTP token'){
                if ($scope.otp_request){
                    $scope.error = data.api_error_message;
                }
                else{
                    $scope.otp_request = true;
                    $scope.u2f_request = false;
                }
                $scope.loading = false;
                $scope.otp = "";
                $timeout(function(){$('#inputOTP').focus()}, 100);
            }
            else {
                $scope.error = data.api_error_message;
                $scope.loading = false;
            }
        });
    };

    //Load current_user from datastore
    $scope.start = function () {

    };
}

var app = angular.module('app', []);
app.controller('ALController', LoginBaseCtrl);
