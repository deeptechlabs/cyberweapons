/* global angular */
'use strict';

/**
 * Main App Module
 */
var uuid = null;

function generateUUID(file) {
    var relativePath = file.relativePath || file.webkitRelativePath || file.fileName || file.name;

    if (uuid == null) {
        var d = new Date().getTime();
        uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
            var r = (d + Math.random() * 16) % 16 | 0;
            d = Math.floor(d / 16);
            return (c == 'x' ? r : (r & 0x7 | 0x8)).toString(16);
        });
    }

    return uuid + "_" + file.size + '_' + relativePath.replace(/[^0-9a-zA-Z_-]/img, '');
}

function SubmitBaseCtrl($scope, $http, $timeout) {
    //DEBUG MODE
    $scope.debug = false;
    $scope.showParams = function () {
        console.log("Scope", $scope)
    };

    $scope.receiveClassification = function (classification) {
        $scope.params.classification = classification;
    };

    $scope.prepare_transfer = function () {
        if ($scope.user.c12n_enforcing) {
            swal({
                    title: $scope.params.classification,
                    text: "\n\nAre you sure this is the right classification for your files?\n\n",
                    type: "warning",
                    showCancelButton: true,
                    confirmButtonColor: "#d9534f",
                    confirmButtonText: "Yes, submit this!",
                    closeOnConfirm: true
                },
                function () {
                    $timeout(function () {
                        $scope.check_external();
                    }, 250)
                });
        }
        else {
            $scope.check_external();
        }
    };

    $scope.check_external = function () {
        var raise_warning = false;
        for (var i = 0; i < $scope.params.services.length; i++) {
            for (var x = 0; x < $scope.params.services[i].services.length; x++) {
                if ($scope.params.services[i].services[x].is_external && $scope.params.services[i].services[x].selected) {
                    raise_warning = true;
                    break;
                }
            }
        }

        if (raise_warning) {
            swal({
                    title: "External Submission!",
                    text: "\n\nYou are about to submit your file(s) to a service outside of our infrastructure.\n\nThis may take several minutes...\n\n",
                    type: "warning",
                    showCancelButton: true,
                    confirmButtonColor: "#d9534f",
                    confirmButtonText: "Deselect external services",
                    cancelButtonText: "Continue",
                    closeOnConfirm: true,
                    closeOnCancel: true
                },
                function () {
                    for (var i = 0; i < $scope.params.services.length; i++) {
                        for (var x = 0; x < $scope.params.services[i].services.length; x++) {
                            if ($scope.params.services[i].services[x].is_external && $scope.params.services[i].services[x].selected) {
                                $scope.params.services[i].selected = false;
                                $scope.params.services[i].services[x].selected = false;
                            }
                        }
                    }
                    $scope.start_transfer();
                },
                function () {
                    $scope.start_transfer();
                });
        }
        else {
            $scope.start_transfer();
        }
    };

    //Error handling
    $scope.error = '';
    $scope.success = '';
    $scope.loading = false;
    $scope.user = null;
    $scope.obj = {};

    //File transfer Variables/Functions
    $scope.transfer_started = false;

    $scope.start_transfer = function () {
        $scope.transfer_started = true;
        $scope.obj.flow.on('complete', function () {
            for (var x = 0; x < $scope.obj.flow.files.length; x++) {
                if ($scope.obj.flow.files[x].error) {
                    return;
                }
            }
            $http({
                method: 'POST',
                url: "/api/v3/ui/start/" + uuid + "/",
                data: $scope.params
            })
                .success(function (data) {
                    window.location = "/submission_detail.html?new&sid=" + data.api_response.sid;
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

                    $scope.reset_transfer();
                    uuid = null;
                });
        });
        $scope.obj.flow.upload();
    };

    $scope.reset_transfer = function () {
        $scope.transfer_started = false;
        $scope.obj.flow.cancel();
    };

    //Sliding menu
    $scope.showmenu = false;
    $scope.params = null;
    $scope.params_bck = null;

    $scope.toggleMenu = function () {
        $scope.showmenu = (!$scope.showmenu);
    };

    $scope.forceOpenMenu = function () {
        if ($scope.showmenu == false) {
            $scope.showmenu = true;
        }
    };

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

    //Load params from datastore
    $scope.start = function () {
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
}

function flowFactory(flowFactoryProvider) {
    flowFactoryProvider.defaults = {
        target: '/api/v3/ui/flowjs/',
        permanentErrors: [412, 404, 500],
        maxChunkRetries: 1,
        chunkRetryInterval: 2000,
        simultaneousUploads: 4,
        generateUniqueIdentifier: generateUUID
    };
    flowFactoryProvider.on('catchAll', function (event) {
        console.log('catchAll', arguments);
    });
    flowFactoryProvider.on('fileAdded', function (event) {
        console.log(arguments[0].uniqueIdentifier)
    });
}

var app = angular.module('app', ['search', 'flow', 'utils', 'ui.bootstrap']);
app.config(flowFactory);
app.controller('ALController', SubmitBaseCtrl);
