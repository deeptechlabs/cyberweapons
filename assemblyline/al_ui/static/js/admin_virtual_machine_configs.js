/* global angular */
'use strict';

/**
 * Main App Module
 */
var app = angular.module('app', ['search', 'utils', 'ui.bootstrap'])
    .controller('ALController', function ($scope, $http, $timeout) {
        //Parameters vars
        $scope.vm_list = null;
        $scope.user = null;
        $scope.loading = false;
        $scope.loading_extra = false;
        $scope.current_vm = null;
        $scope.started = false;
        $scope.new_vm = false;

        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        //Error handling
        $scope.error = '';
        $scope.success = '';

        $scope.add_vm_modal = function () {
            $scope.new_vm = true;
            $scope.current_vm = {
                enabled: true,
                name: "",
                num_workers: 1,
                os_type: "windows",
                os_variant: "win7",
                ram: 1024,
                revert_every: 86400,
                vcpus: 1,
                virtual_disk_url: ""
            };
            $scope.error = '';
            $scope.success = '';
            $scope.error_exist = "";
            $("#vm_name_group").removeClass("has-error");
            $("#myModal").modal('show');
        };

        $scope.editVM = function (vm) {
            $scope.loading_extra = true;
            $scope.error = '';
            $scope.success = '';
            $("#vm_name_group").removeClass("has-error");
            $scope.error_exist = "";

            $http({
                method: 'GET',
                url: "/api/v3/vm/" + vm.name + "/"
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.current_vm = data.api_response;
                    $scope.new_vm = false;
                    $("#myModal").modal('show');
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
                    scroll(0, 0);
                });
        };

        //Save params
        $scope.save = function () {
            $scope.loading_extra = true;
            $scope.error = '';
            $scope.success = '';

            $http({
                method: 'POST',
                url: "/api/v3/vm/" + $scope.current_vm.name + "/",
                data: $scope.current_vm
            })
                .success(function () {
                    $scope.loading_extra = false;
                    $("#myModal").modal('hide');
                    $scope.success = "Virtual Machine " + $scope.current_vm.name + " successfully updated!";
                    $timeout(function () {
                        $scope.success = "";
                        $scope.load_data();
                    }, 2000);
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;
                    if (data == "") {
                        return;
                    }

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                    scroll(0, 0);
                });
        };

        $scope.add = function () {
            $scope.loading_extra = true;
            $scope.error = '';
            $scope.success = '';

            $http({
                method: 'PUT',
                url: "/api/v3/vm/" + $scope.current_vm.name + "/",
                data: $scope.current_vm
            })
                .success(function () {
                    $scope.loading_extra = false;
                    $("#myModal").modal('hide');
                    $scope.success = "Virtual Machine " + $scope.current_vm.name + " successfully updated!";
                    $timeout(function () {
                        $scope.success = "";
                        $scope.load_data();
                    }, 2000);
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (data == "" || status == 400) {
                        $("#vm_name_group").addClass("has-error");
                        $("#vm_name").select();
                        $scope.error_exist = data.api_error_message;
                        return;
                    }

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                    scroll(0, 0);
                });
        };

        $scope.del = function () {
            swal({
                    title: "Delete Virtual Machine?",
                    text: "You are about to delete the current virtual machine. Are you sure?",
                    type: "warning",
                    showCancelButton: true,
                    confirmButtonColor: "#d9534f",
                    confirmButtonText: "Yes, delete it!",
                    closeOnConfirm: true
                },
                function () {
                    $scope.do_del();
                })
        };

        $scope.do_del = function () {
            $scope.error = '';
            $scope.success = '';
            $scope.loading_extra = true;

            $http({
                method: 'DELETE',
                url: "/api/v3/vm/" + $scope.current_vm.name + "/"
            })
                .success(function () {
                    $scope.loading_extra = false;
                    $("#myModal").modal('hide');
                    $scope.success = "Virtual Machine '" + $scope.current_vm.name + "' successfully deleted!";
                    $timeout(function () {
                        $scope.success = "";
                        $scope.load_data();
                    }, 2000);
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (data == "") {
                        return;
                    }

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                    scroll(0, 0);
                });
        };

        $scope.nonProvisioned = function () {
            if ($scope.vm_list == null || $scope.service_list == null || !$scope.new_vm) {
                return [];
            }

            var keys = [];
            for (var i in $scope.vm_list) {
                keys.push($scope.vm_list[i].name);
            }
            var array = [];
            var found = false;

            for (var idx in $scope.service_list) {
                if (!$scope.service_list[idx].enabled) {
                    continue;
                }
                for (var k in keys) {
                    if (keys[k] == $scope.service_list[idx].name) {
                        found = true;
                        break;
                    }
                }
                if (!found) array.push($scope.service_list[idx]);
                found = false;
            }

            for (var idx_vmname in array) {
                if ($scope.current_vm.name == array[idx_vmname].name) {
                    found = true;
                    break;
                }
            }
            if (!found && array.length > 0) $scope.current_vm.name = array[0].name;

            return array;
        };

        //Load params from datastore
        $scope.start = function () {
            $scope.load_services();
            $scope.load_data();
        };

        //Pager methods
        $scope.load_data = function () {
            $scope.loading_extra = true;

            $http({
                method: 'GET',
                url: "/api/v3/vm/list/"
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.vm_list = data.api_response;
                    $scope.started = true;
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (data == "" || status == 400) {
                        $scope.vm_list = [];
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
        };

        $scope.load_services = function () {
            $scope.loading_extra = true;

            $http({
                method: 'GET',
                url: "/api/v3/service/list/"
            })
                .success(function (data) {
                    $scope.loading_extra = false;

                    $scope.service_list = data.api_response;
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

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

    });
