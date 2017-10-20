/* global angular */
'use strict';

/**
 * Main App Module
 */
var app = angular.module('app', ['search', 'utils', 'ui.bootstrap'])
    .controller('ALController', function ($scope, $http, $timeout) {
        //Parameters vars
        $scope.profile_list = null;
        $scope.profile = null;
        $scope.user = null;
        $scope.loading = false;
        $scope.loading_extra = false;
        $scope.current_profile = null;
        $scope.started = false;
        $scope.new_profile = false;

        $scope.temp_srv_workers = 1;
        $scope.temp_srv_config = {};
        $scope.temp_srv_name = "";
        $scope.edit_mode = false;

        $scope.conf_temp_key = "";
        $scope.conf_temp_type = "bool";
        $scope.conf_temp_val = false;

        $scope.temp_override_key = "";
        $scope.temp_override_type = "bool";
        $scope.temp_override_val = false;

        $scope.temp_vm_config = {};
        $scope.temp_vm_name = "";
        $scope.temp_vm_instance = 1;
        $scope.temp_vm_override_key = "";
        $scope.temp_vm_override_type = "bool";
        $scope.temp_vm_override_val = false;

        $scope.filtered = false;
        $scope.filter = "*";
        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        //Error handling
        $scope.error = '';
        $scope.success = '';

        //Pager vars
        $scope.show_pager_add = true;
        $scope.pager_add = function () {
            $scope.profile = "";
            $scope.new_profile = true;
            $scope.edit_mode = false;
            $scope.current_profile = {services: {}, system_overrides: {}, virtual_machines: {}};
            $scope.error = '';
            $scope.success = '';
            $scope.error_exist = "";
            $("#profile_name_group").removeClass("has-error");
            $("#myModal").modal('show');
        };
        $scope.pager_btn_text = "Add Profile";
        $scope.total = null;
        $scope.offset = 0;
        $scope.count = 25;
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

        $scope.cancel = function () {
            $scope.edit_mode = false;
        };

        //VM functions
        $scope.toggleAddVM = function () {
            $scope.temp_vm_config = {};
            if ($scope.vm_list.length != 0) {
                $scope.temp_vm_name = $scope.vm_list[0].name;
            }
            $scope.edit_mode = false;
        };

        $scope.toggleEditVM = function (key) {
            $scope.temp_vm_config = $scope.current_profile.virtual_machines[key].vm_overrides;
            $scope.temp_vm_instance = $scope.current_profile.virtual_machines[key].num_instances;
            $scope.temp_vm_name = key;
            $scope.edit_mode = true;

        };

        $scope.resetVMOverride = function () {
            $scope.temp_vm_override_key = "";
            $scope.temp_vm_override_type = "bool";
            $scope.temp_vm_override_val = false;
        };

        $scope.$watch('temp_vm_override_type', function () {
            if ($scope.temp_vm_override_type == "bool") {
                $scope.temp_vm_override_val = false;
                $("#vm_default").val("false");
            }
            else if ($scope.temp_vm_override_type == "list") {
                $scope.temp_vm_override_val = [];
                $("#vm_default").val("");
            }
            else if ($scope.temp_vm_override_type == "int") {
                $scope.temp_vm_override_val = 1;
                $("#vm_default").val("1");
            }
            else {
                $scope.temp_vm_override_val = "";
                $("#vm_default").val("");
            }
        });

        $scope.add_temp_vm_override = function () {
            if ($scope.temp_vm_override_key == "") return;
            $scope.temp_vm_config[$scope.temp_vm_override_key] = $scope.temp_vm_override_val;
            $scope.resetVMOverride();
        };

        $scope.remove_temp_vm_override = function (key) {
            delete $scope.temp_vm_config[key];
        };

        $scope.removeVM = function (key) {
            delete $scope.current_profile.virtual_machines[key];
        };

        $scope.addVM = function () {
            if ($scope.temp_vm_name == "") return;
            $scope.current_profile.virtual_machines[$scope.temp_vm_name] = {
                vm_overrides: $scope.temp_vm_config,
                num_instances: $scope.temp_vm_instance
            };
        };

        $scope.saveVM = function () {
            $scope.edit_mode = false;
            $scope.current_profile.virtual_machines[$scope.temp_vm_name] = {
                vm_overrides: $scope.temp_vm_config,
                num_instances: $scope.temp_vm_instance
            };
        };

        $scope.notInVMs = function () {
            if ($scope.current_profile == null || $scope.vm_list == null || $scope.edit_mode) {
                return [];
            }

            var keys = null;
            try {
                keys = Object.keys($scope.current_profile.virtual_machines);
            }
            catch (e) {
                keys = [];
            }
            var array = [];
            var found = false;

            for (var idx in $scope.vm_list) {
                if (!$scope.vm_list[idx].enabled) {
                    continue;
                }
                for (var k in keys) {
                    if (keys[k] == $scope.vm_list[idx].name) {
                        found = true;
                        break;
                    }
                }
                if (!found) array.push($scope.vm_list[idx]);
                found = false;
            }

            for (var idx_vname in array) {
                if ($scope.temp_vm_name == array[idx_vname].name) {
                    found = true;
                    break;
                }
            }
            if (!found && array.length > 0) $scope.temp_vm_name = array[0].name;

            return array;
        };

        //SERVICE functions
        $scope.toggleAddComponent = function () {
            $scope.temp_srv_workers = 1;
            $scope.temp_srv_config = {};
            if ($scope.service_list.length != 0) {
                $scope.temp_srv_name = $scope.service_list[0].name;
            }
            $scope.edit_mode = false;
        };

        $scope.toggleEditComponent = function (key) {
            $scope.temp_srv_workers = $scope.current_profile.services[key].workers;
            $scope.temp_srv_config = $scope.current_profile.services[key].service_overrides;
            $scope.temp_srv_name = key;
            $scope.edit_mode = true;

        };

        $scope.resetOverride = function () {
            $scope.temp_override_key = "";
            $scope.temp_override_type = "bool";
            $scope.temp_override_val = false;
        };

        $scope.$watch('temp_override_type', function () {
            if ($scope.temp_override_type == "bool") {
                $scope.temp_override_val = false;
                $("#comp_default").val("false");
            }
            else if ($scope.temp_override_type == "list") {
                $scope.temp_override_val = [];
                $("#comp_default").val("");
            }
            else if ($scope.temp_override_type == "int") {
                $scope.temp_override_val = 1;
                $("#comp_default").val("1");
            }
            else {
                $scope.temp_override_val = "";
                $("#comp_default").val("");
            }
        });

        $scope.add_temp_override = function () {
            if ($scope.temp_override_key == "") return;
            $scope.temp_srv_config[$scope.temp_override_key] = $scope.temp_override_val;
            $scope.resetOverride();
        };

        $scope.remove_temp_override = function (key) {
            delete $scope.temp_srv_config[key];
        };

        $scope.removeComponent = function (key) {
            delete $scope.current_profile.services[key];
        };

        $scope.addComponent = function () {
            if ($scope.temp_srv_name == "") return;
            $scope.current_profile.services[$scope.temp_srv_name] = {
                workers: $scope.temp_srv_workers,
                service_overrides: $scope.temp_srv_config
            };
        };

        $scope.saveComponent = function () {
            $scope.edit_mode = false;
            $scope.current_profile.services[$scope.temp_srv_name] = {
                workers: $scope.temp_srv_workers,
                service_overrides: $scope.temp_srv_config
            };
        };

        $scope.notInComponents = function () {
            if ($scope.current_profile == null || $scope.service_list == null || $scope.edit_mode) {
                return [];
            }

            var keys = null;
            try {
                keys = Object.keys($scope.current_profile.services);
            }
            catch (e) {
                keys = [];
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

            for (var idx_vname in array) {
                if ($scope.temp_srv_name == array[idx_vname].name) {
                    found = true;
                    break;
                }
            }
            if (!found && array.length > 0) $scope.temp_srv_name = array[0].name;

            return array;
        };


        //SYSTEM functions
        $scope.resetGlob = function () {
            $scope.conf_temp_key = "";
            $scope.conf_temp_type = "bool";
            $scope.conf_temp_val = false;
        };

        $scope.$watch('conf_temp_type', function () {
            if ($scope.conf_temp_type == "bool") {
                $scope.conf_temp_val = false;
                $("#glob_default").val("false");
            }
            else if ($scope.conf_temp_type == "list") {
                $scope.conf_temp_val = [];
                $("#glob_default").val("");
            }
            else if ($scope.conf_temp_type == "int") {
                $scope.conf_temp_val = 1;
                $("#glob_default").val("1");
            }
            else {
                $scope.conf_temp_val = "";
                $("#glob_default").val("");
            }
        });

        $scope.add_meta = function () {
            if ($scope.conf_temp_key == "") return;
            $scope.current_profile.system_overrides[$scope.conf_temp_key] = $scope.conf_temp_val;
            $scope.resetGlob();
        };

        $scope.remove_meta = function (key) {
            delete $scope.current_profile.system_overrides[key];
        };

        $scope.typeOf = function (val) {
            return typeof(val);
        };

        //Pager methods
        $scope.load_profile = function (profile) {
            $scope.loading_extra = true;

            $http({
                method: 'GET',
                url: "/api/v3/profile/" + profile + "/"
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.current_profile = data.api_response;
                    $scope.error_exist = "";
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
                    scroll(0, 0);
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
                    if ($scope.service_list.length != 0) {
                        $scope.temp_srv_name = $scope.service_list[0].name;
                    }
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
                    scroll(0, 0);
                });
        };

        $scope.load_vms = function () {
            $scope.loading_extra = true;

            $http({
                method: 'GET',
                url: "/api/v3/vm/list/"
            })
                .success(function (data) {
                    $scope.loading_extra = false;

                    $scope.vm_list = data.api_response;
                    if ($scope.vm_list.length != 0) {
                        $scope.temp_vm_name = $scope.vm_list[0].name;
                    }
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
                    scroll(0, 0);
                });
        };

        $scope.viewProfile = function (profile) {
            $scope.load_profile(profile);
            $scope.profile = profile;

            $scope.error = '';
            $scope.success = '';
            $scope.loading_extra = true;
            $scope.new_profile = false;

        };

        //Save params
        $scope.save = function () {
            $scope.error = '';
            $scope.success = '';
            $scope.loading_extra = true;

            $http({
                method: 'POST',
                url: "/api/v3/profile/" + $scope.profile + "/",
                data: $scope.current_profile
            })
                .success(function () {
                    $scope.loading_extra = false;
                    $("#myModal").modal('hide');
                    $scope.success = "Profile '" + $scope.profile + "' successfully updated!";
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
            $scope.error = '';
            $scope.success = '';
            $scope.loading_extra = true;

            $http({
                method: 'PUT',
                url: "/api/v3/profile/" + $scope.profile + "/",
                data: $scope.current_profile
            })
                .success(function () {
                    $scope.loading_extra = false;
                    $("#myModal").modal('hide');
                    $scope.success = "Profile '" + $scope.profile + "' successfully added!";
                    $timeout(function () {
                        $scope.success = "";
                        $scope.load_data();
                    }, 2000);
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (data == "" || status == 400) {
                        $("#profile_name_group").addClass("has-error");
                        $("#profile_name").select();
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
                    title: "Delete Profile?",
                    text: "You are about to delete the current profile. Are you sure?",
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
                url: "/api/v3/profile/" + $scope.profile + "/"
            })
                .success(function () {
                    $scope.loading_extra = false;
                    $("#myModal").modal('hide');
                    $scope.success = "Profile '" + $scope.profile + "' successfully deleted!";
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

        //Load params from datastore
        $scope.start = function () {
            $scope.load_services();
            $scope.load_vms();
            $scope.load_data();
        };

        //Pager methods
        $scope.load_data = function () {
            $scope.loading_extra = true;

            $http({
                method: 'GET',
                url: "/api/v3/profile/list/?offset=" + $scope.offset + "&length=" + $scope.count + "&filter=" + $scope.filter
            })
                .success(function (data) {
                    $scope.loading_extra = false;

                    $scope.profile_list = data.api_response.items;
                    $scope.total = data.api_response.total;

                    $scope.pages = $scope.pagerArray();
                    $scope.started = true;

                    $scope.filtered = $scope.filter != "*";
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (data == "" || status == 400) {
                        $scope.service_list = [];
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
    });
