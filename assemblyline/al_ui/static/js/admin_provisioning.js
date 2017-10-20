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
        $scope.cpu_gauge_val = 0;
        $scope.ram_gauge_val = 0;
        $scope.host_list = [];
        $scope.total_cpu = 0;
        $scope.total_ram = 0;
        $scope.total_cpu_used = 0;
        $scope.total_ram_used = 0;
        $scope.resource_allocation = {};
        $scope.overrides = {};
        $scope.flex_count = 0;
        $scope.current_plan = null;
        $scope.current_overrides = [];
        $scope.temp_override_count = null;
        $scope.temp_override_val = null;

        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        $scope.getKeys = function (o) {
            return Object.keys(o);
        };

        $scope.add_special_req = function (svc_name) {
            $scope.temp_override_count = null;
            $scope.temp_override_val = null;
            $scope.current_svc = svc_name;
            $scope.current_overrides = jQuery.extend([], $scope.overrides[$scope.current_svc]);
            $('#svc_overrides').modal('show');
        };

        $scope.save_overrides = function () {
            if ($scope.temp_override_count != null && $scope.temp_override_val != null) {
                if (!$scope.add_temp_override()) {
                    return;
                }
            }

            if ($scope.current_overrides.length > 0) {
                $scope.overrides[$scope.current_svc] = jQuery.extend([], $scope.current_overrides);
                $scope.resource_allocation['svc_' + $scope.current_svc] = 0;
                for (var key in $scope.overrides[$scope.current_svc]) {
                    $scope.resource_allocation['svc_' + $scope.current_svc] += $scope.overrides[$scope.current_svc][key].count;
                }
            }
            else {
                delete $scope.overrides[$scope.current_svc];
                $("#svc_" + $scope.current_svc).slider('setValue', $scope.resource_allocation['svc_' + $scope.current_svc]);
            }
            $('#svc_overrides').modal('hide');
        };

        $scope.add_temp_override = function () {
            try {
                JSON.parse($scope.temp_override_val);
                if (($scope.temp_override_val.indexOf("{") != 0 &&
                    $scope.temp_override_val.slice($scope.temp_override_val.length - 1, $scope.temp_override_val.length) != "}") ||
                    $scope.temp_override_val.indexOf(":") == -1) {
                    swal({
                        title: "Invalid override!",
                        text: "\n\nThe following is not a valid JSON override.\n\n" + $scope.temp_override_val,
                        type: "error",
                        showCancelButton: false,
                        confirmButtonColor: "#d9534f",
                        confirmButtonText: "Close",
                        closeOnConfirm: true
                    });
                    return false;
                }
            }
            catch (ex) {
                swal({
                    title: "Invalid override!",
                    text: "\n\nThe following is not a valid JSON override.\n\n" + $scope.temp_override_val,
                    type: "error",
                    showCancelButton: false,
                    confirmButtonColor: "#d9534f",
                    confirmButtonText: "Close",
                    closeOnConfirm: true
                });
                return false;
            }

            $scope.temp_override_count = parseInt($scope.temp_override_count) || 0;
            if ($scope.temp_override_count == 0) {
                swal({
                    title: "Invalid override!",
                    text: "\n\nInvalid number of workers for new override.",
                    type: "error",
                    showCancelButton: false,
                    confirmButtonColor: "#d9534f",
                    confirmButtonText: "Close",
                    closeOnConfirm: true
                });
                return false;
            }

            var data = {
                count: $scope.temp_override_count,
                override: $scope.temp_override_val
            };
            $scope.current_overrides.push(data);
            $scope.temp_override_count = null;
            $scope.temp_override_val = null;

            return true;
        };

        $scope.remove_temp_override = function (key) {
            $scope.current_overrides.pop(key);
        };

        $scope.set_slider_value = function (key, value) {
            $("#" + key).slider('setValue', value);
            $scope.recalculate_gauges();
        };

        $scope.count_vm_allocation = function (vm_name) {
            var srv_count = 0;
            var count = $scope.resource_allocation[vm_name];
            var vm = $scope.vm_list[vm_name.slice(3, vm_name.length)];
            for (var key in vm.services) {
                srv_count += vm.services[key];
            }
            return count * srv_count;
        };

        $scope.reset_sliders = function () {
            $(".slider_item").each(function () {
                $scope.resource_allocation[this.id] = 0;
                $("#" + this.id).slider('setValue', 0);
            });
            $("#flex").slider('setValue', 0);
            $scope.flex_count = 0;
            $scope.overrides = {};
            $scope.recalculate_gauges();
        };

        $scope.recalculate_gauges = function () {
            var cpu_selection = 0;
            var ram_selection = 0;

            for (var i = 0; i < $scope.flex_count; i++) {
                var host = $scope.host_list[i];
                cpu_selection += host.cores;
                ram_selection += host.memory;
            }

            for (var key in $scope.resource_allocation) {
                var count = $scope.resource_allocation[key];
                if (key.indexOf('vm') == 0) {
                    //VM case
                    var vm = $scope.vm_list[key.slice(3, key.length)];
                    if (vm !== undefined) {
                        cpu_selection += vm.cpu_usage * count;
                        ram_selection += vm.ram_usage * count;
                    }
                }
                else {
                    var svc = $scope.service_list[key.slice(4, key.length)];
                    if (svc !== undefined) {
                        cpu_selection += svc.cpu_usage * count;
                        ram_selection += svc.ram_usage * count;
                    }
                }
            }

            $scope.total_cpu_used = cpu_selection;
            $scope.total_ram_used = ram_selection;

            $scope.cpu_gauge_val = cpu_selection / $scope.total_cpu;
            $scope.ram_gauge_val = ram_selection / $scope.total_ram;

            $scope.cpu_gauge.moveTo(Math.min($scope.cpu_gauge_val, 1));
            $scope.ram_gauge.moveTo(Math.min($scope.ram_gauge_val, 1));
        };

        $scope.apply_plan = function () {
            swal({
                    title: "Apply current plan",
                    text: "\n\nAre you sure you want to apply the current plan?\n\nThis is a non-reversible process...",
                    type: "warning",
                    showCancelButton: true,
                    confirmButtonColor: "#d9534f",
                    confirmButtonText: "Yes, do it!",
                    closeOnConfirm: true
                },
                function () {
                    var data = {
                        profiles: $scope.current_plan.allocation_data.profiles,
                        flex_nodes: $scope.current_plan.flex_nodes
                    };

                    $http({
                        method: 'POST',
                        url: "/api/v3/provisioning/plan/apply/",
                        data: data
                    })
                        .success(function (data, config) {
                            $scope.current_plan = null;
                            $('#plan_preview').modal('hide');
                            swal({
                                title: "Plan successfully applied!",
                                text: "",
                                type: "info",
                                showCancelButton: false,
                                confirmButtonColor: "#d9534f",
                                confirmButtonText: "Close",
                                closeOnConfirm: true
                            });

                            data = {
                                allocation: $scope.resource_allocation,
                                flex: $scope.flex_count,
                                overrides: $scope.overrides
                            };

                            $http({
                                method: 'POST',
                                url: "/api/v3/provisioning/config/__LAST_GOOD__/",
                                data: data
                            })
                                .success(function () {
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
                });
        };

        $scope.test_plan = function () {
            if ($scope.cpu_gauge_val > 1 || $scope.ram_gauge_val > 1) {
                swal({
                    title: "Cluster over-provisioned!",
                    text: "You are not allowed to over-provision the cluster.\n\nRemove some services or virtualmachines",
                    type: "error",
                    showCancelButton: false,
                    confirmButtonColor: "#d9534f",
                    confirmButtonText: "Close",
                    closeOnConfirm: true
                });
                return
            }

            $scope.loading_extra = true;
            var data = {
                services: $scope.service_list,
                vms: $scope.vm_list,
                allocation: $scope.resource_allocation,
                flex: $scope.flex_count,
                hosts: $scope.host_list,
                overrides: $scope.overrides
            };

            $http({
                method: 'POST',
                url: "/api/v3/provisioning/plan/test/",
                data: data
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.current_plan = data.api_response;

                    for (var i = 0; i < $scope.flex_count; i++) {
                        $scope.host_list[i].core_percent = 100;
                        $scope.host_list[i].ram_percent = 100;
                    }

                    for (var key in data.api_response.allocation_data.machines) {
                        var machine = data.api_response.allocation_data.machines[key];
                        for (var host_key in $scope.host_list) {
                            var host = $scope.host_list[host_key];
                            if (host.hostname + "-" + host.mac == machine.name) {
                                host.core_percent = (machine.total_cores - machine.available_cores) / machine.total_cores * 100;
                                host.ram_percent = (machine.total_ram - machine.available_ram) / machine.total_ram * 100;
                            }
                        }
                    }
                    $('#plan_preview').modal('show');
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

        $scope.load_current = function () {
            $scope.loading_extra = true;
            $scope.reset_sliders();

            $http({
                method: 'GET',
                url: "/api/v3/provisioning/config/"
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    for (var alloc_key in data.api_response.allocation) {
                        $scope.resource_allocation[alloc_key] = data.api_response.allocation[alloc_key];
                        $("#" + alloc_key).slider('setValue', data.api_response.allocation[alloc_key]);
                    }

                    $("#flex").slider('setValue', data.api_response.flex);
                    $scope.flex_count = data.api_response.flex;
                    $scope.recalculate_gauges();
                    $scope.overrides = data.api_response.overrides;
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

        $scope.load_last_good = function () {
            $scope.loading_extra = true;
            $scope.reset_sliders();

            $http({
                method: 'GET',
                url: "/api/v3/provisioning/config/__LAST_GOOD__/"
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    for (var alloc_key in data.api_response.allocation) {
                        $scope.resource_allocation[alloc_key] = data.api_response.allocation[alloc_key];
                        $("#" + alloc_key).slider('setValue', data.api_response.allocation[alloc_key]);
                    }

                    $("#flex").slider('setValue', data.api_response.flex);
                    $scope.flex_count = data.api_response.flex;
                    $scope.recalculate_gauges();
                    $scope.overrides = data.api_response.overrides;
                })
                .error(function (data, status, headers, config) {
                    if (data == "") {
                        return;
                    }

                    $scope.loading_extra = false;

                    if (status == 404) {
                        $scope.warning = "No config was ever applied through this provisionning interface.";
                        $timeout(function () {
                            $scope.warning = '';
                        }, 2000);
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

        $scope.start = function () {
            $http({
                method: 'GET',
                url: "/api/v3/provisioning/info/"
            })
                .success(function (data) {
                    $scope.loading = false;
                    for (var key in data.api_response.hosts) {
                        var host = data.api_response.hosts[key];
                        $scope.host_list.push(host);
                        $scope.total_cpu += host.cores;
                        $scope.total_ram += host.memory;
                    }

                    $scope.service_list = data.api_response.services;
                    $scope.vm_list = data.api_response.vms;
                    $timeout(function () {
                        $(".slider_item").each(function () {
                            var ctrl = this;
                            $scope.resource_allocation[ctrl.id] = 0;
                            var html_ctrl = $("#" + ctrl.id);
                            html_ctrl.slider().on('slide', function (ev) {
                                $timeout(function () {
                                    $scope.resource_allocation[ctrl.id] = ev.value;
                                    $scope.recalculate_gauges();
                                }, 0);
                            });
                            html_ctrl.slider('setValue', 0);
                        });
                        var flex_ctrl = $("#flex");
                        flex_ctrl.slider({min: 0, max: $scope.host_list.length}).on('slide', function (ev) {
                            $timeout(function () {
                                $scope.flex_count = ev.value;
                                $scope.recalculate_gauges();
                            }, 0);
                        });
                        flex_ctrl.slider('setValue', 0);
                        $("#input_flex").attr({max: $scope.host_list.length});

                        $scope.ready = true;
                    }, 0);
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

            $scope.cpu_gauge = create_gauge('cpu');
            $scope.cpu_gauge.render();
            $scope.cpu_gauge.moveTo($scope.cpu_gauge_val);
            $scope.ram_gauge = create_gauge('ram');
            $scope.ram_gauge.render();
            $scope.ram_gauge.moveTo($scope.ram_gauge_val);
        };
    });
