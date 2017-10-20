/* global angular */
'use strict';

/**
 * Main App Module
 */
var app = angular.module('app', ['search', 'utils', 'ui.bootstrap'])
    .controller('ALController', function ($scope, $http, $timeout) {
        //Parameters vars
        $scope.service_list = null;
        $scope.user = null;
        $scope.loading = false;
        $scope.loading_extra = false;
        $scope.current_service = null;
        $scope.started = false;
        $scope.new_service = false;

        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        //Error handling
        $scope.error = '';
        $scope.success = '';

        $scope.typeOf = function (val) {
            return typeof val;
        };

        $scope.add_service_modal = function () {
            $scope.new_service = true;
            $scope.current_service = {
                accepts: ".*",
                classpath: "al_services.alsvc_",
                cpu_cores: 1,
                ram_mb: 1024,
                enabled: true,
                name: "",
                timeout: 60,
                type: "service",
                supported_platforms: ["Linux", "Windows"],
                category: "Static Analysis",
                groups: ["DEFAULT"],
                config: {},
                stage: "CORE",
                submission_params: [],
                install_by_default: false
            };
            // Reset variables
            $scope.spec_temp = {
                type: "bool",
                list: [],
                default: false,
                name: ""
            };
            $scope.spec_error = "";

            $scope.conf_temp = {
                type: "str",
                key: "",
                val: ""
            };

            $("#spec_default").val("false");
            $("#conf_temp_val").val("");

            $scope.error = '';
            $scope.success = '';
            $("#myModal").modal('show');
        };

        $scope.del = function () {
            swal({
                    title: "Delete Service?",
                    text: "You are about to delete the current service. Are you sure?",
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
            $scope.loading_extra = true;
            $scope.error = '';
            $scope.success = '';

            $http({
                method: 'DELETE',
                url: "/api/v3/service/" + $scope.current_service.name + "/"
            })
                .success(function () {
                    $scope.loading_extra = false;
                    $("#myModal").modal('hide');
                    $scope.success = "Service " + $scope.current_service.name + " successfully deleted!";
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

        $scope.editService = function (service) {
            $scope.new_service = false;
            $scope.loading_extra = true;
            $scope.error = '';
            $scope.saved = '';

            // Reset variables
            $scope.spec_temp = {
                type: "bool",
                list: [],
                default: false,
                name: ""
            };
            $scope.spec_error = "";

            $scope.conf_temp.type = "str";
            $scope.conf_temp.key = "";
            $scope.conf_temp.val = "";

            $("#spec_default").val("false");
            $("#conf_temp_val").val("");

            $http({
                method: 'GET',
                url: "/api/v3/service/" + service.name + "/"
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.current_service = data.api_response;
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

            for (var idx in $scope.current_service.submission_params) {
                $scope.current_service.submission_params[idx].value = $scope.current_service.submission_params[idx].default;
            }

            $http({
                method: 'POST',
                url: "/api/v3/service/" + $scope.current_service.name + "/",
                data: $scope.current_service
            })
                .success(function () {
                    $scope.loading_extra = false;
                    $("#myModal").modal('hide');
                    $scope.success = "Service " + $scope.current_service.name + " successfully updated!";
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

            for (var idx in $scope.current_service.submission_params) {
                $scope.current_service.submission_params[idx].value = $scope.current_service.submission_params[idx].default;
            }

            $http({
                method: 'PUT',
                url: "/api/v3/service/" + $scope.current_service.name + "/",
                data: $scope.current_service
            })
                .success(function () {
                    $scope.loading_extra = false;
                    $("#myModal").modal('hide');
                    $scope.success = "Service " + $scope.current_service.name + " successfully added!";
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
            $scope.load_data();
        };

        //Pager methods
        $scope.load_data = function () {
            $scope.loading_extra = true;

            $http({
                method: 'GET',
                url: "/api/v3/service/list/"
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.service_list = data.api_response;
                    $scope.started = true;
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (data == "" || status == 400) {
                        $scope.service_list = [];
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

            $http({
                method: 'GET',
                url: "/api/v3/service/constants/"
            })
                .success(function (data) {
                    $scope.service_constants = data.api_response;
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

        //Toggle os on or off
        $scope.toggleOS = function toggleOS(osName) {
            var idx = $scope.current_service.supported_platforms.indexOf(osName);

            if (idx > -1) {
                $scope.current_service.supported_platforms.splice(idx, 1);
            }
            else {
                $scope.current_service.supported_platforms.push(osName);
            }
        };

        //Service Specific functions/vars
        $scope.spec_temp = {
            type: "bool",
            list: [],
            default: false,
            name: ""
        };
        $scope.spec_error = "";

        $scope.remove_specific = function (name) {
            for (var idx in $scope.current_service.submission_params) {
                if ($scope.current_service.submission_params[idx].name == name) {
                    $scope.current_service.submission_params.splice(idx, 1);
                    break;
                }
            }

        };

        $scope.add_specific = function () {
            for (var idx in $scope.current_service.submission_params) {
                if ($scope.current_service.submission_params[idx].name == $scope.spec_temp.name) {
                    $scope.spec_error = "This user specified parameter name already exists.";
                    $("#new_spec_name").addClass("has-error");
                    return;
                }
            }
            if ($scope.spec_temp.name == "" || $scope.spec_temp.name == null) {
                $scope.spec_error = "Name field is required.";
                $("#new_spec_name").addClass("has-error");
                return;
            }

            var temp = {
                'name': $scope.spec_temp.name,
                'type': $scope.spec_temp.type,
                'default': $scope.spec_temp.default,
                'value': $scope.spec_temp.default
            };
            if ($scope.spec_temp.type == 'list') {
                temp['list'] = $scope.spec_temp.list;
            }

            $scope.current_service.submission_params.push(temp);

            $scope.spec_temp = {
                type: "bool",
                list: [],
                default: false,
                name: ""
            };

            $scope.spec_error = "";
        };

        $scope.$watch('spec_error', function () {
            if ($scope.spec_error == "") {
                $("#new_spec_name").removeClass("has-error");
                $("#new_spec_type").removeClass("has-error");
                $("#new_spec_default").removeClass("has-error");
            }

        });

        $scope.$watch('spec_temp.type', function () {
            if ($scope.spec_temp.type == "bool") {
                $scope.spec_temp.default = false;
                $("#spec_default").val("false");
            }
            else if ($scope.spec_temp.type == "list") {
                $scope.spec_temp.list = [];
                $scope.spec_temp.default = "";
                $("#spec_default").val("");
            }
            else if ($scope.spec_temp.type == "int") {
                $scope.spec_temp.default = 1;
                $("#spec_default").val("1");
            }
            else {
                $scope.spec_temp.default = "";
                $("#spec_default").val("");
            }
        });

        //Evironment Variables functions/vars
        $scope.conf_temp = {
            type: "str",
            key: "",
            val: ""
        };

        $scope.remove_meta = function (key) {
            delete $scope.current_service.config[key];
        };

        $scope.add_meta = function () {
            if ($scope.conf_temp.key in $scope.current_service.config) {
                $scope.conf_temp_error = "This environement variable name already exists.";
                $("#new_conf_temp_key").addClass("has-error");
                return
            }

            if ($scope.conf_temp.key == "" || $scope.conf_temp.key == null) {
                $scope.conf_temp_error = "Environment variable name is required.";
                $("#new_conf_temp_key").addClass("has-error");
                return;
            }
            $scope.current_service.config[$scope.conf_temp.key] = $scope.conf_temp.val;

            $scope.conf_temp = {
                type: "str",
                key: "",
                val: ""
            };
        };

        $scope.$watch('conf_temp_error', function () {
            if ($scope.conf_temp_error == "") {
                $("#new_conf_temp_key").removeClass("has-error");
                $("#new_conf_temp_type").removeClass("has-error");
                $("#new_conf_temp_val").removeClass("has-error");
            }

        });

        $scope.$watch('conf_temp.type', function () {
            if ($scope.conf_temp.type == "bool") {
                $scope.conf_temp.val = false;
                $("#conf_temp_val").val("false");
            }
            else if ($scope.conf_temp.type == "list") {
                $scope.conf_temp.val = [];
                $("#conf_temp_val").val("");
            }
            else if ($scope.conf_temp.type == "int") {
                $scope.conf_temp.val = 1;
                $("#conf_temp_val").val("1");
            }
            else if ($scope.conf_temp.type == "json") {
                $scope.conf_temp.val = {};
                $("#conf_temp_val").val("1");
            }
            else {
                $scope.conf_temp.val = "";
                $("#conf_temp_val").val("");
            }
        });
    });
