/* global angular */
'use strict';

/**
 * Main App Module
 */

var app = angular.module('app', ['utils', 'search', 'ngAnimate', 'ui.bootstrap', 'ngSanitize', 'ui.select'])
    .controller('ALController', function ($scope, $http) {
        //Parameters vars
        $scope.user = null;
        $scope.loading = false;
        $scope.loading_extra = false;
        $scope.alert_key = null;
        $scope.alert = null;
        $scope.alert_idx = 0;
        $scope.label_suggestions = ['PHISHING', 'COMPROMISE', 'CRIME', 'ATTRIBUTED', 'WHITELISTED',
            'FALSE_POSITIVE', 'REPORTED', 'MITIGATED', 'PENDING'];

        $scope.banned = [
            "__access_grp1__",
            "__access_grp2__",
            "__access_lvl__",
            "__access_req__",
            "__expiry_ts__",
            "classification",
            "event_id",
            "extended_scan",
            "filename",
            "group_count",
            "label",
            "md5",
            "priority",
            "reporting_ts",
            "sha1",
            "sha256",
            "sid",
            "size",
            "al_attrib",
            "al_av",
            "al_domain",
            "al_domain_dynamic",
            "al_domain_static",
            "al_ip",
            "al_ip_dynamic",
            "al_ip_static",
            "al_request_end_time",
            "al_score",
            "status",
            "summary",
            "ts",
            "type",
            "yara"
        ];

        $scope.has_meta = function (alert) {
            for (var k in alert) {
                if ($scope.banned.indexOf(k) == -1) {
                    return true;
                }
            }

            return false;
        };
        $scope.get_alert_meta = function (alert) {
            var out = {};

            for (var k in alert) {
                if ($scope.banned.indexOf(k) == -1) {
                    out[k] = alert[k];
                }
            }

            return out;
        };

        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        //Error handling
        $scope.error = '';

        $scope.has_items = function (variable) {
            return variable !== undefined && variable.length >= 1;
        };

        $scope.list_related_alerts = function (alert) {
            if (alert && (alert.group_count === undefined || alert.group_count == null)) {
                $scope.last_params = {q: "event_id:" + alert.event_id};
                $scope.related_ids = [alert.event_id];
                $("#related_ids_mdl").modal('show');
            }
            else {
                var params = {
                    q: $scope.filter,
                    tc: $scope.time_slice,
                    start: $scope.start_time,
                    fq: $scope.filter_queries.slice()
                };

                if (alert) {
                    params.fq.push($scope.group_by + ":" + alert[$scope.group_by]);
                }

                $scope.last_params = params;

                $http({
                    method: 'GET',
                    url: "/api/v3/alert/related/",
                    params: params
                })
                    .success(function (data) {
                        $scope.related_ids = data.api_response;
                        $("#related_ids_mdl").modal('show');
                    })
                    .error(function (data) {
                        $timeout(function () {
                            swal({
                                title: "Error while generating list of IDs.",
                                text: data.api_error_message,
                                type: "error",
                                showCancelButton: false,
                                confirmButtonColor: "#d9534f",
                                confirmButtonText: "Dismiss",
                                closeOnConfirm: true
                            });
                        }, 250);
                    });
            }
        };

        $scope.take_ownership = function (alert, alert_idx) {
            swal({
                    title: "Take ownership",
                    text: "\n\nDo you want to take ownership of this alert?\n\n",
                    type: "info",
                    showCancelButton: true,
                    confirmButtonColor: "#d9534f",
                    confirmButtonText: "Yes, do it!",
                    closeOnConfirm: true
                },
                function () {
                    var ctrl = $("#" + alert_idx + "_ownership");
                    var disabled = ctrl.attr('disabled');
                    if (disabled === undefined && disabled == false) {
                        return;
                    }

                    ctrl.attr("disabled", "disabled");
                    ctrl.text("Taking Ownership...");

                    $http({
                        method: 'GET',
                        url: "/api/v3/alert/ownership/" + alert.event_id + "/"
                    })
                        .success(function () {
                            ctrl.text("Has ownership");
                            $scope.alert['owner'] = $scope.user.uname;
                        })
                        .error(function (data) {
                            ctrl.removeClass("btn-default");
                            ctrl.addClass("btn-danger");
                            ctrl.removeAttr('disabled');
                            ctrl.text("Error: " + data.api_error_message + " (Retry?)");
                        });
                });

        };

        $scope.count_similar = function (alert, alert_idx) {
            var ctrl = $("#" + alert_idx + "_similar");
            var disabled = ctrl.attr('disabled');
            if (disabled === undefined && disabled == false) {
                return;
            }

            ctrl.attr("disabled", "disabled");
            ctrl.removeClass("btn-danger");
            ctrl.addClass("btn-default");
            ctrl.text("Counting alerts...");

            var url = "/api/v3/search/advanced/alert/?q=md5:\"" + alert['md5'] + "\"&rows=0";
            $http({method: 'GET', url: url})
                .success(function (data) {
                    ctrl.removeClass("btn-default");
                    ctrl.addClass("btn-primary");
                    ctrl.text(data.api_response.response.numFound + " similar alerts")
                })
                .error(function (data) {
                    ctrl.removeClass("btn-default");
                    ctrl.addClass("btn-danger");
                    ctrl.removeAttr('disabled');
                    ctrl.text("Error: " + data.api_error_message + " (Retry?)");
                });
        };

        $scope.workflow_action = function (action) {
            if (action.priority) {
                $http({
                    method: 'GET',
                    url: "/api/v3/alert/priority/" + $scope.alert.event_id + "/" + action.priority + "/"
                })
                    .success(function () {
                        $scope.alert['priority'] = action.priority;
                        $scope.user_input = null;
                        $scope.last_error = "";
                    })
                    .error(function (data) {
                        if (data.api_error_message.indexOf("already has") == -1) {
                            $scope.last_error = data.api_error_message;
                        }
                    });
            }
            if (action.status) {
                $http({
                    method: 'GET',
                    url: "/api/v3/alert/status/" + $scope.alert.event_id + "/" + action.status + "/"
                })
                    .success(function () {
                        $scope.alert['status'] = action.status;
                        $scope.user_input = null;
                        $scope.last_error = "";
                    })
                    .error(function (data) {
                        if (data.api_error_message.indexOf("already has") == -1) {
                            $scope.last_error = data.api_error_message;
                        }
                    });
            }
            if (action.label.length > 0) {
                $http({
                    method: 'GET',
                    url: "/api/v3/alert/label/" + $scope.alert.event_id + "/" + action.label.join(",") + "/"
                })
                    .success(function () {
                        if ($scope.alert['label'] === undefined) {
                            $scope.alert['label'] = []
                        }
                        for (var i in action.label) {
                            var label = action.label[i];
                            if ($scope.alert['label'].indexOf(label) == -1) {
                                $scope.alert['label'].push(label);
                            }
                        }
                        $scope.user_input = null;
                        $scope.last_error = "";
                    })
                    .error(function (data) {
                        if (data.api_error_message.indexOf("already has") == -1) {
                            $scope.last_error = data.api_error_message;
                        }
                    });
            }

            $("#worflow_action").modal('hide');
        };

        $scope.$watch('last_error', function () {
            if ($scope.last_error) {
                swal({
                    title: "ERROR",
                    text: $scope.last_error,
                    type: "error",
                    closeOnConfirm: true
                })
            }
        });


        $scope.prompt_workflow_action = function () {
            $scope.user_input = {
                label: [],
                priority: '',
                status: ''
            };
            $scope.last_error = "";
            $("#worflow_action").modal('show');
        };

        //Load params from datastore
        $scope.start = function () {
            $scope.loading_extra = true;
            $http({
                method: 'GET',
                url: "/api/v3/alert/" + $scope.alert_key + "/"
            })
                .success(function (data) {
                    $scope.alert = data.api_response;
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
        };

    });

