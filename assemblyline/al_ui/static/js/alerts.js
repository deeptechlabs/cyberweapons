/* global angular */
'use strict';

/**
 * Main App Module
 */
var app = angular.module('app', ['utils', 'search', 'infinite-scroll', 'ui.bootstrap', 'ngSanitize', 'ui.select'])
    .controller('ALController', function ($scope, $http, $timeout) {
        //Parameters vars
        $scope.user = null;
        $scope.loading = false;
        $scope.loading_extra = false;
        $scope.alert_list = null;
        $scope.started = false;
        $scope.filtered = false;
        $scope.filter = "";
        $scope.time_slice_array = [{value: "", name: "None (slow)"},
            {value: "24HOUR", name: "24 Hours"},
            {value: "4DAY", name: "4 Days"},
            {value: "7DAY", name: "1 Week"}];
        $scope.time_slice = $scope.time_slice_array[2].value;
        $scope.start_time = null;
        $scope.label_suggestions = ['PHISHING', 'COMPROMISE', 'CRIME', 'ATTRIBUTED', 'WHITELISTED',
            'FALSE_POSITIVE', 'REPORTED', 'MITIGATED', 'PENDING'];

        $scope.total = 0;
        $scope.offset = 0;
        $scope.count = 25;
        $scope.filtering_group_by = [];
        $scope.non_filtering_group_by = [];
        $scope.group_by = 'md5';
        $scope.counted_total = 0;
        $scope.view_type = "grouped";
        $scope.filter_queries = [];
        $scope.forced_filter = "";
        $scope.field_fq = null;
        $scope.current_alert_idx = null;
        $scope.current_alert = null;
        $scope.modal_error = null;
        $scope.user_input = null;
        $scope.related_ids = null;
        $scope.last_params = null;

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

        $scope.showmenu = false;
        $scope.toggleMenu = function () {
            $scope.showmenu = (!$scope.showmenu);
        };
        $scope.forceOpenMenu = function () {
            if ($scope.showmenu == false) {
                $scope.showmenu = true;
            }
        };

        $scope.getKeys = function (o) {
            try {
                return Object.keys(o);
            } catch (ex) {
                return [];
            }
        };

        $scope.getToday = function () {
            var today = new Date();
            var dd = today.getDate();
            if (dd < 10) {
                dd = '0' + dd;
            }
            else {
                dd = '' + dd;
            }
            var mm = today.getMonth() + 1;
            if (mm < 10) {
                mm = '0' + mm;
            }
            else {
                mm = '' + mm;
            }
            return today.getFullYear() + mm + dd;
        };

        $scope.has_items = function (variable) {
            return variable !== undefined && variable.length >= 1;
        };

        $scope.workflow_action = function (action) {
            if ($scope.current_alert && ($scope.current_alert.group_count === undefined || $scope.current_alert.group_count == null)) {
                if (action.priority) {
                    $http({
                        method: 'GET',
                        url: "/api/v3/alert/priority/" + $scope.current_alert.event_id + "/" + action.priority + "/"
                    })
                        .success(function () {
                            $scope.alert_list[$scope.current_alert_idx]['priority'] = action.priority;
                            $scope.user_input = null;
                            $scope.last_error = "";
                        })
                        .error(function (data) {
                            $scope.last_error = data.api_error_message;
                        });
                }
                if (action.status) {
                    $http({
                        method: 'GET',
                        url: "/api/v3/alert/status/" + $scope.current_alert.event_id + "/" + action.status + "/"
                    })
                        .success(function () {
                            $scope.alert_list[$scope.current_alert_idx]['status'] = action.status;
                            $scope.user_input = null;
                            $scope.last_error = "";
                        })
                        .error(function (data) {
                            $scope.last_error = data.api_error_message;
                        });
                }
                if (action.label.length > 0) {
                    $http({
                        method: 'GET',
                        url: "/api/v3/alert/label/" + $scope.current_alert.event_id + "/" + action.label.join(",") + "/"
                    })
                        .success(function () {
                            if ($scope.alert_list[$scope.current_alert_idx]['label'] === undefined) {
                                $scope.alert_list[$scope.current_alert_idx]['label'] = []
                            }
                            for (var i in action.label) {
                                var label = action.label[i];
                                if ($scope.alert_list[$scope.current_alert_idx]['label'].indexOf(label) == -1) {
                                    $scope.alert_list[$scope.current_alert_idx]['label'].push(label);
                                }
                            }
                            $scope.user_input = null;
                            $scope.last_error = "";
                        })
                        .error(function (data) {
                            $scope.last_error = data.api_error_message;
                        });
                }
            }
            else {
                var params = {
                    q: $scope.filter,
                    tc: $scope.time_slice,
                    start: $scope.start_time,
                    fq: $scope.filter_queries.slice()
                };

                if ($scope.current_alert) {
                    params.fq.push($scope.group_by + ":" + $scope.current_alert[$scope.group_by]);
                }

                if (action.priority) {
                    $http({
                        method: 'GET',
                        url: "/api/v3/alert/priority/batch/" + action.priority + "/",
                        params: params
                    })
                        .success(function () {
                            if ($scope.current_alert_idx !== undefined) {
                                $scope.alert_list[$scope.current_alert_idx]['priority'] = action.priority;
                            }
                            else {
                                for (var idx in $scope.alert_list) {
                                    $scope.alert_list[idx]['priority'] = action.priority;
                                }
                            }
                            $scope.user_input = null;
                            $scope.last_error = "";
                        })
                        .error(function (data) {
                            $scope.last_error = data.api_error_message;
                        });
                }
                if (action.status) {
                    $http({
                        method: 'GET',
                        url: "/api/v3/alert/status/batch/" + action.status + "/",
                        params: params
                    })
                        .success(function () {
                            if ($scope.current_alert_idx !== undefined) {
                                $scope.alert_list[$scope.current_alert_idx]['status'] = action.status;
                            }
                            else {
                                for (var idx in $scope.alert_list) {
                                    $scope.alert_list[idx]['status'] = action.status;
                                }
                            }
                            $scope.user_input = null;
                            $scope.last_error = "";
                        })
                        .error(function (data) {
                            $scope.last_error = data.api_error_message;
                        });
                }
                if (action.label.length > 0) {
                    $http({
                        method: 'GET',
                        url: "/api/v3/alert/label/batch/" + action.label.join(",") + "/",
                        params: params
                    })
                        .success(function () {
                            if ($scope.current_alert_idx !== undefined) {
                                if ($scope.alert_list[$scope.current_alert_idx]['label'] === undefined) {
                                    $scope.alert_list[$scope.current_alert_idx]['label'] = []
                                }
                                for (var i in action.label) {
                                    var label = action.label[i];
                                    if ($scope.alert_list[$scope.current_alert_idx]['label'].indexOf(label) == -1) {
                                        $scope.alert_list[$scope.current_alert_idx]['label'].push(label);
                                    }
                                }
                            }
                            else {
                                for (var idx in $scope.alert_list) {
                                    if ($scope.alert_list[idx]['label'] === undefined) {
                                        $scope.alert_list[idx]['label'] = []
                                    }
                                    for (var x in action.label) {
                                        var label_item = action.label[x];
                                        if ($scope.alert_list[idx]['label'].indexOf(label_item) == -1) {
                                            $scope.alert_list[idx]['label'].push(label_item);
                                        }
                                    }
                                }
                            }
                            $scope.user_input = null;
                            $scope.last_error = "";
                        })
                        .error(function (data) {
                            $scope.last_error = data.api_error_message;
                        });
                }
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


        $scope.prompt_workflow_action = function (alert, alert_idx) {
            $scope.current_alert_idx = alert_idx;
            $scope.current_alert = alert;
            $scope.user_input = {
                label: [],
                priority: '',
                status: ''
            };
            $scope.last_error = "";
            $("#worflow_action").modal('show');
        };

        $scope.take_ownership = function (alert, alert_idx) {
            if (alert && (alert.group_count === undefined || alert.group_count == null)) {
                swal({
                        title: "Take ownership",
                        text: "\n\nDo you want to take ownership of this alert?\n\n" + alert.event_id,
                        type: "info",
                        showCancelButton: true,
                        confirmButtonColor: "#d9534f",
                        confirmButtonText: "Yes, do it!",
                        closeOnConfirm: true
                    },
                    function () {
                        $http({
                            method: 'GET',
                            url: "/api/v3/alert/ownership/" + alert.event_id + "/"
                        })
                            .success(function () {
                                $scope.alert_list[alert_idx]['owner'] = $scope.user.uname;
                            })
                            .error(function (data) {
                                $timeout(function () {
                                    swal({
                                        title: "Error while taking ownership",
                                        text: data.api_error_message,
                                        type: "error",
                                        showCancelButton: false,
                                        confirmButtonColor: "#d9534f",
                                        confirmButtonText: "Dismiss",
                                        closeOnConfirm: true
                                    });
                                }, 250);
                            });
                    });
            }
            else {
                var params = {
                    q: $scope.filter,
                    tc: $scope.time_slice,
                    start: $scope.start_time,
                    fq: $scope.filter_queries.slice()
                };

                var text = "\n\nDo you want to take ownership of all " + $scope.total + " alert(s) filtered in the current view?";
                if (alert) {
                    params.fq.push($scope.group_by + ":" + alert[$scope.group_by]);
                    text = "\n\nDo you want to take ownership of " + alert.group_count + " alert(s) related to this " + $scope.group_by + "?\n\n" + alert[$scope.group_by];
                }

                swal({
                        title: "Multiple Take ownership",
                        text: text,
                        type: "warning",
                        showCancelButton: true,
                        confirmButtonColor: "#d9534f",
                        confirmButtonText: "Yes, do it!",
                        closeOnConfirm: true
                    },
                    function () {
                        $http({
                            method: 'GET',
                            url: "/api/v3/alert/ownership/batch/",
                            params: params
                        })
                            .success(function () {
                                if (alert_idx) {
                                    $scope.alert_list[alert_idx]['owner'] = $scope.user.uname;
                                }
                                else {
                                    for (var idx in $scope.alert_list) {
                                        $scope.alert_list[idx]['owner'] = $scope.user.uname;
                                    }
                                }
                            })
                            .error(function (data) {
                                $timeout(function () {
                                    swal({
                                        title: "Error while taking ownership",
                                        text: data.api_error_message,
                                        type: "error",
                                        showCancelButton: false,
                                        confirmButtonColor: "#d9534f",
                                        confirmButtonText: "Dismiss",
                                        closeOnConfirm: true
                                    });
                                }, 250);
                            });
                    });
            }
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

        $scope.lock_in_timestamp = function (alert) {
            $scope.filter_queries.push("reporting_ts:[" + alert.reporting_ts + " TO *]");
            $scope.gen_forced_filter(false);
            var url = "/alerts.html?filter=" + $scope.filter + "&time_slice=" + $scope.time_slice + "&view_type=" + $scope.view_type + "&group_by=" + $scope.group_by;
            for (var key in $scope.filter_queries) {
                var fq = $scope.filter_queries[key];
                url += "&fq=" + fq;
            }
            window.location = url;
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

            var url = "/api/v3/search/advanced/alert/?q=" + $scope.group_by + ":\"" + alert[$scope.group_by] + "\"&rows=0";
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

        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        //Error handling
        $scope.error = '';
        $scope.invalid_query = "";

        $scope.filterData = function (searchText) {
            var url = "/alerts.html?filter=" + searchText + "&time_slice=" + $scope.time_slice + "&view_type=" + $scope.view_type + "&group_by=" + $scope.group_by;
            for (var key in $scope.filter_queries) {
                var fq = $scope.filter_queries[key];
                url += "&fq=" + fq;
            }

            window.location = url;
        };

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

        //Load params from datastore
        $scope.start = function () {
            $scope.filter = decodeURI($scope.filter);
            $scope.offset -= $scope.count;
            for (var key in $scope.filter_queries) {
                $scope.filter_queries[key] = decodeURI($scope.filter_queries[key]);
            }
            $scope.gen_forced_filter(true);
            $scope.possible_group_by = $scope.filtering_group_by.concat($scope.non_filtering_group_by).sort();
        };

        $scope.gen_forced_filter = function (do_count) {
            $scope.forced_filter = "";
            for (var key in $scope.filter_queries) {
                var fq = $scope.filter_queries[key];
                if (fq.indexOf($scope.group_by + ":\"") != -1) {
                    $scope.field_fq = fq;
                }
                $scope.forced_filter += "&fq=" + fq;
            }
            if ($scope.view_type == 'list' && $scope.start_time) {
                $scope.forced_filter += "&start_time=" + $scope.start_time;
                if ($scope.field_fq != null && do_count) {
                    $scope.count_instances();
                }
            }
        };

        $scope.getNextAlertPage = function () {
            $scope.offset += $scope.count;
            $scope.load_data();
        };

        $scope.clear_forced_filter = function () {
            var url = "";

            if ($scope.view_type == "list") {
                var new_fq = [];
                for (var fq_key in $scope.filter_queries) {
                    var item = $scope.filter_queries[fq_key];
                    if (item.indexOf($scope.group_by + ":") != -1) {
                        new_fq.push(item);
                    }
                }

                url = "/alerts.html?filter=" + $scope.filter + "&time_slice=&view_type=" + $scope.view_type + "&group_by=" + $scope.group_by;
                for (var key in new_fq) {
                    var fq = new_fq[key];
                    url += "&fq=" + fq;
                }
            }
            else {
                url = "/alerts.html?filter=" + $scope.filter + "&time_slice=" + $scope.time_slice + "&view_type=" + $scope.view_type + "&group_by=" + $scope.group_by;
            }

            window.location = url;
        };

        $scope.count_instances = function () {
            var url = "/api/v3/search/alert/?query=" + $scope.field_fq + "&length=0";

            $scope.loading_extra = true;

            $http({
                method: 'GET',
                url: url
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.total_instances = data.api_response.total;
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (data == "") return;

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                });
        };

        $scope.load_data = function () {
            var url = null;
            var url_params = "?offset=" + $scope.offset + "&length=" + $scope.count + "&filter=" + $scope.filter;

            $scope.loading_extra = true;
            if ($scope.view_type == "list") {
                url = "/api/v3/alert/list/";
            }
            else {
                url = "/api/v3/alert/grouped/" + $scope.group_by + "/";
            }

            if ($scope.start_time != null) {
                url_params += "&start_time=" + $scope.start_time;
            }

            if ($scope.time_slice != "") {
                url_params += "&time_slice=" + $scope.time_slice;
            }

            for (var key in $scope.filter_queries) {
                var fq = $scope.filter_queries[key];
                url_params += "&fq=" + fq;
            }

            url += url_params;

            $http({
                method: 'GET',
                url: url
            })
                .success(function (data) {
                    $scope.loading_extra = false;

                    if (!$scope.started) {
                        $scope.alert_list = []
                    }
                    Array.prototype.push.apply($scope.alert_list, data.api_response.items);
                    $scope.total = data.api_response.total;
                    if ($scope.view_type != "list") {
                        $scope.counted_total += data.api_response.counted_total;
                        $scope.start_time = data.api_response.start_time;
                    }
                    else {
                        $scope.counted_total += data.api_response.items.length;
                    }
                    $scope.started = true;

                    $scope.filtered = (($scope.filter != "*" && $scope.filter != "") || $scope.time_slice != "" || $scope.forced_filter != "" || $scope.filtering_group_by.indexOf($scope.group_by) != -1);
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (data == "") return;

                    if (status == 400) {
                        $timeout(function () {
                            $("#search-term").addClass("has-error");
                            var sb = $("#search-box");
                            sb.select();
                            sb.focus();
                        }, 0);

                        $scope.invalid_query = data.api_error_message;

                        $scope.alert_list = [];
                        $scope.total = 0;
                        $scope.filtered = true;
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

            $scope.stats_url = "/api/v3/alert/statistics/" + url_params + "&fq=" + $scope.group_by + ":*";
            $scope.labels_url = "/api/v3/alert/labels/" + url_params + "&fq=" + $scope.group_by + ":*";
            $scope.statuses_url = "/api/v3/alert/statuses/" + url_params + "&fq=" + $scope.group_by + ":*";
            $scope.priorities_url = "/api/v3/alert/priorities/" + url_params + "&fq=" + $scope.group_by + ":*";

            if ($scope.view_type != "list") {
                $scope.get_labels();
                $scope.get_statuses();
                $scope.get_priorities();
            }

        };

        $scope.get_labels = function () {
            $scope.loading_extra = true;
            $http({
                method: 'GET',
                url: $scope.labels_url
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.current_labels = data.api_response;
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (data == "") return;

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                    $scope.started = true;

                });
        };

        $scope.get_priorities = function () {
            $scope.loading_extra = true;
            $http({
                method: 'GET',
                url: $scope.priorities_url
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.current_priorities = data.api_response;
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (data == "") return;

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                    $scope.started = true;

                });
        };

        $scope.get_statuses = function () {
            $scope.loading_extra = true;
            $http({
                method: 'GET',
                url: $scope.statuses_url
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.current_statuses = data.api_response;
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (data == "") return;

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                    $scope.started = true;

                });
        };

        $scope.show_statistics = function () {
            $scope.loading_extra = true;
            $http({
                method: 'GET',
                url: $scope.stats_url
            })
                .success(function (data) {
                    $scope.loading_extra = false;

                    $scope.statistics = data.api_response;
                    $("#statsModal").modal('show');
                    $timeout(function () {
                        $scope.overflows();
                    }, 0);
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (data == "") return;

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                    $scope.started = true;

                });
        };

        $scope.expand = function (id) {
            $("#" + id).removeClass("expandable-tags");
            $("#" + id + "_expand").addClass("ng-hide");
        };

        $scope.overflows = function () {
            var skipped = 0;
            for (var stat_id in $scope.statistics) {
                var target = $("#" + stat_id)[0];
                if (target.scrollHeight == 0) {
                    skipped += 1;
                    continue;
                }
                if (target.offsetHeight >= target.scrollHeight &&
                    target.offsetWidth >= target.scrollWidth) {
                    $scope.expand(stat_id);
                }
            }
            if (skipped == $scope.getKeys($scope.statistics).length) {
                $timeout(function () {
                    $scope.overflows();
                }, 0);
            }
        };

        window.onunload = function () {
        };
    });

