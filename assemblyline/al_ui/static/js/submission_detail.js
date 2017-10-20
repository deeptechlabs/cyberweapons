/* global angular */
'use strict';

/**
 * Main App Module
 */

var app = angular.module('app', ['utils', 'search', 'ngAnimate', 'socket-io', 'ui.bootstrap'])
    .factory('mySocket', function (socketFactory) {
        var mySocket = socketFactory();
        mySocket.forward('error');
        mySocket.forward('start');
        mySocket.forward('stop');
        mySocket.forward('cachekey');
        mySocket.forward('cachekeyerr');
        return mySocket;
    })
    .controller('ALController', function ($scope, $http, $window, $location, $timeout, mySocket) {
        //Parameters vars
        $scope.user = null;
        $scope.options = null;
        $scope.loading = false;
        $scope.loading_extra = false;
        $scope.data = null;
        $scope.temp_data = null;
        $scope.sid = null;
        $scope.wq = null;
        $scope.summary = null;
        $scope.file_tree = null;
        $scope.tag_map = null;
        $scope.messages = [];
        $scope.messages_error = [];
        $scope.temp_res = Object();
        $scope.temp_errors = Object();
        $scope.file_res = Object();
        $scope.file_errors = Object();
        $scope.file_highlight = null;
        $scope.selected_highlight = [];
        $scope.splitter = "__";
        $scope.showslider = false;
        $scope.current_file = null;
        $scope.backto = 0;
        $scope.final_timeout_count = 0;
        $scope.completed = false;
        $scope.started = false;
        $scope.slide_done = false;
        $scope.redraw_rate = 3000;
        $scope.run_count = 0;
        $scope.num_files = 0;
        $scope.temp_keys = {error: [], result: []};
        $scope.outstanding = null;

        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        //Filters
        var tagTypes = [];
        $scope.tagTypeList = function (myTagList) {
            tagTypes = [];
            if (myTagList === undefined || myTagList == null) return [];
            return myTagList;
        };

        $scope.filterTagType = function (tag) {
            var isNewType = tagTypes.indexOf(tag.type) == -1;
            if (isNewType) {
                tagTypes.push(tag.type);
            }
            return isNewType;
        };

        $scope.useless_results = function () {
            return function (item) {
                return !(item.result.score == 0 && item.result.sections.length == 0 && item.result.tags.length == 0 && item.response.extracted.length == 0);

            }
        };

        $scope.good_results = function () {
            return function (item) {
                return item.result.score == 0 && item.result.sections.length == 0 && item.result.tags.length == 0 && item.response.extracted.length == 0;

            }
        };

        $scope.futile_errors = function (error_list) {
            var out = {MAX_DEPTH_REACHED: [], MAX_FILES_REACHED: [], MAX_RETRY_REACHED: [], SERVICE_DOWN: []};
            for (var idx in error_list) {
                var key = error_list[idx];
                var ehash = key.substr(65, key.length);
                var srv = key.substr(65, key.length);

                if (srv.indexOf(".") != -1) {
                    srv = srv.substr(0, srv.indexOf("."));
                }
                if (ehash.indexOf(".e") != -1) {
                    ehash = ehash.substr(ehash.indexOf(".e") + 1, ehash.length);
                }

                if (ehash == "eb54dc2e040a925f84e55e91ff27601ad") {
                    if (out["SERVICE_DOWN"].indexOf(srv) == -1) {
                        out["SERVICE_DOWN"].push(srv);
                    }
                }
                else if (ehash == "ec502020e499f01f230e06a58ad9b5dcc") {
                    if (out["MAX_RETRY_REACHED"].indexOf(srv) == -1) {
                        out["MAX_RETRY_REACHED"].push(srv);
                    }
                }
                else if (ehash == "e56d398ad9e9c4de4dd0ea8897073d430") {
                    if (out["MAX_DEPTH_REACHED"].indexOf(srv) == -1) {
                        out["MAX_DEPTH_REACHED"].push(srv);
                    }
                }
                else if (ehash == "e6e34a5b7aa6fbfb6b1ac0d35f2c44d70") {
                    if (out["MAX_FILES_REACHED"].indexOf(srv) == -1) {
                        out["MAX_FILES_REACHED"].push(srv);
                    }
                }

            }

            out.SERVICE_DOWN.sort();
            out.MAX_DEPTH_REACHED.sort();
            out.MAX_FILES_REACHED.sort();
            out.MAX_RETRY_REACHED.sort();

            return out;
        };

        $scope.relevant_errors = function (error_list) {
            var out = [];
            for (var idx in error_list) {
                var key = error_list[idx];
                var ehash = key.substr(65, key.length);

                if (ehash.indexOf(".e") != -1) {
                    ehash = ehash.substr(ehash.indexOf(".e") + 1, ehash.length);
                }

                if (ehash != "eb54dc2e040a925f84e55e91ff27601ad" && ehash != "ec502020e499f01f230e06a58ad9b5dcc" && ehash != "e56d398ad9e9c4de4dd0ea8897073d430" && ehash != "e6e34a5b7aa6fbfb6b1ac0d35f2c44d70") {
                    out.push(key);
                }
            }

            return out;
        };

        $scope.sort_by_name = function (item) {
            return item.response.service_name;
        };

        $scope.obj_len = function (o) {
            if (o === undefined || o == null) return 0;
            return Object.keys(o).length;
        };

        //Action
        $scope.uri_encode = function (val) {
            return encodeURIComponent(val)
        };

        $scope.search_tag = function (tag, value) {
            window.location = "/search.html?query=result.tags.type:" + encodeURIComponent(tag) + " AND result.tags.value:" + encodeURIComponent(value)
        };

        $scope.dump = function (obj) {
            return angular.toJson(obj, true);
        };

        $scope.delete_submission = function () {
            swal({
                    title: "Delete submission?",
                    text: "You are about to delete submission the current submission. This will delete all associated files and results.",
                    type: "warning",
                    showCancelButton: true,
                    confirmButtonColor: "#d9534f",
                    confirmButtonText: "Yes, delete it!",
                    closeOnConfirm: false
                },
                function () {
                    $("div.sweet-alert").find("button").hide();
                    swal({
                        title: "Deleting",
                        text: "Removing all related content...",
                        type: "warning"
                    });
                    $http({
                        method: 'DELETE',
                        url: "/api/v3/submission/" + $scope.sid + "/"
                    })
                        .success(function () {
                            swal("Deleted!", "Submission was succesfully deleted.", "success");
                            $timeout(function () {
                                $window.location = document.referrer;
                            }, 1500);
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

        $scope.share_submission = function () {
            swal("Share submission", "Sharing function not implemented just yet...", "info");
        };

        $scope.resubmit_dynamic_async = function (srl, sid, name) {
            $scope.error = '';
            $scope.success = '';
            $scope.loading_extra = true;

            var data = {'name': name, 'copy_sid': sid};

            $http({
                method: 'GET',
                url: "/api/v3/submit/dynamic/" + srl + "/",
                params: data
            })
                .success(function (data) {
                    $scope.loading_extra = true;
                    $scope.success = 'File successfully resubmitted for dynamic analysis. You will be redirected...';
                    $timeout(function () {
                        $scope.success = "";
                        window.location = "/submission_detail.html?sid=" + data.api_response.submission.sid;
                    }, 2000);
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

        $scope.resubmit_submission = function () {
            $scope.error = '';
            $scope.success = '';
            $scope.loading_extra = true;

            $http({
                method: 'GET',
                url: "/api/v3/submit/resubmit/" + $scope.sid + "/"
            })
                .success(function (data) {
                    $scope.loading_extra = true;
                    $scope.success = 'Current submission successfully resubmitted for analysis. You will be redirected...';
                    $timeout(function () {
                        $scope.success = "";
                        window.location = "/submission_detail.html?sid=" + data.api_response.submission.sid;
                    }, 2000);
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

        $scope.timed_redraw = function () {
            $scope.fetch_keys();
            if (!$scope.completed) {
                $timeout(function () {
                    $scope.timed_redraw()
                }, $scope.redraw_rate);
            }
        };

        //SocketIO
        $scope.$on('socket:error', function (event, data) {
            if (data.err_msg) {
                $scope.error = data.err_msg;
            }
        });
        $scope.$on('socket:start', function () {
            $scope.started = true;
            for (var idx in $scope.messages) {
                if ($scope.messages[idx] == "start") {
                    return;
                }
            }
            $scope.messages.push("start");
            sessionStorage.setItem("msg_" + $scope.sid, JSON.stringify($scope.messages));

            if ($scope.temp_data != null) {
                $scope.draw_temp_data();
            }
            $scope.timed_redraw();
        });
        $scope.$on('socket:stop', function () {
            var should_push = true;
            for (var idx in $scope.messages) {
                if ($scope.messages[idx] == "stop") {
                    if (idx < 1) {
                        should_push = false;
                    }
                }
            }
            if (should_push && $scope.messages.length != 0) {
                $scope.messages.push("stop");
                sessionStorage.setItem("msg_" + $scope.sid, JSON.stringify($scope.messages))
            }

            //That timeout is an ugly fix for an eventually consistent issues with the search index
            //generating the file scores.
            //
            //We should find a better way to fix this!
            $timeout(function () {
                $scope.get_final_data();
            }, 2000);

        });
        $scope.$on('socket:cachekey', function (event, data) {
            for (var idx in $scope.messages) {
                if ($scope.messages[idx] == data.msg) {
                    return;
                }
            }

            $scope.messages.push(data.msg);
            sessionStorage.setItem("msg_" + $scope.sid, JSON.stringify($scope.messages));

            $scope.temp_keys.result.push(data.msg)
        });
        $scope.$on('socket:cachekeyerr', function (event, data) {
            for (var idx in $scope.messages_error) {
                if ($scope.messages_error[idx] == data.msg) {
                    return;
                }
            }
            $scope.messages_error.push(data.msg);
            sessionStorage.setItem("error_" + $scope.sid, JSON.stringify($scope.messages_error));

            $scope.temp_keys.error.push(data.msg)
        });

        //Slider functions
        $scope.$watch('showslider', function () {
            if ($scope.showslider) {
                $scope.backto = $window.scrollY;
                $('body').addClass('modal-open');
            }
            else {
                $('body').removeClass('modal-open');
                $window.scrollTo(0, $scope.backto);
            }
        }, true);

        angular.element($window).on('keydown', function (e) {
            if (e.which == 27 && $scope.showslider) {
                $window.history.back();
            }
        });

        $scope.hide_slider = function () {
            $window.history.back();
        };

        $scope.$on("$locationChangeStart", function (event, next, current) {
            if (current.indexOf(next) == 0 && current !== next) {
                $scope.showslider = false;
            }
            else if (next.indexOf("#/") != -1 && next.indexOf("submission_detail.html") != -1) {
                var idx = next.indexOf("#/");
                if (idx != -1) {
                    var route = next.slice(idx + 2);
                    var sep_idx = route.indexOf("/");
                    if (sep_idx != -1) {
                        var srl = route.slice(0, sep_idx);
                        var name = decodeURIComponent(route.slice(sep_idx + 1));
                        $scope.view_file_details(srl, name);
                    }
                }
            }
        });

        //Highlighter
        $scope.trigger_highlight = function (tag, value) {
            var key = tag + $scope.splitter + value;
            var idx = $scope.selected_highlight.indexOf(key);
            if (idx == -1) {
                $scope.selected_highlight.push(key);
            }
            else {
                $scope.selected_highlight.splice(idx, 1);
            }
            $scope.file_highlight = [];
            for (var item in $scope.selected_highlight) {
                $scope.file_highlight.push.apply($scope.file_highlight, $scope.tag_map[$scope.selected_highlight[item]])
            }
        };

        $scope.remove_highlight = function (key) {
            var values = key.split($scope.splitter, 2);
            $scope.trigger_highlight(values[0], values[1])
        };

        $scope.isHighlighted = function (tag, value) {
            return $scope.selected_highlight.indexOf(tag + $scope.splitter + value) != -1
        };

        $scope.hasContext = function (tag) {
            return tag.context != null;
        };

        $scope.hasHighlightedTags = function (tags) {
            for (var i in tags) {
                var tag = tags[i];
                if ($scope.isHighlighted(tag.type, tag.value)) {
                    return true;
                }
            }
            return false;
        };

        $scope.clear_selection = function () {
            $scope.selected_highlight = [];
            $scope.file_highlight = null;
        };


        $scope.fetch_keys = function () {
            var data = $scope.temp_keys;
            if (data.error.length == 0 && data.result.length == 0) {
                $scope.run_count += 1;
                if ($scope.run_count == 5) {
                    $http({
                        method: 'GET',
                        url: "/api/v3/live/outstanding_services/" + $scope.sid + "/"
                    })
                        .success(function (data) {
                            $scope.outstanding = data.api_response;
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
                }
                return;
            }
            $timeout(function () {
                $scope.outstanding = null;
            }, 3000);
            $scope.run_count = 0;
            $scope.temp_keys = {error: [], result: []};

            $http({
                method: 'POST',
                url: "/api/v3/service/multiple/keys/",
                data: data
            })
                .success(function (data) {
                    if (!$scope.completed) {
                        $scope.temp_res = data.api_response.result;
                        $scope.temp_errors = data.api_response.error;

                        $scope.draw_results();
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

                });
        };

        //Cache key functions
        $scope.get_cache_key = function (key) {
            $http({
                method: 'GET',
                url: "/api/v3/service/result/" + key + "/"
            })
                .success(function (data) {
                    if (!$scope.completed) {
                        $scope.temp_res[key] = data.api_response;
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

                });
        };

        $scope.get_cache_key_error = function (key) {
            $http({
                method: 'GET',
                url: "/api/v3/service/error/" + key + "/"
            })
                .success(function (data) {
                    if (!$scope.completed) {
                        $scope.temp_errors[key] = data.api_response;
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

                });
        };
        //Error handling
        $scope.error = '';

        $scope.$on('slide', function () {
            $scope.showslider = true;
            $timeout(function () {
                $scope.slide_done = true;
            }, 500);
        });

        $scope.render_file = function (data, name) {
            if ($scope.slide_done) {
                data.api_response['name'] = name;
                $scope.current_file = data.api_response;
                $scope.loading_extra = false;
                $scope.slide_done = false;
            }
            else {
                $timeout(function () {
                    $scope.render_file(data, name);
                }, 20)
            }

        };

        $scope.view_file_details = function (srl, name) {
            var method = 'GET';
            var data = null;
            if ($scope.file_res[srl] !== undefined) {
                if (data == null) {
                    data = {};
                }
                data.extra_result_keys = $scope.file_res[srl];
            }
            if ($scope.file_errors[srl] !== undefined) {
                if (data == null) {
                    data = {};
                }
                data.extra_error_keys = $scope.file_errors[srl];
            }

            if (data != null) {
                method = 'POST';
            }

            $scope.current_file = null;
            $scope.$emit('slide');
            $scope.loading_extra = true;

            $http({
                method: method,
                url: "/api/v3/submission/" + $scope.sid + "/file/" + srl + "/",
                data: data
            })
                .success(function (data) {
                    $scope.render_file(data, name);
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

        $scope.get_final_data = function () {
            $scope.outstanding = null;
            $http({
                method: 'GET',
                url: "/api/v3/submission/" + $scope.sid + "/"
            })
                .success(function (data) {
                    $scope.data = data.api_response;
                    $scope.data.parsed_errors = {
                        listed: $scope.relevant_errors($scope.data.errors),
                        aggregated: $scope.futile_errors($scope.data.errors)
                    };
                    if ($scope.data.state == "completed") {
                        $scope.get_summary();
                        $scope.get_file_tree();
                        $scope.temp_data = null;
                        $scope.temp_res = Object();
                        $scope.temp_errors = Object();
                        $scope.file_res = Object();
                        $scope.file_errors = Object();
                        $scope.completed = true;
                        $scope.started = true;
                    }
                    else {
                        if ($scope.final_timeout_count == 10) {
                            $scope.final_timeout_count = 9;
                        }

                        $scope.final_timeout_count += 1;
                        $timeout(function () {
                            $scope.setup_watch_queue(true);
                        }, 500 * $scope.final_timeout_count);
                    }

                })
                .error(function (data, status, headers, config) {
                    if (data == "") {
                        return;
                    }
                    $scope.loading = false;

                    if (status == 404) {
                        $timeout(function () {
                            swal({
                                    title: "Error",
                                    text: "\nSelected SID does not exists. You'll be returned to the previous page you where on...",
                                    type: "error",
                                    confirmButtonColor: "#d9534f",
                                    confirmButtonText: "Close",
                                    closeOnConfirm: false
                                },
                                function () {
                                    if ($window.location == document.referrer) {
                                        $window.location = "about:blank";
                                    }
                                    else {
                                        $window.location = document.referrer;
                                    }
                                });
                        }, 100);
                        return;
                    }
                    else if (status == 403) {
                        $timeout(function () {
                            swal({
                                    title: "Error",
                                    text: "\nYou do not have access to the page you've requested. You'll be returned to the previous page you where on...",
                                    type: "error",
                                    confirmButtonColor: "#d9534f",
                                    confirmButtonText: "Close",
                                    closeOnConfirm: false
                                },
                                function () {
                                    if ($window.location == document.referrer) {
                                        $window.location = "about:blank";
                                    }
                                    else {
                                        $window.location = document.referrer;
                                    }
                                });
                        }, 100);
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

        $scope.get_summary = function () {
            $http({
                method: 'GET',
                url: "/api/v3/submission/summary/" + $scope.sid + "/"
            })
                .success(function (data) {
                    $scope.summary = data.api_response.tags;
                    $scope.tag_map = data.api_response.map;
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

        $scope.get_file_tree = function () {
            $http({
                method: 'GET',
                url: "/api/v3/submission/tree/" + $scope.sid + "/"
            })
                .success(function (data) {
                    if ($scope.file_tree != null) {
                        //ReDraw hack because angular templates are fucked up...
                        $scope.file_tree = null;
                        $timeout(function () {
                            $scope.file_tree = data.api_response;
                        })
                    }
                    else {
                        $scope.file_tree = data.api_response;
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

                });
        };

        $scope.setup_watch_queue = function (from_start, p_suffix) {
            var params = {};
            if (p_suffix !== undefined) {
                params = {suffix: p_suffix};
            }

            $http({
                method: 'GET',
                url: "/api/v3/live/setup_watch_queue/" + $scope.sid + "/",
                params: params
            })
                .success(function (data) {
                    $scope.wq = data.api_response.wq_id;
                    mySocket.emit("listen", {wq_id: $scope.wq, from_start: from_start});

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

        //Display temporary results
        $scope.draw_temp_data = function () {
            if ($scope.data == null) {
                if ($scope.temp_data == null) {
                    $scope.error = "Nothing to draw ?! That's not right...";
                    return;
                }
                else {
                    $scope.data = $scope.temp_data;
                }

            }

            $scope.summary = {};
            $scope.tag_map = {};
            $scope.file_tree = {};

            //TODO: load file tree from file info...
            for (var idx in $scope.data.fileinfo) {
                var file_item = $scope.data.fileinfo[idx];
                $scope.file_tree[file_item.sha256] = {};
                $scope.file_tree[file_item.sha256]['name'] = file_item.original_filename;
                $scope.file_tree[file_item.sha256]['score'] = 0;
                $scope.file_tree[file_item.sha256]['children'] = {};
            }
        };

        $scope.draw_results = function () {
            for (var key in $scope.temp_res) {
                $scope.update_summary(key, $scope.temp_res[key]);
                $scope.update_filetree(key, $scope.temp_res[key]);
                if ($scope.file_res[key.substr(0, 64)] === undefined) {
                    $scope.file_res[key.substr(0, 64)] = [];
                }
                $scope.file_res[key.substr(0, 64)].push(key);
            }
            $scope.temp_res = {};

            for (var key_err in $scope.temp_errors) {
                $scope.update_errors(key_err, $scope.temp_errors[key_err]);
                if ($scope.file_errors[key_err.substr(0, 64)] === undefined) {
                    $scope.file_errors[key_err.substr(0, 64)] = [];
                }
                $scope.file_errors[key_err.substr(0, 64)].push(key_err);
            }
            $scope.temp_errors = {};

            $scope.redraw_rate = Math.min(Math.max(3000, $scope.num_files * 100), 15000);
        };

        $scope.update_errors = function (key) {
            //console.log("Update errors with", key, " => ", result);
            if (!$scope.data.hasOwnProperty('errors')) {
                $scope.data['errors'] = [];
            }

            $scope.data['errors'].push(key);
            $scope.data.parsed_errors = {
                listed: $scope.relevant_errors($scope.data.errors),
                aggregated: $scope.futile_errors($scope.data.errors)
            }
        };

        $scope.update_summary = function (key, result) {
            var valid_types = ["NET_IP", "NET_DOMAIN_NAME", "NET_FULL_URI", "AV_VIRUS_NAME", "IMPLANT_NAME", "IMPLANT_FAMILY", "TECHNIQUE_OBFUSCATION", "THREAT_ACTOR", "FILE_CONFIG", "FILE_OBFUSCATION", "EXPLOIT_NAME", "FILE_SUMMARY"];

            key = key.substr(0, 64);
            if ($scope.summary == null) {
                $scope.summary = {};
            }

            if ($scope.tag_map == null) {
                $scope.tag_map = {};
            }

            if (!$scope.tag_map.hasOwnProperty(key)) {
                $scope.tag_map[key] = [];
            }

            for (var tag in result['result']['tags']) {
                var tag_item = result['result']['tags'][tag];
                if (valid_types.indexOf(tag_item.type) == -1) {
                    continue;
                }

                if (!$scope.summary.hasOwnProperty(tag_item.type)) {
                    $scope.summary[tag_item.type] = [];
                }

                var exists = false;
                for (var i in $scope.summary[tag_item.type]) {
                    if ($scope.summary[tag_item.type][i]["value"] == tag_item.value) {
                        exists = true;
                        break;
                    }
                }

                if (!exists) {
                    $scope.summary[tag_item.type].push({
                        value: tag_item.value,
                        classification: tag_item.classification,
                        usage: tag_item.usage
                    })
                }

                var tag_key = tag_item.type + $scope.splitter + tag_item.value;
                $scope.tag_map[key].push(tag_key);
                if (!$scope.tag_map.hasOwnProperty(tag_key)) {
                    $scope.tag_map[tag_key] = [];
                }
                $scope.tag_map[tag_key].push(key);
            }
        };

        $scope.get_file_name_from_srl = function (srl) {
            for (var i in $scope.data.files) {
                if ($scope.data.files[i][1] == srl) {
                    return $scope.data.files[i][0]
                }
            }

            return null;
        };

        $scope.update_filetree = function (key, result) {
            key = key.substr(0, 64);
            if ($scope.file_tree == null) {
                $scope.file_tree = {};
            }

            var to_update = $scope.search_file_tree(key, $scope.file_tree);

            if (to_update.length == 0) {
                var fname = $scope.get_file_name_from_srl(key);

                if (fname != null) {
                    $scope.file_tree[key] = {};
                    $scope.file_tree[key]['children'] = {};
                    $scope.file_tree[key]['name'] = [fname];
                    $scope.file_tree[key]['score'] = 0;
                    $scope.num_files += 1;
                    to_update.push($scope.file_tree[key]);
                }
                else {
                    fname = key;
                    if (!$scope.file_tree.hasOwnProperty("TBD")) {
                        $scope.file_tree["TBD"] = {};
                        $scope.file_tree["TBD"]['children'] = {};
                        $scope.file_tree["TBD"]['name'] = "Undertermined Parent";
                        $scope.file_tree["TBD"]['score'] = 0;
                    }

                    $scope.file_tree["TBD"]['children'][key] = {};
                    $scope.file_tree["TBD"]['children'][key]['children'] = {};
                    $scope.file_tree["TBD"]['children'][key]['name'] = [fname];
                    $scope.file_tree["TBD"]['children'][key]['score'] = 0;
                    $scope.num_files += 1;

                    to_update.push($scope.file_tree["TBD"]['children'][key]);
                }

            }
            var to_del_tbd = [];
            for (var idx in to_update) {
                var item = to_update[idx];
                if (result.result['score'] !== undefined) {
                    item['score'] = item['score'] + result.result['score'];
                }

                for (var i in result.response.extracted) {
                    var srl = result.response.extracted[i][1];
                    var name = result.response.extracted[i][0];

                    if (!item['children'].hasOwnProperty(srl)) {
                        if ($scope.file_tree.hasOwnProperty("TBD") && $scope.file_tree["TBD"]['children'].hasOwnProperty(srl)) {
                            item['children'][srl] = $scope.file_tree["TBD"]['children'][srl];
                            item['children'][srl]['name'] = [name];
                            if (to_del_tbd.indexOf(srl) == -1) to_del_tbd.push(srl);
                        }
                        else {
                            item['children'][srl] = {};
                            item['children'][srl]['children'] = {};
                            item['children'][srl]['name'] = [name];
                            item['children'][srl]['score'] = 0;
                            $scope.num_files += 1;
                        }
                    }
                    else {
                        item['children'][srl]['name'].push(name)
                    }

                }
            }

            for (var idx_del in to_del_tbd) {
                delete $scope.file_tree["TBD"]['children'][to_del_tbd[idx_del]];
            }
        };

        $scope.search_file_tree = function (srl, tree) {
            var output = [];
            for (var key in tree) {
                if ($scope.obj_len(tree[key]['children']) != 0) {
                    output.push.apply(output, $scope.search_file_tree(srl, tree[key]['children']));
                }
                if (key == srl) {
                    output.push(tree[key]);
                }
            }
            return output;
        };

        $scope.reload_messages = function () {
            var ret_val = {get_final: false, queue_from_start: false};

            var temp = sessionStorage.getItem("msg_" + $scope.sid);
            var temp_err = sessionStorage.getItem("error_" + $scope.sid);

            if (temp != null) {
                $scope.messages = JSON.parse(temp);
            }
            if (temp_err != null) {
                $scope.messages_error = JSON.parse(temp_err);
            }

            if ($scope.messages.length == 0) {
                ret_val.queue_from_start = true;
            }
            else if ($scope.messages[$scope.messages.length - 1] != "stop") {
                for (var i = 0; i < $scope.messages.length; i++) {
                    if ($scope.messages[i] == "start") {
                        $scope.started = true;
                        $scope.draw_temp_data();
                        $scope.temp_data = null;
                        ret_val.queue_from_start = false;
                    }
                    else {
                        $scope.temp_keys.result.push($scope.messages[i]);
                    }
                }
                for (var y = 0; y < $scope.messages_error.length; y++) {
                    $scope.temp_keys.error.push($scope.messages_error[y]);
                }
                $scope.timed_redraw();
            }
            else {
                ret_val.get_final = true;
            }

            return ret_val;
        };

        //Load params from datastore
        $scope.start = function () {
            if ($scope.sid == null || $scope.sid == "") {
                $timeout(function () {
                    swal({
                            title: "Error",
                            text: "\nInvalid SID provided. You'll be returned to the previous page you where on...",
                            type: "error",
                            confirmButtonColor: "#d9534f",
                            confirmButtonText: "Close",
                            closeOnConfirm: false
                        },
                        function () {
                            if ($window.location == document.referrer) {
                                $window.location = "about:blank";
                            }
                            else {
                                $window.location = document.referrer;
                            }
                        });
                }, 100);
            }
            else {
                $scope.get_final_data();
            }
        };
    });

