/* global angular */
'use strict';

/**
 * Main App Module
 */

function AdminUserBaseCtrl($scope, $http, $timeout) {
    //Parameters vars
    $scope.user_list = null;
    $scope.user = null;
    $scope.loading = false;
    $scope.loading_extra = false;
    $scope.current_user = null;
    $scope.started = false;
    $scope.editmode = true;

    $scope.filtered = false;
    $scope.filter = "";

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
        $scope.reset_error_ctrls();
        $scope.editmode = false;
        $scope.current_user = {
            avatar: null,
            groups: ["DEFAULT_GROUP"],
            is_active: true,
            is_admin: false,
            classification: classification_definition.UNRESTRICTED,
            name: "",
            uname: ""
        };
        $scope.current_user.new_pass = null;
        $scope.error = '';
        $scope.success = '';
        $('#avatar').attr("src", "/static/images/user_default.png");
        $("#myModal").modal('show');
    };

    $scope.maximum_classification = true;
    $scope.receiveClassification = function (classification) {
        $scope.current_user.classification = classification;
    };

    $scope.pager_btn_text = "Add User";
    $scope.total = null;
    $scope.offset = 0;
    $scope.count = 25;
    $scope.searchText = "";
    $scope.$watch('searchText', function () {
        if ($scope.started && $scope.searchText !== undefined && $scope.searchText != null) {
            if ($scope.searchText == "" || $scope.searchText == null || $scope.searchText === undefined) {
                $scope.filter = "";
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

    //User editing
    $("#myModal").on('hidden.bs.modal', function () {
        $("#uname").removeClass("has-error");
        $("#uname_lbl").text("User ID")
    });

    $scope.reveal_show = function () {
        var ctrl = $("#pwd");
        ctrl.attr('type', 'text');
    };

    $scope.reveal_hide = function () {
        var ctrl = $("#pwd");
        ctrl.attr('type', 'password');
    };

    $scope.delUser = function (user) {
        swal({
                title: "Delete User?",
                text: "You are about to delete the current user. Are you sure?",
                type: "warning",
                showCancelButton: true,
                confirmButtonColor: "#d9534f",
                confirmButtonText: "Yes, delete it!",
                closeOnConfirm: true
            },
            function () {
                $scope.do_delUser(user);
            })
    };

    $scope.do_delUser = function (user) {
        console.log("Delete", user);
        $("#myModal").modal('hide');
        $scope.loading_extra = true;

        $http({
            method: 'DELETE',
            url: "/api/v3/user/" + user.uname + "/"
        })
            .success(function () {
                $scope.loading_extra = false;
                $scope.success = "User " + $scope.user.uname + " successfully removed!";
                $timeout(function () {
                    $scope.success = "";
                    $scope.load_data();
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
                $scope.started = true;

            });
    };

    $scope.editUser = function (user) {
        $scope.reset_error_ctrls();
        $scope.editmode = true;

        $scope.error = '';
        $scope.success = '';
        $scope.loading_extra = true;

        $http({
            method: 'GET',
            url: "/api/v3/user/" + user.uname + "/?load_avatar=true"
        })
            .success(function (data) {
                $scope.loading_extra = false;
                $scope.current_user = data.api_response;
                $scope.current_user.new_pass = null;
                if ($scope.current_user.avatar != null) {
                    $('#avatar').attr("src", $scope.current_user.avatar);
                }
                else {
                    $('#avatar').attr("src", "/static/images/user_default.png");
                }
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
            });
    };

    //Save params
    $scope.save = function () {
        $scope.reset_error_ctrls();
        $scope.loading_extra = true;
        $scope.error = '';
        $scope.success = '';

        $http({
            method: 'POST',
            url: "/api/v3/user/" + $scope.current_user.uname + "/",
            data: $scope.current_user
        })
            .success(function () {
                $scope.loading_extra = false;
                $("#myModal").modal('hide');
                $scope.success = "User " + $scope.current_user.uname + " successfully updated!";
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

                if (data == "" || status == 400) {
                    var ctrl = $("#uname");
                    ctrl.addClass("has-error");
                    ctrl.find("input").select();
                    ctrl.find("error").text("* Username already exists");
                    return;
                }

                if (data == "" || status == 412) {
                    var ctrl = $("#uname");
                    ctrl.addClass("has-error");
                    ctrl.find("input").select();
                    ctrl.find("error").text("* Invalid characters used in the User ID");
                    return;
                }

                if (data == "" || status == 469) {
                    var pass_ctrl = $("#new_pass");
                    pass_ctrl.addClass("has-error");
                    pass_ctrl.find("input").select();
                    pass_ctrl.find('error').text("* " + data.api_error_message);
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

    $scope.reset_error_ctrls = function () {
        var ctrl = $("#uname");
        ctrl.removeClass("has-error");
        ctrl.find("error").text("");
        var pass_ctrl = $("#new_pass");
        pass_ctrl.removeClass("has-error");
        pass_ctrl.find("error").text("");
    };

    $scope.add = function () {
        $scope.reset_error_ctrls();
        $scope.error = '';
        $scope.success = '';

        $http({
            method: 'PUT',
            url: "/api/v3/user/" + $scope.current_user.uname + "/",
            data: $scope.current_user
        })
            .success(function () {
                if (!$scope.editmode) $scope.user_list.push($scope.current_user);
                $("#myModal").modal('hide');
                $scope.success = "User " + $scope.current_user.uname + " successfully added!";
                $timeout(function () {
                    $scope.success = "";
                    $scope.load_data();
                }, 2000);
            })
            .error(function (data, status, headers, config) {
                $scope.loading_extra = false;

                if (data == "" || status == 400) {
                    var ctrl = $("#uname");
                    ctrl.addClass("has-error");
                    ctrl.find("input").select();
                    ctrl.find("error").text("* Username already exists");
                    return;
                }

                if (data == "" || status == 412) {
                    var ctrl = $("#uname");
                    ctrl.addClass("has-error");
                    ctrl.find("input").select();
                    ctrl.find("error").text("* Invalid characters used in the User ID");
                    return;
                }

                if (data == "" || status == 469) {
                    var pass_ctrl = $("#new_pass");
                    pass_ctrl.addClass("has-error");
                    pass_ctrl.find("input").select();
                    pass_ctrl.find('error').text("* " + data.api_error_message);
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

    //Load params from datastore
    $scope.start = function () {
        $scope.load_data();
    };

    //Pager methods
    $scope.load_data = function () {
        $scope.loading_extra = true;

        $http({
            method: 'GET',
            url: "/api/v3/user/list/?offset=" + $scope.offset + "&length=" + $scope.count + "&filter=" + $scope.filter
        })
            .success(function (data) {
                $scope.loading_extra = false;

                $scope.user_list = data.api_response.items;
                $scope.total = data.api_response.total;

                $scope.pages = $scope.pagerArray();
                $scope.started = true;

                $scope.filtered = $scope.filter != "";
            })
            .error(function (data, status, headers, config) {
                $scope.loading_extra = false;

                if (data == "" || status == 400) {
                    $scope.user_list = [];
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
}

var app = angular.module('app', ['utils', 'search', 'ngAnimate', 'ui.bootstrap']);
app.controller('ALController', AdminUserBaseCtrl);
