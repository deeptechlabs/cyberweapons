/* global angular */
'use strict';

/**
 * Main App Module
 */
function ServiceBaseCtrl($scope, $http, $timeout) {
    //Parameters vars
    $scope.signature_list = null;
    $scope.user = null;
    $scope.loading = false;
    $scope.loading_extra = false;
    $scope.current_signature = null;
    $scope.sig_temp_key = null;
    $scope.sig_temp_val = null;
    $scope.started = false;
    $scope.editmode = true;
    $scope.organisation = "ORG";
    $scope.state_changed = false;
    $scope.signature_changed = false;
    $scope.current_signature_state = "TESTING";
    $scope.filtered = false;
    $scope.filter = "meta.id:*";
    $scope.non_editable = ['creation_date', 'last_saved_by', 'modification_date', 'al_state_change_date', 'al_state_change_user'];

    //DEBUG MODE
    $scope.debug = false;
    $scope.showParams = function () {
        console.log("Scope", $scope)
    };

    //Error handling
    $scope.error = '';
    $scope.success = '';

    //pager dependencies
    $scope.total = null;
    $scope.offset = 0;
    $scope.count = 25;
    $scope.searchText = "";
    $scope.$watch('searchText', function () {
        if ($scope.started && $scope.searchText !== undefined && $scope.searchText != null) {
            if ($scope.searchText == "" || $scope.searchText == null || $scope.searchText === undefined) {
                $scope.filter = "meta.id:*";
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

    $scope.receiveClassification = function (classification) {
        $scope.current_signature.meta.classification = classification;
    };

    $scope.add_signature = function () {
        $scope.editmode = false;
        $scope.current_signature = {
            comments: [],
            condition: [],
            meta: {
                al_status: "TESTING",
                classification: classification_definition.UNRESTRICTED,
                description: "",
                id: $scope.organisation + "_XXXXXX",
                organisation: $scope.organisation,
                poc: $scope.user.uname + "@" + $scope.organisation.toLowerCase(),
                rule_group: "info",
                rule_version: 1,
                yara_version: "3.6"
            },
            name: "",
            strings: [],
            tags: [],
            type: "rule"
        };
        $scope.error = '';
        $scope.success = '';
        $("#myModal").modal('show');
    };

    $scope.remove_meta = function (key) {
        delete $scope.current_signature.meta[key];
    };

    $scope.add_meta = function () {
        if ($scope.sig_temp_key in $scope.current_signature.meta || $scope.sig_temp_key == "" || $scope.sig_temp_key == null) {
            return;
        }
        $scope.current_signature.meta[$scope.sig_temp_key] = $scope.sig_temp_val;

        $scope.sig_temp_key = "";
        $scope.sig_temp_val = "";
    };

    $scope.otherKeys = function () {
        var out = [];

        if ($scope.current_signature !== undefined && $scope.current_signature != null) {
            var exclusion = ['rule_group', 'classification', 'description', 'id', 'organisation', 'poc', 'rule_version', 'yara_version', 'al_status', $scope.current_signature.meta.rule_group];
            for (var key in $scope.current_signature.meta) {
                if (exclusion.indexOf(key) == -1) {
                    out.push(key);
                }
            }
        }
        out.sort();

        return out;
    };

    var myModal = $("#myModal");
    myModal.on('shown.bs.modal', function () {
        $scope.$apply(function () {
            $scope.state_changed = false;
            $scope.signature_changed = false;
            $scope.current_signature_state = $scope.current_signature.meta.al_status;
        });
    });

    myModal.on('show.bs.modal', function () {
        $scope.sig_temp_key = null;
        $scope.sig_temp_val = null;

        if ($scope.editmode) {
            $("#preview").addClass('active');
            $("#preview_tab").addClass('active');
            $("#edit").removeClass('active');
            $("#edit_tab").removeClass('active');
            $("#state").removeClass('active');
            $("#state_tab").removeClass('active');
        }
        else {
            $("#preview").removeClass('active');
            $("#preview_tab").removeClass('active');
            $("#edit").addClass('active');
            $("#edit_tab").addClass('active');
            $("#state").removeClass('active');
            $("#state_tab").removeClass('active');
        }

    });

    $scope.editSignature = function (sid, rev) {
        $scope.loading_extra = true;
        $scope.editmode = true;
        $scope.error = '';
        $scope.success = '';

        $http({
            method: 'GET',
            url: "/api/v3/signature/" + sid + "/" + rev + "/"
        })
            .success(function (data) {
                $scope.loading_extra = false;
                $scope.current_signature = data.api_response;
                $("#myModal").modal('show');
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

    $scope.beautify_error_message = function (data) {
        if (data.field === undefined) {
            return data;
        }

        var out = String();

        if (data.field == null) {
            out += "Rule has a " + data.message.type + " on line " + data.message.line + ": [ " + data.message.error + " ]\n\n";
            out += data.message.rule_text;
        }
        else {
            out += "Field ";
            out += data.field;
            out += " has an error:\n\n";
            out += data.message;
        }

        return out;
    };

    //Save params
    $scope.save = function () {
        $scope.error = '';
        $scope.success = '';

        if (!$scope.editmode) {
            $http({
                method: 'PUT',
                url: "/api/v3/signature/add/",
                data: $scope.current_signature
            })
                .success(function (data) {
                    $("#myModal").modal('hide');
                    $scope.success = "Signature " + data.api_response.sid + " r." + data.api_response.rev + " successfully added!";
                    $timeout(function () {
                        $scope.success = "";
                        $scope.load_data();
                    }, 2000);

                })
                .error(function (data, status, headers, config) {
                    if (data == "") {
                        return;
                    }

                    if (data.api_error_message) {
                        $scope.error = $scope.beautify_error_message(data.api_error_message);
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                });
        }
        else {
            $http({
                method: 'POST',
                url: "/api/v3/signature/" + $scope.current_signature.meta.id + "/" + $scope.current_signature.meta.rule_version + "/",
                data: $scope.current_signature
            })
                .success(function (data) {
                    $("#myModal").modal('hide');
                    if (data.api_response.rev != $scope.current_signature.meta.rule_version) {
                        $scope.success = "Signature " + data.api_response.sid + " succesfully saved and bumped to revision " + data.api_response.rev + ".";
                    }
                    else {
                        $scope.success = "Signature " + data.api_response.sid + " succesfully saved.";
                    }

                    $timeout(function () {
                        $scope.success = "";
                        $scope.load_data();
                    }, 2000);
                })
                .error(function (data, status, headers, config) {
                    if (data == "") {
                        return;
                    }

                    if (data.api_error_message) {
                        $scope.error = $scope.beautify_error_message(data.api_error_message);
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                });
        }

    };

    $scope.change_state = function (new_status) {
        $http({
            method: 'GET',
            url: "/api/v3/signature/change_status/" + $scope.current_signature.meta.id + "/" + $scope.current_signature.meta.rule_version + "/" + new_status + "/"
        })
            .success(function () {
                $("#myModal").modal('hide');
                $scope.success = "Status of signature " + $scope.current_signature.meta.id + " r." + $scope.current_signature.meta.rule_version + " successfully changed to " + new_status + ".";
                $timeout(function () {
                    $scope.success = "";
                    $scope.load_data();
                }, 2000);

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
            });
    };

    $scope.set_state_change = function () {
        $scope.state_changed = true;
    };

    //Load params from datastore
    $scope.start = function () {
        $scope.load_data();
    };

    //Page traversing
    $scope.load_data = function () {
        $scope.loading_extra = true;

        $http({
            method: 'GET',
            url: "/api/v3/signature/list/?offset=" + $scope.offset + "&length=" + $scope.count + "&filter=" + $scope.filter
        })
            .success(function (data) {
                $scope.loading_extra = false;

                $scope.signature_list = data.api_response.items;
                $scope.total = data.api_response.total;

                $scope.pages = $scope.pagerArray();
                $scope.started = true;

                $scope.filtered = $scope.filter != "meta.id:*";
            })
            .error(function (data, status, headers, config) {
                $scope.loading_extra = false;

                if (data == "" || status == 400) {
                    $scope.signature_list = [];
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
app.controller('ALController', ServiceBaseCtrl);

