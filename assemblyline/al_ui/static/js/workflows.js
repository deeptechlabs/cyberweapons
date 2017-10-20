/* global angular */
'use strict';

/**
 * Main App Module
 */
var app = angular.module('app', ['utils', 'search', 'ui.bootstrap', 'ngSanitize', 'ui.select'])
    .controller('ALController', function ($scope, $http, $timeout) {
        //Parameters vars
        $scope.workflow_list = null;
        $scope.user = null;
        $scope.loading = false;
        $scope.loading_extra = false;
        $scope.cur_workflow = null;
        $scope.started = false;
        $scope.filtered = false;
        $scope.filter = "";

        $scope.label_suggestions = ['PHISHING', 'COMPROMISE', 'CRIME', 'ATTRIBUTED', 'WHITELISTED',
            'FALSE_POSITIVE', 'REPORTED', 'MITIGATED', 'PENDING'];

        //Pager vars
        $scope.show_pager_add = true;
        $scope.pager_add = function () {
            $scope.reset_error_ctrls();
            $scope.cur_workflow = {
                label: [],
                priority: '',
                status: '',
                classification: classification_definition.UNRESTRICTED,
                query: "",
                hit_count: 0
            };
            $scope.error = '';
            $scope.success = '';
            $("#workflowModal").modal('show');
        };

        $scope.maximum_classification = true;
        $scope.receiveClassification = function (classification) {
            $scope.cur_workflow.classification = classification;
        };

        $scope.pager_btn_text = "Add Workflow";

        $scope.total = 0;
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
        $("#workflowModal").on('hidden.bs.modal', function () {
            $scope.reset_error_ctrls();
        });

        $scope.delWorkflow = function (wf) {
            swal({
                    title: "Delete Workflow?",
                    text: "You are about to delete the current workflow. Are you sure?",
                    type: "warning",
                    showCancelButton: true,
                    confirmButtonColor: "#d9534f",
                    confirmButtonText: "Yes, delete it!",
                    closeOnConfirm: true
                },
                function () {
                    $scope.do_delWorkflow(wf);
                })
        };

        $scope.do_delWorkflow = function (wf) {
            console.log("Delete", wf);
            $("#workflowModal").modal('hide');
            $scope.loading_extra = true;

            $http({
                method: 'DELETE',
                url: "/api/v3/workflow/" + wf.id + "/"
            })
                .success(function () {
                    $scope.loading_extra = false;
                    $scope.success = "Workflow " + wf.name + " successfully removed!";
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

        $scope.editWorkflow = function (wf) {
            $scope.reset_error_ctrls();

            $scope.error = '';
            $scope.success = '';
            $scope.loading_extra = true;

            $http({
                method: 'GET',
                url: "/api/v3/workflow/" + wf.id + "/"
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.cur_workflow = data.api_response;
                    $("#workflowModal").modal('show');
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
        $scope.saveWorkflow = function () {
            $scope.reset_error_ctrls();
            $scope.loading_extra = true;
            $scope.error = '';
            $scope.success = '';

            $http({
                method: 'POST',
                url: "/api/v3/workflow/" + $scope.cur_workflow.id + "/",
                data: $scope.cur_workflow
            })
                .success(function () {
                    $scope.loading_extra = false;
                    $("#workflowModal").modal('hide');
                    $scope.success = "Workflow " + $scope.cur_workflow.name + " successfully saved!";
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

                    if (status == 400) {
                        if (data.api_error_message.startsWith("Name")){
                            //noinspection JSDuplicatedDeclaration
                            var ctrl = $("#name");
                        }
                        else if(data.api_error_message.startsWith("Query")) {
                            //noinspection JSDuplicatedDeclaration
                            var ctrl = $("#query");
                        }
                        ctrl.addClass("has-error");
                        ctrl.find("input").select();
                        ctrl.find("error").text("* This field is required");
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
            $("#name").removeClass("has-error");
            $("#query").removeClass("has-error");
        };
    
        $scope.addWorkflow = function () {
            $scope.reset_error_ctrls();
            $scope.error = '';
            $scope.success = '';
    
            $http({
                method: 'PUT',
                url: "/api/v3/workflow/",
                data: $scope.cur_workflow
            })
                .success(function () {
                    $("#workflowModal").modal('hide');
                    $scope.success = "Workflow " + $scope.cur_workflow.name + " successfully added!";
                    $timeout(function () {
                        $scope.success = "";
                        $scope.load_data();
                    }, 2000);
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (data == ""){
                        return;
                    }

                    if (status == 400) {
                        if (data.api_error_message.startsWith("Name")){
                            //noinspection JSDuplicatedDeclaration
                            var ctrl = $("#name");
                        }
                        else if(data.api_error_message.startsWith("Query")) {
                            //noinspection JSDuplicatedDeclaration
                            var ctrl = $("#query");
                        }
                        ctrl.addClass("has-error");
                        ctrl.find("input").select();
                        ctrl.find("error").text("* This field is required");
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

        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        //Error handling
        $scope.error = '';

        //Load params from datastore
        $scope.start = function () {
            $scope.load_data();
            $scope.load_label_suggestions();
        };

        $scope.load_label_suggestions = function(){
            $http({
                method: 'GET',
                url: "/api/v3/workflow/labels/"
            })
                .success(function (data) {
                    for (var item_id in data.api_response){
                        var item = data.api_response[item_id];
                        if ($scope.label_suggestions.indexOf(item) == -1){
                            $scope.label_suggestions.push(item);
                        }
                    }
                })
                .error(function (data, status, headers, config) {

                    if (data == "" || status == 400) {
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

        $scope.load_data = function () {
            $scope.loading_extra = true;

            $http({
                method: 'GET',
                url: "/api/v3/workflow/list/?offset=" + $scope.offset + "&length=" + $scope.count + "&filter=" + $scope.filter
            })
                .success(function (data) {
                    $scope.loading_extra = false;

                    $scope.workflow_list = data.api_response.items;
                    $scope.total = data.api_response.total;

                    $scope.pages = $scope.pagerArray();
                    $scope.started = true;

                    $scope.filtered = $scope.filter != "";
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (data == "" || status == 400) {
                        $scope.workflow_list = [];
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

