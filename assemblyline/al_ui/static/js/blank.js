/* global angular */
'use strict';

/**
 * Main App Module
 */
var app = angular.module('app', ['search', 'utils'])
    .controller('ALController', function ($scope) {
        $scope.user = null;

        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        //Error handling
        $scope.error = '';
        $scope.success = '';

        //Do nothing
        $scope.start = function () {
            console.log("STARTED!")
        };
    });

