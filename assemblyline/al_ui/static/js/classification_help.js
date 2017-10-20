/* global angular */
'use strict';

/**
 * Main App Module
 */
var app = angular.module('app', ['search', 'utils'])
    .controller('ALController', function ($scope, $timeout) {
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
            if (classification_definition == null) {
                $timeout($scope.start, 50);
            }
            else {
                $scope.classification_definition = classification_definition;
            }
        };

        $scope.level_list = function () {
            var out = [];
            for (var i in $scope.classification_definition.levels_map) {
                if (!isNaN(parseInt(i))) {
                    out.push($scope.classification_definition.levels_map[i]);
                }
            }
            return out;
        };

        $scope.getLength = function (obj) {
            return Object.keys(obj).length;
        }
    });

