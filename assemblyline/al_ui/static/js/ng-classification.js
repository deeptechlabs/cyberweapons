/* global angular */
'use strict';

/*
 * Load classification definition from API into a global variable.
 */
var classification_definition = null;
$.getJSON("/api/v3/help/classification_definition/", function (data) {
    classification_definition = data.api_response;
});

/***************************************************************************************************
 * Classification static functions
 *  NOTE:   Contrary to the python implementation of the classification engine functions in the
 *          Javascript implementation will not normalize the classification, they are only here
 *          for display purposes.
 */
function get_c12n_level_index(c12n) {
    if (classification_definition == null || c12n === undefined || c12n == null) return null;
    c12n = c12n.toUpperCase();
    var split_idx = c12n.indexOf("//");
    if (split_idx != -1) {
        c12n = c12n.slice(0, split_idx)
    }

    if (classification_definition.levels_map[c12n] !== undefined) {
        return classification_definition.levels_map[c12n];
    }
    else if (classification_definition.levels_map_lts[c12n] !== undefined) {
        return classification_definition.levels_map[classification_definition.levels_map_lts[c12n]];
    }
    else if (classification_definition.levels_aliases[c12n] !== undefined) {
        return classification_definition.levels_map[classification_definition.levels_aliases[c12n]];
    }

    return null;
}

function get_c12n_level_text(lvl_idx, long_format) {
    if (long_format === undefined) long_format = true;
    var text = null;
    if (lvl_idx === parseInt(lvl_idx, 10)) {
        lvl_idx = lvl_idx.toString();
    }
    if (classification_definition != null) {
        text = classification_definition.levels_map[lvl_idx];
    }

    if (text === undefined || text == null) {
        text = ""
    }

    if (long_format) {
        return classification_definition.levels_map_stl[text]
    }

    return text
}

function get_c12n_required(c12n, long_format) {
    if (classification_definition == null || c12n === undefined || c12n == null) return [];
    if (long_format === undefined) long_format = true;
    c12n = c12n.toUpperCase();

    var return_set = [];
    var part_set = c12n.split("/");
    for (var i in part_set) {
        var p = part_set[i];
        if (p in classification_definition.access_req_map_lts) {
            return_set.push(classification_definition.access_req_map_lts[p]);
        }
        else if (p in classification_definition.access_req_map_stl) {
            return_set.push(p);
        }
        else if (p in classification_definition.access_req_aliases) {
            for (var j in classification_definition.access_req_aliases[p]) {
                var a = classification_definition.access_req_aliases[p][j];
                return_set.push(a);
            }
        }
    }

    if (long_format) {
        var out = [];
        for (var k in return_set) {
            var r = return_set[k];
            out.push(classification_definition.access_req_map_stl[r]);
        }

        return out.sort();
    }

    return return_set.sort();
}

function get_c12n_groups(c12n, long_format) {
    if (classification_definition == null || c12n === undefined || c12n == null) return [];
    if (long_format === undefined) long_format = true;
    c12n = c12n.toUpperCase();

    var g1 = [];
    var g2 = [];

    var parts = c12n.split("//");
    var groups = [];
    for (var p_idx in parts) {
        var grp_part = parts[p_idx].replace("REL TO ", "");
        var temp_group = grp_part.split(",");
        for (var i in temp_group) {
            var t = temp_group[i].trim();
            groups = groups.concat(t.split('/'));
        }
    }

    for (var j in groups) {
        var g = groups[j];
        if (g in classification_definition.groups_map_lts) {
            g1.push(classification_definition.groups_map_lts[g]);
        }
        else if (g in classification_definition.groups_map_stl) {
            g1.push(g);
        }
        else if (g in classification_definition.groups_aliases) {
            for (var k in classification_definition.groups_aliases[g]) {
                var a = classification_definition.groups_aliases[g][k];
                g1.push(a);
            }
        }
        else if (g in classification_definition.subgroups_map_lts) {
            g2.push(classification_definition.subgroups_map_lts[g]);
        }
        else if (g in classification_definition.subgroups_map_stl) {
            g2.push(g);
        }
        else if (g in classification_definition.subgroups_aliases) {
            for (var l in classification_definition.subgroups_aliases[g]) {
                var sa = classification_definition.subgroups_aliases[g][l];
                g2.push(sa);
            }
        }
    }

    if (long_format) {
        var g1_out = [];
        for (var m in g1) {
            var gr = g1[m];
            g1_out.push(classification_definition.groups_map_stl[gr]);
        }

        var g2_out = [];
        for (var n in g2) {
            var sgr = g2[n];
            g2_out.push(classification_definition.subgroups_map_stl[sgr]);
        }

        return {'groups': g1_out.sort(), 'subgroups': g2_out.sort()};
    }

    return {'groups': g1.sort(), 'subgroups': g2.sort()};
}

function get_c12n_parts(c12n, long_format) {
    if (classification_definition == null || c12n === undefined || c12n == null) return {};
    if (long_format === undefined) long_format = true;
    var out = {
        'lvl_idx': get_c12n_level_index(c12n),
        'req': get_c12n_required(c12n, long_format)
    };

    var grps = get_c12n_groups(c12n, long_format);
    out['groups'] = grps['groups'];
    out['subgroups'] = grps['subgroups'];

    return out;
}

function get_c12n_text_from_parts(parts, long_format) {
    var lvl_idx = parts['lvl_idx'];
    var req = parts['req'];
    var groups = parts['groups'];
    var subgroups = parts['subgroups'];

    var out = get_c12n_level_text(lvl_idx, long_format);

    var req_grp = [];
    for (var i in req) {
        var r = req[i];
        if (classification_definition.params_map[r] !== undefined) {
            if (classification_definition.params_map[r].is_required_group !== undefined) {
                if (classification_definition.params_map[r].is_required_group) {
                    req_grp.push(r);
                }
            }
        }
    }

    for (var j in req_grp) {
        var rg = req_grp[j];
        req.splice(req.indexOf(rg), 1);
    }

    if (req.length > 0) {
        out += "//" + req.join("/")
    }
    if (req_grp.length > 0) {
        out += "//" + req_grp.join("/")
    }

    if (groups.length > 0) {
        if (req_grp.length > 0) {
            out += "/";
        }
        else {
            out += "//";
        }

        if (groups.length == 1) {
            var group = groups[0];
            if (classification_definition.params_map[group] !== undefined) {
                if (classification_definition.params_map[group].solitary_display_name !== undefined) {
                    out += classification_definition.params_map[group].solitary_display_name
                }
                else {
                    out += "REL TO " + group;
                }
            }
            else {
                out += "REL TO " + group;
            }

        }
        else {
            if (!long_format) {
                for (var alias in classification_definition.groups_aliases) {
                    var values = classification_definition.groups_aliases[alias];
                    if (values.length > 1) {
                        if (JSON.stringify(values.sort()) == JSON.stringify(groups)) {
                            groups = [alias];
                        }
                    }
                }
            }
            out += "REL TO " + groups.join(", ")
        }
    }

    if (subgroups.length > 0) {
        if (groups.length > 0 || req_grp.length > 0) {
            out += "/";
        }
        else {
            out += "//";
        }
        out += subgroups.join("/")
    }


    return out;
}

function get_c12n_text(c12n, long_format) {
    if (classification_definition == null || c12n === undefined || c12n == null) return c12n;
    if (long_format === undefined) long_format = true;
    var parts = get_c12n_parts(c12n, long_format);
    return get_c12n_text_from_parts(parts, long_format);
}

/***************************************************************************************************
 * ng-utils EXTRA Controllers
 */
utils.controller('classificationCtrl', function ($scope) {
    $scope.classification_definition = classification_definition;
    $scope.active_list = {};
    $scope.disabled_list = {};

    $scope.level_list = function () {
        if (classification_definition == null) return [];
        var out = [];
        for (var i in classification_definition.levels_map) {
            if (!isNaN(parseInt(i))) {
                out.push(classification_definition.levels_map[i]);
            }
        }
        return out;
    };

    $scope.apply_classification_rules = function () {
        var require_lvl = {};
        var limited_to_group = {};
        var require_group = {};
        var parts_to_check = ['req', 'group', 'subgroup'];

        $scope.disabled_list = {
            "level": {},
            "req": {},
            "group": {},
            "subgroup": {}
        };

        for (var item in classification_definition.params_map) {
            var data = classification_definition.params_map[item];
            if ("require_lvl" in data) {
                require_lvl[item] = data.require_lvl;
            }
            if ("limited_to_group" in data) {
                limited_to_group[item] = data.limited_to_group;
            }
            if ("require_group" in data) {
                require_group[item] = data.require_group;
            }
        }

        for (var part_name in parts_to_check) {
            var part = $scope.active_list[parts_to_check[part_name]];
            for (var key in part) {
                var value = part[key];
                var trigger_auto_select = false;
                if (value) {
                    if (key in require_lvl) {
                        if ($scope.active_list['level_idx'] < require_lvl[key]) {
                            $scope.active_list['level_idx'] = require_lvl[key];
                            $scope.active_list['level'] = {};
                            $scope.active_list['level'][get_c12n_level_text(require_lvl[key], false)] = true;
                        }
                        var levels = $scope.level_list();
                        for (var l_idx in levels) {
                            var l = levels[l_idx];
                            if ($scope.classification_definition.levels_map[l] < require_lvl[key]) {
                                $scope.disabled_list['level'][l] = true;
                            }
                        }
                    }
                    if (key in require_group) {
                        if ($scope.active_list['group'][require_group[key]] != true) {
                            $scope.active_list['group'][require_group[key]] = true
                        }
                    }
                    if (key in limited_to_group) {
                        for (var g in $scope.classification_definition.groups_map_stl) {
                            if (g != limited_to_group[key]) {
                                $scope.disabled_list['group'][g] = true;
                                $scope.active_list['group'][g] = false;
                            }
                        }
                    }
                    if (!$scope.maximum_classification && parts_to_check[part_name] == 'group') {
                        trigger_auto_select = true;
                    }
                }
                if (trigger_auto_select) {
                    for (var auto_idx in $scope.classification_definition.groups_auto_select) {
                        $scope.active_list['group'][$scope.classification_definition.groups_auto_select[auto_idx]] = true
                    }
                }
            }
        }
    };

    $scope.$parent.setClassification = function (classification) {
        if (classification == null || classification == "") classification = $scope.classification_definition.UNRESTRICTED;
        var parts = get_c12n_parts(classification, false);

        $scope.active_list = {
            "level_idx": 0,
            "level": {},
            "req": {},
            "group": {},
            "subgroup": {}
        };
        $scope._temp_classification = classification;

        $scope.active_list["level_idx"] = parts['lvl_idx'];
        $scope.active_list["level"][get_c12n_level_text(parts['lvl_idx'], false)] = true;
        for (var r in parts['req']) {
            $scope.active_list["req"][parts['req'][r]] = true;
        }
        for (var g in parts['groups']) {
            $scope.active_list["group"][parts['groups'][g]] = true;
        }
        for (var s in parts['subgroups']) {
            $scope.active_list["subgroup"][parts['subgroups'][s]] = true;
        }
        $scope.apply_classification_rules();
    };

    $scope.toggle = function (item, type) {
        var is_disabled = $scope.disabled_list[type][item];
        if (is_disabled !== undefined && is_disabled) {
            return;
        }

        var current = $scope.active_list[type][item];
        if (current === undefined || !current) {
            if (type == "level") {
                $scope.active_list[type] = {};
                $scope.active_list['level_idx'] = $scope.classification_definition.levels_map[item];
            }
            $scope.active_list[type][item] = true;
        }
        else {
            if (type != "level") {
                $scope.active_list[type][item] = false;
            }
        }

        $scope.apply_classification_rules();
        $scope.showClassificationText();
    };

    $scope.showClassificationText = function () {
        var parts = {
            'lvl_idx': $scope.active_list.level_idx,
            'req': [],
            'groups': [],
            'subgroups': []
        };

        for (var r_key in $scope.active_list.req) {
            if ($scope.active_list.req[r_key]) {
                parts.req.push(r_key);
            }
        }

        for (var g_key in $scope.active_list.group) {
            if ($scope.active_list.group[g_key]) {
                parts.groups.push(g_key);
            }
        }

        for (var sg_key in $scope.active_list.subgroup) {
            if ($scope.active_list.subgroup[sg_key]) {
                parts.subgroups.push(sg_key);
            }
        }

        $scope._temp_classification = get_c12n_text_from_parts(parts);
    };

    if ($scope.$parent.maximum_classification === undefined) {
        $scope.maximum_classification = false;
    }
    else {
        $scope.maximum_classification = $scope.$parent.maximum_classification;
    }

    $scope.receiveClassification = function (classification_text) {
        $scope.$parent.receiveClassification(classification_text);
    }
});

/***************************************************************************************************
 * ng-utils EXTRA Directives
 */
utils.directive('classificationPicker', function () {
    return {
        templateUrl: '/static/ng-template/class_picker.html',
        replace: true,
        compile: function () {
            return {
                pre: function () {
                },
                post: function () {
                    init_modals();
                    console.log("Classification picker successfully added to the DOM. Modal windows were re-initialized...");
                }
            };
        }
    };
});

/***************************************************************************************************
 * ng-utils EXTRA Filters
 */
utils.filter('class_banner_color', function () {
    return function (s) {
        if (classification_definition == null) return "hidden";
        if (s === undefined || s == null) return "alert-success";

        var split_idx = s.indexOf("//");
        if (split_idx != -1) {
            s = s.slice(0, split_idx)
        }

        s = get_c12n_text(s, false);

        if (classification_definition.levels_styles_map[s] !== undefined) {
            return classification_definition.levels_styles_map[s].banner;
        }

        return "alert-success";
    }
});

utils.filter('class_label_color', function () {
    return function (s) {
        if (classification_definition == null) return "hidden";
        if (s === undefined || s == null) return "label-default";

        var split_idx = s.indexOf("//");
        if (split_idx != -1) {
            s = s.slice(0, split_idx)
        }

        s = get_c12n_text(s, false);

        if (classification_definition.levels_styles_map[s] !== undefined) {
            return classification_definition.levels_styles_map[s].label;
        }

        return "label-default";
    }
});

utils.filter('class_long', function () {
    return function (s) {
        if (classification_definition == null) return "";
        if (s === undefined || s == null) s = classification_definition.UNRESTRICTED;
        return get_c12n_text(s);
    }
});

utils.filter('class_sm', function () {
    return function (s) {
        if (classification_definition == null) return "";
        if (s === undefined || s == null) s = classification_definition.UNRESTRICTED;
        return get_c12n_text(s, false);
    }
});

utils.filter('class_text_color', function () {
    return function (s) {
        if (classification_definition == null) return "hidden";
        if (s === undefined || s == null) return "text-muted";
        var split_idx = s.indexOf("//");
        if (split_idx != -1) {
            s = s.slice(0, split_idx)
        }

        s = get_c12n_text(s, false);

        if (classification_definition.levels_styles_map[s] !== undefined) {
            return classification_definition.levels_styles_map[s].text;
        }

        return "text-muted";
    }
});