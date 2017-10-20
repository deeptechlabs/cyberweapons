/* global angular */
'use strict';

/**
 * Main App Module
 */
function add(a, b) {
    return a + b;
}

var app = angular.module('app', ['utils', 'search', 'socket-io', 'ngAnimate', 'ui.bootstrap'])
    .factory('mySocket', function (socketFactory) {
        var mySocket = socketFactory();
        // Hearbeats
        mySocket.forward('SvcHeartbeat');
        mySocket.forward('DispHeartbeat');
        mySocket.forward('IngestHeartbeat');
        mySocket.forward('CtlHeartbeat');

        // State
        mySocket.forward('connected');

        // Agent messages
        mySocket.forward('drain');
        mySocket.forward('undrain');

        // Controller message
        mySocket.forward('start');
        mySocket.forward('stop');
        mySocket.forward('status');
        mySocket.forward('restart');

        mySocket.setConnectionCallback(function () {
            mySocket.emit("monitor", {'status': "start"});
        });
        return mySocket;
    })
    .controller('ALController', function ($scope, $http, $timeout, mySocket) {
        //Parameters vars
        $scope.valid_keys = ['ip', 'hostname', 'mac_address', 'enabled', 'profile', 'is_vm', 'vm_host',
            'platform', 'machine_info', 'vm_host_mac', 'roles'];
        $scope.host_list = null;
        $scope.host_array = null;
        $scope.profile_list = null;
        $scope.user = null;
        $scope.loading = false;
        $scope.loading_extra = false;
        $scope.current_host = null;
        $scope.current_host_backup = null;
        $scope.socket_status = "init";
        $scope.last_msg_time = null;
        $scope.new_host = false;
        $scope.vm_name = {};
        $scope.machine_type = "metal";
        $scope.searchText = "";

        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        $scope.getKeys = function (o) {
            return Object.keys(o);
        };

        $scope._set_result_state = function (data, control) {
            var mac = data.sender;
            if (mac.indexOf("Controller.") != -1) {
                mac = mac.slice(11, mac.length);
            }
            if (data.body != null && data.body.vm_mac !== undefined) {
                mac = data.body.vm_mac;
            }

            var selector = $("#" + mac + control);
            var current_selector = $("#current_" + mac + control);
            if (data.succeeded) {
                $timeout(function () {
                    selector.removeClass("action_pending");
                    selector.addClass("action_success");
                    if (current_selector != undefined) {
                        current_selector.removeClass("action_pending");
                        current_selector.addClass("action_success");
                    }
                    $timeout(function () {
                        selector.removeClass("action_success");
                        if (current_selector != undefined) {
                            current_selector.removeClass("action_success");
                        }
                    }, 2000)
                }, 500)
            }
            else {
                $timeout(function () {
                    selector.removeClass("action_pending");
                    selector.addClass("action_failed");
                    if (current_selector != undefined) {
                        current_selector.removeClass("action_pending");
                        current_selector.addClass("action_failed");
                    }
                }, 500)
            }
        };

        $scope._start_action = function (mac, control) {
            var selector = $("#" + mac + control);
            var current_selector = $("#current_" + mac + control);

            selector.removeClass("action_failed");
            selector.removeClass("action_success");
            selector.addClass("action_pending");
            if (current_selector != undefined) {
                current_selector.removeClass("action_failed");
                current_selector.removeClass("action_success");
                current_selector.addClass("action_pending");
            }
        };

        $scope.aggregate_dispatcher_stats = function (mac) {
            var temp = {
                services: {
                    up: [],
                    down: []
                },
                outstanding: 0,
                queues: {
                    ingest: 0,
                    response: 0,
                    control: 0,
                    max_inflight: 0
                },
                errors: [],
                count: 0
            };

            for (var id in $scope.host_array[mac].dispatchers) {
                //noinspection JSUnfilteredForInLoop
                var dispatcher = $scope.host_array[mac].dispatchers[id];
                for (var key in dispatcher.services.up) {
                    var s_name = dispatcher.services.up[key];
                    if (temp.services.up.indexOf(s_name) == -1) {
                        temp.services.up.push(s_name);
                    }
                }
                for (key in dispatcher.services.down) {
                    s_name = dispatcher.services.down[key];
                    if (temp.services.up.indexOf(s_name) != -1) {
                        temp.services.up.remove(s_name);
                    }
                    if (temp.services.down.indexOf(s_name) == -1) {
                        temp.services.down.push(s_name);
                    }
                }
                temp.outstanding += dispatcher.entries;
                temp.queues.ingest += dispatcher.queues.ingest;
                temp.queues.response += dispatcher.queues.response;
                temp.queues.control += dispatcher.queues.control;
                temp.queues.max_inflight += dispatcher.queues.max_inflight;
                temp.count += 1;
            }
            $scope.host_array[mac].dispatchers_stat = temp;
        };

        $scope.get_node_state = function (node) {
            var statuses = {};
            var status_count = {
                'up': 0,
                'down': 0,
                'init': 0,
                'grace-period': 0
            };

            for (var role_id in node.roles) {
                var role = node.roles[role_id];
                var status = node[role + "_status"];
                if (status !== undefined) {
                    status_count[status] += 1;
                    statuses[role] = status;
                }
            }

            if (!node.enabled) {
                return "disabled";
            }
            else {
                if (node.roles.length == status_count['up']) {
                    if (node.service_status == "error" || node.vm_status == "error") {
                        return "degraded";
                    }
                    if ($scope.is_flex(node)) {
                        return 'flex'
                    }
                    return 'up';
                }
                else if (node.roles.length == status_count['down']) {
                    return 'down';
                }
                else if (status_count['init'] != 0 || status_count['grace-period'] != 0) {
                    return "init";
                }
                else if (node.roles.length == 2 && statuses['controller'] == "up" && statuses['hostagent'] == "down") {
                    return "disabled";
                }
            }
            return "degraded";

            /*
             {'disabled': !host.enabled||(host.controller=='up'&&host.hostagent_status=='down'),
             'up': host.controller=='up'&&host.hostagent_status=='up'&&!is_flex(host),
             'flex': host.controller=='up'&&host.hostagent_status=='up'&&is_flex(host),
             'down': host.controller=='down'&&host.hostagent_status=='down'&&host.enabled,
             'degraded': host.controller=='down'&&host.hostagent_status=='up'&&host.enabled}
             */

        };

        //SocketIO Agent's RPC
        $scope.$on('socket:drain', function (event, data) {
            console.log('Socket-IO::drain', data);
            $scope._set_result_state(data, "_pause")
        });

        $scope.$on('socket:undrain', function (event, data) {
            console.log('Socket-IO::undrain', data);
            $scope._set_result_state(data, "_resume");
        });

        //SocketIO Controller's RPC
        $scope.$on('socket:start', function (event, data) {
            console.log('Socket-IO::start', data);
            $scope._set_result_state(data, "_start");
        });
        $scope.$on('socket:stop', function (event, data) {
            console.log('Socket-IO::stop', data);
            $scope._set_result_state(data, "_stop");
        });
        $scope.$on('socket:restart', function (event, data) {
            console.log('Socket-IO::restart', data);
            $scope._set_result_state(data, "_restart");
        });
        $scope.$on('socket:status', function (event, data) {
            console.log('Socket-IO::status', data);
            $scope._set_result_state(data, "_status");
        });

        //SocketIO Heartbeats
        $scope.$on('socket:CtlHeartbeat', function (event, data) {
            var cur_time = new Date().getTime();
            if (data.sender === undefined) {
                return;
            }
            if ($scope.host_array == null || $scope.host_array === undefined) {
                return;
            }

            try {
                if (!$scope.host_array.hasOwnProperty(data.body.mac)) {
                    return;
                }

                var mac = data.body.mac;

                $scope.last_msg_time = cur_time;
                $scope.host_array[mac]['controller_status'] = 'up';
                $scope.host_array[mac]['controller_timer'] = cur_time;
            }
            catch (e) {
                console.log('Socket-IO::CtlHeartbeat [ERROR] Invalid message', data, e);
            }
        });

        $scope.$on('socket:IngestHeartbeat', function (event, data) {
            var cur_time = new Date().getTime();
            if (data.sender === undefined) {
                return;
            }
            if ($scope.host_array == null || $scope.host_array === undefined) {
                return;
            }

            try {
                if (!$scope.host_array.hasOwnProperty(data.body.hostinfo.mac_address)) {
                    return;
                }

                var mac = data.body.hostinfo.mac_address;

                $scope.last_msg_time = cur_time;
                $scope.host_array[mac]['middleman_status'] = 'up';
                $scope.host_array[mac]['middleman_timer'] = cur_time;

                if ($scope.host_array[mac].middleman_stat == undefined) {
                    $scope.host_array[mac].middleman_stat = {
                        count: 0,
                        index: 0,
                        'inflight': [],
                        'ingest': [],
                        'ingesting.critical': [],
                        'ingesting.high': [],
                        'ingesting.low': [],
                        'ingesting.medium': [],
                        'queues.critical': [],
                        'queues.high': [],
                        'queues.low': [],
                        'queues.medium': [],
                        'up_hours': [],
                        'waiting': [],
                        'ingest.submissions_completed': [],
                        'ingest.bytes_completed': [],
                        'ingest.bytes_ingested': [],
                        'ingest.skipped': [],
                        'ingest.files_completed': [],
                        'ingest.whitelisted': [],
                        'ingest.duplicates': []
                    }
                }

                try {
                    var index_jump = 1;
                    var cur_mm_time = Math.floor(new Date().getTime() / 1000);
                    if ($scope.last_mm_hb !== undefined) {
                        index_jump = cur_mm_time - $scope.last_mm_hb;
                    }

                    if (index_jump > 0) {
                        $scope.host_array[mac].middleman_stat.index += index_jump;
                        for (var x = index_jump - 1; x > 0; x--) {
                            $scope.host_array[mac].middleman_stat['ingest.submissions_completed'][($scope.host_array[mac].middleman_stat.index - x) % 60] = 0;
                            $scope.host_array[mac].middleman_stat['ingest.bytes_completed'][($scope.host_array[mac].middleman_stat.index - x) % 60] = 0;
                            $scope.host_array[mac].middleman_stat['ingest.bytes_ingested'][($scope.host_array[mac].middleman_stat.index - x) % 60] = 0;
                            $scope.host_array[mac].middleman_stat['ingest.files_completed'][($scope.host_array[mac].middleman_stat.index - x) % 60] = 0;
                            $scope.host_array[mac].middleman_stat['ingest.skipped'][($scope.host_array[mac].middleman_stat.index - x) % 60] = 0;
                            $scope.host_array[mac].middleman_stat['ingest.whitelisted'][($scope.host_array[mac].middleman_stat.index - x) % 60] = 0;
                            $scope.host_array[mac].middleman_stat['ingest.duplicates'][($scope.host_array[mac].middleman_stat.index - x) % 60] = 0;
                        }

                        $scope.host_array[mac].middleman_stat['ingest.submissions_completed'][$scope.host_array[mac].middleman_stat.index % 60] = data.body['ingest.submissions_completed'];
                        $scope.host_array[mac].middleman_stat['ingest.bytes_completed'][$scope.host_array[mac].middleman_stat.index % 60] = data.body['ingest.bytes_completed'];
                        $scope.host_array[mac].middleman_stat['ingest.bytes_ingested'][$scope.host_array[mac].middleman_stat.index % 60] = data.body['ingest.bytes_ingested'];
                        $scope.host_array[mac].middleman_stat['ingest.files_completed'][$scope.host_array[mac].middleman_stat.index % 60] = data.body['ingest.files_completed'];
                        $scope.host_array[mac].middleman_stat['ingest.skipped'][$scope.host_array[mac].middleman_stat.index % 60] = data.body['ingest.skipped'];
                        $scope.host_array[mac].middleman_stat['ingest.whitelisted'][$scope.host_array[mac].middleman_stat.index % 60] = data.body['ingest.whitelisted'];
                        $scope.host_array[mac].middleman_stat['ingest.duplicates'][$scope.host_array[mac].middleman_stat.index % 60] = data.body['ingest.duplicates'];
                    } else {
                        $scope.host_array[mac].middleman_stat['ingest.submissions_completed'][$scope.host_array[mac].middleman_stat.index % 60] += data.body['ingest.submissions_completed'];
                        $scope.host_array[mac].middleman_stat['ingest.bytes_completed'][$scope.host_array[mac].middleman_stat.index % 60] += data.body['ingest.bytes_completed'];
                        $scope.host_array[mac].middleman_stat['ingest.bytes_ingested'][$scope.host_array[mac].middleman_stat.index % 60] += data.body['ingest.bytes_ingested'];
                        $scope.host_array[mac].middleman_stat['ingest.files_completed'][$scope.host_array[mac].middleman_stat.index % 60] += data.body['ingest.files_completed'];
                        $scope.host_array[mac].middleman_stat['ingest.skipped'][$scope.host_array[mac].middleman_stat.index % 60] += data.body['ingest.skipped'];
                        $scope.host_array[mac].middleman_stat['ingest.whitelisted'][$scope.host_array[mac].middleman_stat.index % 60] += data.body['ingest.whitelisted'];
                        $scope.host_array[mac].middleman_stat['ingest.duplicates'][$scope.host_array[mac].middleman_stat.index % 60] += data.body['ingest.duplicates'];
                    }

                    var shard = data.body['shard'];
                    $scope.host_array[mac].middleman_stat['inflight'][shard] = data.body['inflight'];
                    $scope.host_array[mac].middleman_stat['ingest'][shard] = data.body['ingest'];
                    $scope.host_array[mac].middleman_stat['ingesting.critical'][shard] = data.body['ingesting']['critical'];
                    $scope.host_array[mac].middleman_stat['ingesting.high'][shard] = data.body['ingesting']['high'];
                    $scope.host_array[mac].middleman_stat['ingesting.low'][shard] = data.body['ingesting']['low'];
                    $scope.host_array[mac].middleman_stat['ingesting.medium'][shard] = data.body['ingesting']['medium'];
                    $scope.host_array[mac].middleman_stat['queues.critical'][shard] = data.body['queues']['critical'];
                    $scope.host_array[mac].middleman_stat['queues.high'][shard] = data.body['queues']['high'];
                    $scope.host_array[mac].middleman_stat['queues.low'][shard] = data.body['queues']['low'];
                    $scope.host_array[mac].middleman_stat['queues.medium'][shard] = data.body['queues']['medium'];
                    $scope.host_array[mac].middleman_stat['up_hours'][shard] = data.body['up_hours'];
                    $scope.host_array[mac].middleman_stat['waiting'][shard] = data.body['waiting'];

                    $scope.last_mm_hb = cur_mm_time;

                    if (shard != 0) {
                        return;
                    }

                    $scope.host_array[mac].middleman_stat.count = $scope.host_array[mac].middleman_stat['inflight'].length;
                    data.body['inflight'] = $scope.host_array[mac].middleman_stat['inflight'].reduce(add, 0);
                    data.body['ingest'] = $scope.host_array[mac].middleman_stat['ingest'].reduce(add, 0);
                    data.body['ingesting']['critical'] = $scope.host_array[mac].middleman_stat['ingesting.critical'].reduce(add, 0) / $scope.host_array[mac].middleman_stat['ingesting.critical'].length;
                    data.body['ingesting']['high'] = $scope.host_array[mac].middleman_stat['ingesting.high'].reduce(add, 0) / $scope.host_array[mac].middleman_stat['ingesting.high'].length;
                    data.body['ingesting']['low'] = $scope.host_array[mac].middleman_stat['ingesting.low'].reduce(add, 0) / $scope.host_array[mac].middleman_stat['ingesting.low'].length;
                    data.body['ingesting']['medium'] = $scope.host_array[mac].middleman_stat['ingesting.medium'].reduce(add, 0) / $scope.host_array[mac].middleman_stat['ingesting.medium'].length;
                    data.body['queues']['critical'] = $scope.host_array[mac].middleman_stat['queues.critical'].reduce(add, 0);
                    data.body['queues']['high'] = $scope.host_array[mac].middleman_stat['queues.high'].reduce(add, 0);
                    data.body['queues']['low'] = $scope.host_array[mac].middleman_stat['queues.low'].reduce(add, 0);
                    data.body['queues']['medium'] = $scope.host_array[mac].middleman_stat['queues.medium'].reduce(add, 0);
                    data.body['up_hours'] = $scope.host_array[mac].middleman_stat['up_hours'].reduce(add, 0) / $scope.host_array[mac].middleman_stat['up_hours'].length;
                    data.body['waiting'] = $scope.host_array[mac].middleman_stat['waiting'].reduce(add, 0);

                    data.body['ingest.submissions_completed'] = $scope.host_array[mac].middleman_stat['ingest.submissions_completed'].reduce(add, 0);
                    data.body['ingest.bytes_completed'] = $scope.host_array[mac].middleman_stat['ingest.bytes_completed'].reduce(add, 0);
                    data.body['ingest.bytes_ingested'] = $scope.host_array[mac].middleman_stat['ingest.bytes_ingested'].reduce(add, 0);
                    data.body['ingest.files_completed'] = $scope.host_array[mac].middleman_stat['ingest.files_completed'].reduce(add, 0);
                    data.body['ingest.skipped'] = $scope.host_array[mac].middleman_stat['ingest.skipped'].reduce(add, 0);
                    data.body['ingest.whitelisted'] = $scope.host_array[mac].middleman_stat['ingest.whitelisted'].reduce(add, 0);
                    data.body['ingest.duplicates'] = $scope.host_array[mac].middleman_stat['ingest.duplicates'].reduce(add, 0);
                }
                catch (e) {
                    console.log('Socket-IO::IngestHeartbeat [ERROR] Invalid message', data, e);
                }

                $scope.host_array[mac].middleman = data.body;
            }
            catch (e) {
                console.log('Socket-IO::IngestHeartbeat [ERROR] Invalid message', data, e);
            }
        });

        $scope.$on('socket:SvcHeartbeat', function (event, data) {
            var cur_time = new Date().getTime();
            if (data.sender === undefined || data.sender == "runservice_live") {
                return;
            }
            if ($scope.host_array == null || $scope.host_array === undefined) {
                return;
            }

            try {
                if (!$scope.host_array.hasOwnProperty(data.body.mac)) {
                    $scope.host_array[data.body.mac] = data.body.registration;
                    $scope.host_list.push($scope.host_array[data.body.mac]);
                }

                $scope.last_msg_time = cur_time;
                var worker_count = 0;
                var svc_count = 0;
                var services = [];
                var local_services = [];
                var override = $scope.vm_name[data.body.mac];
                if (data.body.services != null) {
                    for (var key in data.body.services.details) {
                        if (key != "status") {
                            worker_count += data.body.services.details[key].num_workers;
                            svc_count += 1;
                            services.push(key);
                        }
                    }
                    for (var svc_key in data.body.profile_definition.services) {
                        if (services.indexOf(svc_key) == -1) {
                            services.push(svc_key);
                        }
                    }
                    local_services = services.slice()
                }

                var vm_count = null;
                var vms = [];
                if (data.body.vmm !== undefined && data.body.vmm != null) {
                    if (data.body.vmm.length == undefined) {
                        vm_count = $scope.getKeys(data.body.vmm).length;
                        for (key in data.body.vmm) {
                            var vm = data.body.vmm[key];
                            vms.push(key);
                            $scope.vm_name[vm['mac_address']] = {
                                name: key,
                                parent_name: $scope.host_array[data.body.mac]['hostname'],
                                parent_mac: data.body.mac
                            };
                            try {
                                svc_count += $scope.host_array[vm['mac_address']].resources['service.count'];
                                worker_count += $scope.host_array[vm['mac_address']].resources['worker.count'];
                                services.push($scope.host_array[vm['mac_address']].resources['service.list'])
                            } catch (e) {
                            }
                        }
                    }
                    else {
                        vm_count = data.body.vmm.length;
                    }

                }
                if (override !== undefined && override != null) {
                    $scope.host_array[data.body.mac]['hostname'] = override.name;
                    $scope.host_array[data.body.mac]['parent_name'] = override.parent_name;
                    $scope.host_array[data.body.mac]['parent_mac'] = override.parent_mac;
                }
                $scope.last_msg_time = cur_time;
                $scope.host_array[data.body.mac]['last_hb'] = data.body;
                $scope.host_array[data.body.mac]['hostagent_status'] = 'up';
                $scope.host_array[data.body.mac]['hostagent_timer'] = cur_time;

                if ($scope.host_array[data.body.mac]['resources'] == null) {
                    $scope.host_array[data.body.mac]['resources'] = data.body.resources;
                    $scope.host_array[data.body.mac]['resources']['worker.count'] = worker_count;
                    $scope.host_array[data.body.mac]['resources']['service.count'] = svc_count;
                    $scope.host_array[data.body.mac]['resources']['vm.count'] = vm_count;
                    $scope.host_array[data.body.mac]['resources']['service.list'] = services.join(" ");
                    $scope.host_array[data.body.mac]['resources']['services'] = local_services;
                    $scope.host_array[data.body.mac]['resources']['vm.list'] = vms.join(" ");
                }
                else {
                    $scope.host_array[data.body.mac]['resources']['cpu_usage.percent'] = data.body.resources['cpu_usage.percent'];
                    $scope.host_array[data.body.mac]['resources']['disk_usage.percent'] = data.body.resources['disk_usage.percent'];
                    $scope.host_array[data.body.mac]['resources']['disk_usage.free'] = data.body.resources['disk_usage.free'];
                    $scope.host_array[data.body.mac]['resources']['mem_usage.percent'] = data.body.resources['mem_usage.percent'];
                    $scope.host_array[data.body.mac]['resources']['worker.count'] = worker_count;
                    $scope.host_array[data.body.mac]['resources']['service.count'] = svc_count;
                    $scope.host_array[data.body.mac]['resources']['vm.count'] = vm_count;
                    $scope.host_array[data.body.mac]['resources']['service.list'] = services.join(" ");
                    $scope.host_array[data.body.mac]['resources']['services'] = local_services;
                    $scope.host_array[data.body.mac]['resources']['vm.list'] = vms.join(" ");
                }

                // Debugging only
                if ($scope.debug) {
                    data['ui_time'] = cur_time;
                    //console.log('Socket-IO::SvcHeartbeat message', data);
                }
            }
            catch (e) {
                console.log('Socket-IO::SvcHeartbeat [ERROR] Invalid message', data, e);
            }

        });

        $scope.$on('socket:DispHeartbeat', function (event, data) {
            var cur_time = new Date().getTime();
            if (data.sender === undefined) {
                return;
            }
            if ($scope.host_array == null || $scope.host_array === undefined) {
                return;
            }

            try {
                if (!$scope.host_array.hasOwnProperty(data.body.hostinfo.mac_address)) {
                    return;
                }

                var mac = data.body.hostinfo.mac_address;

                $scope.last_msg_time = cur_time;
                $scope.host_array[mac]['dispatcher_status'] = 'up';
                $scope.host_array[mac]['dispatcher_timer'] = cur_time;
                if ($scope.host_array[mac]['dispatchers'] === undefined || $scope.host_array[mac]['dispatchers'] == null) {
                    $scope.host_array[mac]['dispatchers'] = {}
                }
                $scope.host_array[mac]['dispatchers'][data.body.shard] = {
                    'entries': data.body.entries,
                    'queues': data.body.queues,
                    'services': {up: [], down: []},
                    'enabled': true
                };
                for (var service in data.body.services) {
                    var item = data.body.services[service];
                    if (item.is_up) {
                        $scope.host_array[mac]['dispatchers'][data.body.shard].services.up.push(service);
                    }
                    else {
                        $scope.host_array[mac]['dispatchers'][data.body.shard].services.down.push(service);
                    }
                }
                $scope.aggregate_dispatcher_stats(mac);

                if ($scope.host_array[mac]['resources'] == null) {
                    $scope.host_array[mac]['resources'] = data.body.resources;
                    $scope.host_array[mac]['resources']['dispatcher.count'] = $scope.getKeys($scope.host_array[mac]['dispatchers']).length;
                }
                else {
                    $scope.host_array[mac]['resources']['cpu_usage.percent'] = data.body.resources['cpu_usage.percent'];
                    $scope.host_array[mac]['resources']['disk_usage.percent'] = data.body.resources['disk_usage.percent'];
                    $scope.host_array[mac]['resources']['disk_usage.free'] = data.body.resources['disk_usage.free'];
                    $scope.host_array[mac]['resources']['mem_usage.percent'] = data.body.resources['mem_usage.percent'];
                    $scope.host_array[mac]['resources']['dispatcher.count'] = $scope.getKeys($scope.host_array[mac]['dispatchers']).length;
                }


                // Debugging only
                if ($scope.debug) {
                    data['ui_time'] = cur_time;
                    //console.log('Socket-IO::DispHeartbeat message', data);
                }
            }
            catch (e) {
                console.log('Socket-IO::DispHeartbeat [ERROR] Invalid message', data, e);
            }

        });

        // SocketIO State
        $scope.$on('socket:connected', function (event, data) {
            $scope.socket_status = 'ok';
            console.log('Socket-IO::Connected', data);
        });

        //Error handling
        $scope.error = '';
        $scope.success = '';

        //Filtering
        $scope.doSearch = function (row) {
            if (row === undefined) return false;
            if ($scope.machine_type == "metal" && row.is_vm) return false;
            if ($scope.machine_type == "vm" && !row.is_vm) return false;

            if ($scope.searchText == "") return true;
            var re = new RegExp($scope.searchText, "i");
            if (row.resources != null) {
                return ((re.test(row.mac_address) || re.test(row.hostname) || re.test(row.parent_name) || re.test(row.parent_mac) || re.test(row.ip) || re.test(row.profile) || re.test(row.resources['service.list']) || re.test(row.resources['vm.list'])));
            }
            else {
                return ((re.test(row.mac_address) || re.test(row.hostname) || re.test(row.parent_name) || re.test(row.parent_mac) || re.test(row.ip) || re.test(row.profile)));
            }
        };

        //User editing
        $("#myModal").on('hidden.bs.modal', function () {
            /**
             * We usually don't want to mix match JQuery events with Angular and
             * we should always let angular deal with the data bindings.
             *
             * We have no choice in this case bacause we need to trap the modal
             * window close and reset the data-bindings in angular.
             *
             * In this case you need to call $scope.$apply(); for this to take place.
             * */
            if ($scope.current_host_backup != null) {
                for (var key in $scope.current_host_backup) {
                    if ($scope.valid_keys.indexOf(key) != -1) {
                        $scope.current_host[key] = $scope.current_host_backup[key];
                    }
                }
            }
            $scope.current_host = null;
            $scope.current_host_backup = null;
            $scope.$apply();
        });

        $scope.viewHost = function (host) {
            $scope.current_host_backup = jQuery.extend(true, {}, host);
            $scope.current_host = host;

            $scope.error = '';
            $scope.success = '';

            $("#myModal").modal('show');
        };

        $scope.flip = function (id) {
            $("#" + id).toggleClass("flipped");
        };

        $scope.is_flex = function (host) {
            return host.profile.indexOf("flex") == 0;

        };

        $scope.del = function () {

            $scope.error = '';
            $scope.success = '';
            swal({
                    title: "Remove Node",
                    text: "\n\nAre you sure you want to remove the current node?\n\n",
                    type: "info",
                    showCancelButton: true,
                    confirmButtonColor: "#d9534f",
                    confirmButtonText: "Yes, do it!",
                    closeOnConfirm: true
                },
                function () {
                    $scope.loading_extra = true;

                    var mac = $scope.current_host.mac_address;
                    var name = $scope.current_host.hostname.toUpperCase();

                    $http({
                        method: 'DELETE',
                        url: "/api/v3/host/" + mac + "/",
                        data: $scope.current_host
                    })
                        .success(function () {
                            $scope.loading_extra = false;
                            $scope.current_host_backup = null;
                            $("#myModal").modal('hide');
                            $scope.success = "Host " + name + " [" + mac + "] successfully deleted!";
                            $timeout(function () {
                                $scope.success = "";
                                for (var h in $scope.host_list) {
                                    var item = $scope.host_list[h];
                                    if (item.mac_address == mac) {
                                        delete $scope.host_array[mac];
                                    }
                                }
                            }, 2000)
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
                });
        };

        //Save params
        $scope.save = function () {
            var data = jQuery.extend(true, {}, $scope.current_host);
            for (var key in data) {
                if ($scope.valid_keys.indexOf(key) == -1) {
                    delete data[key];
                }
            }

            $scope.error = '';
            $scope.success = '';
            $scope.loading_extra = true;

            $http({
                method: 'POST',
                url: "/api/v3/host/" + $scope.current_host.mac_address + "/",
                data: data
            })
                .success(function () {
                    $scope.loading_extra = false;
                    $scope.current_host_backup = null;
                    $("#myModal").modal('hide');
                    $scope.success = "Host " + $scope.current_host.hostname.toLowerCase() + " [" + $scope.current_host.mac_address + "] successfully updated!";
                    $timeout(function () {
                        $scope.success = ""
                    }, 2000)
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

        $scope.validate_vm_for_host = function (host, vm_name) {
            var valid = true;
            if (!('last_hb' in host)) {
                return valid;
            }
            var hb_vmms = host.last_hb.vmm;
            if (vm_name in hb_vmms) {
                var vm_item = hb_vmms[vm_name];
                if (vm_item.mac_address in $scope.host_array) {
                    var vm_data = $scope.host_array[vm_item.mac_address];
                    if (vm_data['vm_status'] == 'error' || vm_data['service_status'] == 'error') {
                        valid = false;
                    }
                }
                else {
                    valid = false;
                }
            }
            else {
                valid = false;
            }

            return valid;
        };

        $scope.validate_profile = function (item) {
            var valid = true;
            item['service_status'] = 'ok';
            item['vm_status'] = 'ok';

            try {
                var item_profile = item.last_hb.profile_definition;
                var hb_services = item.last_hb.services.details;
            }
            catch (e) {
                return valid;
            }
            for (var svc_name in item_profile.services) {
                var hb_service = hb_services[svc_name];
                if (hb_service == undefined) {
                    item['service_status'] = 'error';
                    valid = false;
                    break;
                }
                if (hb_services[svc_name].num_workers != item_profile.services[svc_name].workers) {
                    item['service_status'] = 'error';
                    valid = false;
                    break;
                }
            }

            var hb_vmms = item.last_hb.vmm;
            if (hb_vmms == null) {
                return valid;
            }

            for (var vm_name in item_profile.virtual_machines) {
                var vm = item_profile.virtual_machines[vm_name];
                for (var i = 1; i <= vm.num_instances; i++) {
                    var vm_inst_name = vm_name + "." + i;
                    if (vm_inst_name in hb_vmms) {
                        var vm_item = hb_vmms[vm_inst_name];
                        if (vm_item.mac_address in $scope.host_array) {
                            var vm_data = $scope.host_array[vm_item.mac_address];
                            if (vm_data['vm_status'] == 'error' || vm_data['service_status'] == 'error') {
                                item['vm_status'] = 'error';
                                valid = false;
                                break;
                            }
                        }
                        else {
                            item['vm_status'] = 'error';
                            valid = false;
                            break;
                        }
                    }
                    else {
                        item['vm_status'] = 'error';
                        valid = false;
                        break;
                    }
                }
            }

            return valid;
        };

        $scope.monitor_hosts = function () {
            var timer = 10000;
            var cur_time = new Date().getTime();
            var to_del = [];

            for (var mac in $scope.host_array) {
                var item = $scope.host_array[mac];
                if ((item['middleman_timer'] + timer - cur_time) < 0) {
                    if (!mySocket.connected()) {
                        item['middleman_status'] = 'init';
                    }
                    else {
                        if (item['middleman_status'] == 'init') {
                            item['middleman_status'] = 'grace-period';
                        }
                        else {
                            item['middleman_status'] = 'down';
                        }
                    }
                }
                if ((item['dispatcher_timer'] + timer - cur_time) < 0) {
                    if (!mySocket.connected()) {
                        item['dispatcher_status'] = 'init';
                    }
                    else {
                        if (item['dispatcher_status'] == 'init') {
                            item['dispatcher_status'] = 'grace-period';
                        }
                        else {
                            item['dispatcher_status'] = 'down';
                        }
                    }
                }
                if ((item['hostagent_timer'] + timer - cur_time) < 0) {
                    if (!mySocket.connected()) {
                        item['hostagent_status'] = 'init';
                    }
                    else {
                        if (item['hostagent_status'] == 'init') {
                            item['hostagent_status'] = 'grace-period';
                        }
                        else {
                            item['hostagent_status'] = 'down';
                            if (item['is_vm']) {
                                to_del.push(mac);
                            }
                        }
                    }
                }
                if ((item['controller_timer'] + timer - cur_time) < 0) {
                    if (!mySocket.connected()) {
                        item['controller_status'] = 'init';
                    }
                    else {
                        if (item['controller_status'] == 'init') {
                            item['controller_status'] = 'grace-period';
                        }
                        else {
                            item['controller_status'] = 'down';
                        }
                    }
                }

                $scope.validate_profile(item);
            }

            for (var idx in to_del) {
                var del_item = $scope.host_array[to_del[idx]];
                $scope.host_list.splice($scope.host_list.indexOf(del_item), 1);
                delete $scope.host_array[to_del[idx]];


            }

            if (!mySocket.connected()) {
                $scope.socket_status = "fail";
                console.log("Socket-IO is disconnected.")
            }

            $timeout($scope.monitor_hosts, timer);
            $scope.reload_data();
        };

        $scope.wait_for_connection = function () {
            if (!mySocket.connected()) {
                $timeout(function () {
                    $scope.wait_for_connection()
                }, 50);
            }
            else {
                $scope.monitor_hosts();
            }
        };

        //Load params from datastore
        $scope.start = function () {
            $scope.load_data();
        };

        $scope.reload_data = function () {
            if ($scope.loading_extra) {
                return
            }

            $scope.loading_extra = true;

            $http({
                method: 'GET',
                url: "/api/v3/host/list/"
            })
                .success(function (data) {
                    var temp_macs = [];
                    var to_del_mac = [];
                    var temp_host_list = data.api_response.items;

                    $scope.loading_extra = false;

                    for (var h in temp_host_list) {
                        var item = temp_host_list[h];
                        temp_macs.push(item.mac_address);
                        if (!(item.mac_address in $scope.host_array)) {
                            $scope.host_list.push(item);
                            item['hostagent_status'] = 'init';
                            item['hostagent_timer'] = 0;
                            item['middleman_status'] = 'init';
                            item['middleman_timer'] = 0;
                            item['dispatcher_status'] = 'init';
                            item['dispatcher_timer'] = 0;
                            item['controller_status'] = 'init';
                            item['controller_timer'] = 0;
                            item['resources'] = null;
                            $scope.host_array[item.mac_address] = item
                        }
                    }

                    for (var mac in $scope.host_array) {
                        if (!(mac in temp_macs)) {
                            to_del_mac.push(mac);
                        }
                    }

                    for (mac in to_del_mac) {
                        delete $scope.host_array[mac];
                    }

                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (data == "" || status == 502 || status == 504) {
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
            $scope.loading = true;

            $http({
                method: 'GET',
                url: "/api/v3/host/list/"
            })
                .success(function (data) {
                    $scope.loading = false;
                    $scope.host_list = data.api_response.items;
                    $scope.host_array = {};

                    for (var h in $scope.host_list) {
                        var item = $scope.host_list[h];
                        item['hostagent_status'] = 'init';
                        item['hostagent_timer'] = 0;
                        item['middleman_status'] = 'init';
                        item['middleman_timer'] = 0;
                        item['dispatcher_status'] = 'init';
                        item['dispatcher_timer'] = 0;
                        item['controller_status'] = 'init';
                        item['controller_timer'] = 0;
                        item['resources'] = null;
                        $scope.host_array[item.mac_address] = item
                    }

                    $scope.wait_for_connection();
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

            $scope.loading_extra = true;
            $http({
                method: 'GET',
                url: "/api/v3/profile/list/"
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.profile_list = data.api_response.items;
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
            $http({
                method: 'GET',
                url: "/api/v3/dashboard/shards/"
            })
                .success(function (data) {
                    $scope.dispatcher_shards_count = data.api_response.dispatcher;
                    $scope.middleman_shards_count = data.api_response.middleman;
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


        /*
         *
         * 		ACTIONS
         *
         * */

        $scope.showVMs = function (mac) {
            $scope.searchText = mac;
            $scope.machine_type = 'vm';
        };

        $scope.resetFilter = function () {
            $scope.searchText = "";
            $scope.machine_type = 'metal';
        };

        $scope.flipAll = function () {
            $("div[name=host_card]").each(function () {
                var mac = this.id;
                $scope.flip(mac);
            });
        };

        $scope._action_wrapper = function (action, mac) {
            console.log(action, mac);

            $scope._start_action(mac, "_" + action);

            $scope.loading_extra = true;
            $http({
                method: 'GET',
                url: "/api/v3/controller/" + action + "/" + mac + "/"
            })
                .success(function () {
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

        $scope._global_action_wrapper = function (action) {
            console.log(action, "all");
            $("span[name=action_" + action + "]").each(function () {
                var mac = this.id.substr(0, this.id.indexOf("_"));

                if ($("#" + mac).hasClass('flipped')) {
                    $scope["action_" + action](mac);
                }
            });
        };

        //
        //		Agent's actions
        //

        $scope.action_pause = function (mac) {
            $scope._action_wrapper("pause", mac);
        };

        $scope.action_resume = function (mac) {
            $scope._action_wrapper("resume", mac);
        };

        //
        //		Controller's actions
        //
        $scope.action_start = function (mac) {
            $scope._action_wrapper("start", mac);
        };

        $scope.action_stop = function (mac) {
            $scope._action_wrapper("stop", mac);
        };

        $scope.action_status = function (mac) {
            $scope._action_wrapper("status", mac);
        };

        $scope.action_restart = function (mac) {
            $scope._action_wrapper("restart", mac);
        };


        //
        //		GLOBAL ACTIONS
        //
        $scope.action_pause_all = function () {
            $scope._global_action_wrapper("pause")
        };

        $scope.action_resume_all = function () {
            $scope._global_action_wrapper("resume")
        };

        $scope.action_start_all = function () {
            $scope._global_action_wrapper("start")
        };

        $scope.action_stop_all = function () {
            $scope._global_action_wrapper("stop")
        };

        $scope.action_status_all = function () {
            $scope._global_action_wrapper("status")
        };

        $scope.action_restart_all = function () {
            $scope._global_action_wrapper("restart")
        };
    });
