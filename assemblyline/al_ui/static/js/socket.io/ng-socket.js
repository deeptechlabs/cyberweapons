/*
 * angular-socket-io v0.3.0
 * (c) 2014 Brian Ford http://briantford.com
 * License: MIT
 */

'use strict';

angular.module('socket-io', []).
provider('socketFactory', function () {

	// when forwarding events, prefix the event name
	var defaultPrefix = 'socket:',
	ioSocket;

	// expose to provider
	this.$get = function ($rootScope, $timeout) {

		var asyncAngularify = function (socket, callback) {
			return callback ? function () {
				var args = arguments;
				$timeout(function () {
					callback.apply(socket, args);
				}, 0);
			} : angular.noop;
		};

		return function socketFactory (options) {
			options = options || {};
			var socket = options.ioSocket || io.connect("", {"connect timeout": 500, "max reconnection attempts": 7, "transports": ['websocket', 'xhr-polling']});
			var prefix = options.prefix || defaultPrefix;
			var defaultScope = options.scope || $rootScope;

			socket.on('error', function(event){
				console.log("NG-SocketIO::Failed to connect to:", socket.socket);
			})
			socket.on('connect', function(event){
				console.log("NG-SocketIO::Connected");
			})
			socket.on('reconnecting', function(timeout, number){
				console.log("NG-SocketIO::Reconnection attemp #"+number+" failed. Next retry in " + timeout + " ms");
			})
			
			var addListener = function (eventName, callback) {
				socket.on(eventName, asyncAngularify(socket, callback));
			};

			var setConnectionCallback = function (callback){
				socket.on('connect', asyncAngularify(socket, callback));
			};
			
			var wrappedSocket = {
					connected: function (){
						return socket.socket.connected;
					},

					connecting: function (){
						return socket.socket.connecting;
					},

					get_socket: function (){
						return socket.socket;
					},

					on: addListener,
					addListener: addListener,
					setConnectionCallback: setConnectionCallback,

					emit: function (eventName, data, callback) {
						return socket.emit(eventName, data, asyncAngularify(socket, callback));
					},

					removeListener: function () {
						return socket.removeListener.apply(socket, arguments);
					},

					// when socket.on('someEvent', fn (data) { ... }),
					// call scope.$broadcast('someEvent', data)
					forward: function (events, scope) {
						if (events instanceof Array === false) {
							events = [events];
						}
						if (!scope) {
							scope = defaultScope;
						}
						events.forEach(function (eventName) {
							var prefixedEvent = prefix + eventName;
							var forwardBroadcast = asyncAngularify(socket, function (data) {
								scope.$broadcast(prefixedEvent, data);
							});
							scope.$on('$destroy', function () {
								socket.removeListener(eventName, forwardBroadcast);
							});
							socket.on(eventName, forwardBroadcast);
						});
					}
			};

			return wrappedSocket;
		};
	};
});
