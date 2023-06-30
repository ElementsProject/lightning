import json5
from flask import request, make_response, Response, stream_with_context
from flask_restx import Namespace, Resource
from .shared import call_rpc_method, verify_rune, process_help_response
from .rpc_plugin import plugin

methods_list = []
rpcns = Namespace("RPCs")
payload_model = rpcns.model("Payload", {}, None, False)

@rpcns.route("/list-methods")
class ListMethodsResource(Resource):
    @rpcns.response(200, "Success")
    @rpcns.response(500, "Server error")
    def get(self):
        """Get the list of all valid rpc methods"""
        try:
            help_response = call_rpc_method(plugin, "help", [])
            html_content = process_help_response(help_response)
            response = make_response(html_content)
            response.headers["Content-Type"] = "text/html"
            return response

        except Exception as err:
            plugin.log(f"Error: {err}", "error")
            return json5.loads(str(err)), 500

@rpcns.route("/<rpc_method>")
class RpcMethodResource(Resource):
    @rpcns.doc(security=[{"rune": [], "nodeid": []}])
    @rpcns.doc(params={"rpc_method": (f"Name of the RPC method to be called")})
    @rpcns.expect(payload_model, validate=False)
    @rpcns.response(201, "Success")
    @rpcns.response(500, "Server error")
    def post(self, rpc_method):
        """Call any valid core lightning method (check list-methods response)"""
        try:
            is_valid_rune = verify_rune(plugin, request)
            
            if "error" in is_valid_rune:
                plugin.log(f"Error: {is_valid_rune}", "error")
                raise Exception(is_valid_rune)

        except Exception as err:
            # Fix Me: Remove after lightningd checkrune is available
            if not "unknown command" in str(err).lower():
                return json5.loads(str(err)), 403
        
        try:
            if request.is_json:
                payload = request.get_json()
            else:
                payload = request.form.to_dict()
            return call_rpc_method(plugin, rpc_method, payload), 201

        except Exception as err:
            plugin.log(f"Error: {err}", "error")
            return json5.loads(str(err)), 500

@rpcns.route("/notifications")
class NotificationsResource(Resource):
    def get(self):
        try:
            def notifications_stream():
                while True:
                    from .rpc_plugin import queue
                    yield queue.get()
            return Response(stream_with_context(notifications_stream()), mimetype="text/event-stream")

        except Exception as err:        
            return json5.loads(str(err)), 500
