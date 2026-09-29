#!/usr/bin/env python3

from flask import Flask, render_template, redirect, request
import requests as http

CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 8081
SWITCHES = ["00:00:00:00:00:00:00:01", "00:00:00:00:00:00:00:02"]
PUSH_FLOW_URL = f"http://{CONTROLLER_IP}:{CONTROLLER_PORT}/wm/staticflowpusher/json"
FLOW_LIST_URL = f"http://{CONTROLLER_IP}:{CONTROLLER_PORT}/wm/staticflowpusher/list/all/json"
DELETE_FLOW_URL = f"http://{CONTROLLER_IP}:{CONTROLLER_PORT}/wm/staticflowpusher/json"

BASIC_CONNECTIVITY_FLOWS = [
    # ARP flood on both switches
    {"switch": SWITCHES[0], "name": "route-arp-s1", "priority": "100",
     "eth_type": "0x0806", "active": "true", "actions": "output=flood"},
    {"switch": SWITCHES[1], "name": "route-arp-s2", "priority": "100",
     "eth_type": "0x0806", "active": "true", "actions": "output=flood"},
    
    # s1: h1->1, h2->2, h3->3, h4->3
    {"switch": SWITCHES[0], "name": "route-s1-h1", "priority": "100", "eth_type": "0x0800",
     "ipv4_dst": "10.0.0.1", "active": "true", "actions": "output=1"},
    {"switch": SWITCHES[0], "name": "route-s1-h2", "priority": "100", "eth_type": "0x0800",
     "ipv4_dst": "10.0.0.2", "active": "true", "actions": "output=2"},
    {"switch": SWITCHES[0], "name": "route-s1-h3", "priority": "100", "eth_type": "0x0800",
     "ipv4_dst": "10.0.0.3", "active": "true", "actions": "output=3"},
    {"switch": SWITCHES[0], "name": "route-s1-h4", "priority": "100", "eth_type": "0x0800",
     "ipv4_dst": "10.0.0.4", "active": "true", "actions": "output=3"},
    
    # s2: h1->3, h2->3, h3->1, h4->2
    {"switch": SWITCHES[1], "name": "route-s2-h1", "priority": "100", "eth_type": "0x0800",
     "ipv4_dst": "10.0.0.1", "active": "true", "actions": "output=3"},
    {"switch": SWITCHES[1], "name": "route-s2-h2", "priority": "100", "eth_type": "0x0800",
     "ipv4_dst": "10.0.0.2", "active": "true", "actions": "output=3"},
    {"switch": SWITCHES[1], "name": "route-s2-h3", "priority": "100", "eth_type": "0x0800",
     "ipv4_dst": "10.0.0.3", "active": "true", "actions": "output=1"},
    {"switch": SWITCHES[1], "name": "route-s2-h4", "priority": "100", "eth_type": "0x0800",
     "ipv4_dst": "10.0.0.4", "active": "true", "actions": "output=2"},
]

def push_flow(flow):
    try:
        # attempt to send flow
        resp = http.post(PUSH_FLOW_URL, json=flow, timeout=5)
        # if success return True and status code
        status = f"{resp.status_code}: {resp.text}"
        return True, status
    except http.RequestException as e:
        # if failure return False and error message
        print("Unable to push flow: {flow}")
        return False, e

def get_flows(prefix=None):
    try:
        # try to get all flows from devices on network
        resp = http.get(FLOW_LIST_URL, timeout=5)
        data = resp.json()
    except http.RequestException:
        # if it fails, return an empty dict
        return {}

    # if no prefix is assigned get all flows
    if prefix == None:
        return data

    filtered = {}
    for dpid, entries in data.items():
        kept = []

        # loop through the entries on each switch for any flow names
        for entry in entries:
            for name in entry:
                # sort the flows based on the prefix (i.e. 'route-' for flows and 'fw-' for firewall rules)
                if name.startswith(prefix):
                    kept.append(entry)

        # check if any flow entries matched the prefix and got stored
        if kept:
            filtered[dpid] = kept

    return filtered

def install_default_deny():
    # loop through the dpid's in the list of switches
    for dpid in SWITCHES:
        # build the default deny any any rule
        deny_rule = {
            "switch": dpid,
            "name": f"fw-deny-all-{dpid}",
            "priority": "101",
            "active": "true"
        }
        # push the rule
        push_flow(deny_rule)

app = Flask(__name__)

@app.route("/")
def landing():
    return render_template("index.html")

@app.route("/static_routing", methods=["GET","POST"])
def static_routing():
    result = None

    # if the method is a get just return the information for the table on the webpage.
    if request.method != "POST":
        return render_template("static_routing.html", result=result, flows=get_flows(prefix="route-"))
  
    else:
        # save values from webpage
        dpid = request.form["dpid"]
        priority = request.form["priority"]
        in_port = request.form["in_port"]
        eth_type = request.form["eth_type"]
        dst_ip = request.form["dst_ip"]
        action = request.form["action"]

        # set the action value
        if action == "flood":
            actions = "output=flood"
        elif action == "controller":
            actions = "output=controller"
        else:
            actions = f"output={action}"
 
        # build the flow
        flow = {
            "switch": dpid,
            "name": f"route_{dpid}_{in_port or 'any'}_{dst_ip or eth_type}",
            "priority": priority,
            "eth_type": eth_type,
            "active": "true",
            "actions": actions
        }

        # add port or dst ip if applicable
        if in_port:
            flow["in_port"] = in_port
        if dst_ip:
            flow["ipv4_dst"] = dst_ip

        # prepare result message
        outcome, message = push_flow(flow)
        if outcome:
            result = "Flow pushed: " + message
        else:
            result = "Error" + message

    return render_template("static_routing.html", result=result, flows=get_flows(prefix='route-'))

@app.route("/delete_flow", methods=["POST"])
def delete_flow():
    # find flow and which page to return to after deleting the flow
    name = request.form["flow_name"]
    return_to = request.form.get("return_to")
    
    try:
        # try to send message to controller to delete
        http.delete(DELETE_FLOW_URL, json={"name": name}, timeout=5)
    except http.RequestException:
        pass
    # send user back to the page they were on
    return redirect(return_to)

@app.route("/provision_basic_connectivity", methods=["POST"])
def provision_basic_connectivity():
    pushed = 0

    # loop through all of the flows in the list
    for flow in BASIC_CONNECTIVITY_FLOWS:
        outcome, _ = push_flow(flow)
        if outcome:
            pushed += 1

    result = f"Pushed {pushed}/{len(BASIC_CONNECTIVITY_FLOWS)} flows for basic connectivity on Lab4"
    return render_template("static_routing.html", result=result, switches=SWITCHES, flows=get_flows(prefix="route-"))

@app.route("/firewall", methods=["POST", "GET"])
def firewall():
    result = None
 
    if request.method != "POST":
        # If navigating to the page (i.e. sending a GET request), then install default deny, any, any
        install_default_deny()
        result = "Default deny installed — all traffic blocked."
    else:
        # save values from webpage
        dpid = request.form["dpid"]
        priority = request.form["priority"]
        in_port = request.form["in_port"]
        eth_type = request.form["eth_type"]
        src_ip = request.form["src_ip"]
        dst_ip = request.form["dst_ip"]
        l4_proto = request.form["l4_proto"]
 
        # build a firewall rule based on the info from the webpage
        fw_rule = {
            "switch": dpid,
            "name": f"fw-allow-{dpid}-{src_ip or 'any'}-{dst_ip or 'any'}-{l4_proto or 'any'}",
            "priority": priority,
            "eth_type": eth_type,
            "active": "true",
            "actions": "output=flood",
        }

        # If any of the optional fields are not empty, then add them to the rule
        if in_port:
            fw_rule["in_port"] = in_port
        if src_ip:
            fw_rule["ipv4_src"] = src_ip
        if dst_ip:
            fw_rule["ipv4_dst"] = dst_ip
        if l4_proto:
            fw_rule["ip_proto"] = l4_proto

        # push the firewall rule to the device
        ok, message = push_flow(fw_rule)
        result = ("Allow rule pushed — " if ok else "Error — ") + message
 
    return render_template("firewall.html", result=result, switches=SWITCHES, fw_rules=get_flows(prefix="fw-"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5555, debug=True)