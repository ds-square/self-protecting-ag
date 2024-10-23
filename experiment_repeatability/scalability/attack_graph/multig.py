import json
import networkx as nx
# import os.path, sys
# sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
# import config

def generate_multig_model(network_file,graph_folder):
    with open(network_file) as nf:
        content_network = json.load(nf)
    reachability_edges = content_network["edges"]
    vulnerabilities = content_network["meta_vulnerabilities"]

    G = nx.MultiDiGraph()
    count=0
    dict_edge_props={}
    for r_edge in reachability_edges:
        src_id = r_edge["id_link"][0]
        dst_id = r_edge["id_link"][1]
        for meta_vuln in vulnerabilities:
            if dst_id == meta_vuln["device_id"]:
                precondition = meta_vuln["pre_condition"]
                postcondition = meta_vuln["post_condition"]
                vuln_id = meta_vuln["id"]

                req_node = precondition+"@"+str(src_id)
                gain_node = postcondition+"@"+str(dst_id)

                if req_node not in G.nodes(): G.add_node(req_node)
                if gain_node not in G.nodes(): G.add_node(gain_node)
                G.add_edge(req_node, gain_node, key=count)
                dict_edge_props[(req_node, gain_node, count)]={"type":"vulnerability", "metavuln_id":vuln_id}

                count+=1
    nx.set_edge_attributes(G, dict_edge_props)

    for node_1 in G.nodes():
        if "@" not in node_1: continue
        priv1,hostid1 = node_1.split("@")
        for node_2 in G.nodes():
            if node_1 == node_2 or "@" not in node_2: continue
            priv2,hostid2 = node_2.split("@")
            if hostid1 != hostid2: continue
            
            if priv1 == "ROOT" and priv2 == "USER": G.add_edge(node_1, node_2)
            if priv1 == "USER" and priv2 == "NONE": G.add_edge(node_1, node_2)
            if priv1 == "ROOT" and priv2 == "NONE": G.add_edge(node_1, node_2)  

    subfolder = network_file.split("/")
    graph_filename = subfolder[len(subfolder)-1].split(".json")[0]
    nx.write_graphml_lxml(G, graph_folder+"MULTI_"+graph_filename+".graphml")