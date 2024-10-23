import json
import networkx as nx
# import os.path, sys
# sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
# import config

def generate_tva_model(network_file,graph_folder):
    with open(network_file) as nf:
        content_network = json.load(nf)
    reachability_edges = content_network["edges"]
    vulnerabilities = content_network["meta_vulnerabilities"]

    G = nx.DiGraph()
    for r_edge in reachability_edges:
        src_id = r_edge["id_link"][0]
        dst_id = r_edge["id_link"][1]
        for meta_vuln in vulnerabilities:
            if dst_id == meta_vuln["device_id"]:
                precondition = meta_vuln["pre_condition"]
                postcondition = meta_vuln["post_condition"]
                vuln_id = meta_vuln["id"]+"#"+dst_id

                req_node = precondition+"@"+str(src_id)
                gain_node = postcondition+"@"+str(dst_id)

                if req_node not in G.nodes(): G.add_node(req_node, type="privilege", color="green")
                if gain_node not in G.nodes(): G.add_node(gain_node, type="privilege", color="green")
                if vuln_id not in G.nodes(): G.add_node(vuln_id, type="vulnerability", color="blue")
                if (req_node, vuln_id) not in G.edges(): G.add_edge(req_node, vuln_id)
                if (vuln_id, gain_node) not in G.edges(): G.add_edge(vuln_id, gain_node)

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
    nx.write_graphml_lxml(G,graph_folder+"TVA_"+graph_filename+".graphml")
