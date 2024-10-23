import random

from graph_runner import GraphRunner



class SequentialGraphRunner():

    def do_run(SNAPSHOT_ID,host_to_graph,host_to_cve_to_cpe,host_to_validation_inventory_inert,host_to_cpe_to_cpe_mod,
               host_to_cpe_vendor_to_cpe,host_to_cpe_product_to_cpe,host_to_cpe_version_to_cpe,
               host_to_cve_to_cpe_tree_vendor,host_to_cve_to_cpe_tree_product,host_to_cve_to_cpe_tree_version):

        # Dumb Run
        # Use the graph as it is
        print("1 - Dumb Run")

        # Rationale:
        # 1 Take the highest ranking element
        # 2 Validate it
        # 3 Update graph


        def run_1_exec(local_host_id,local_cve_to_cpe,local_graph,log_mod,
                    local_validation_inventory_inert,local_cpe_to_cpe_mod,
                    local_cpe_vendor_to_cpe,local_cpe_product_to_cpe,local_cpe_version_to_cpe):
            # Fetch data
            open_cve = set()
            confirmed_cve = set()
            discarded_cve = set()

            open_cpe = set()
            confirmed_cpe = set()
            discarded_cpe = set()

            for cve in local_cve_to_cpe:
                open_cve.add(cve)
                for and_cpe in local_cve_to_cpe[cve]:
                    for cpe in and_cpe:
                        open_cpe.add(cpe)
            
            # Copy graph
            rolling_graph = local_graph.copy()
            root = rolling_graph.nodes[local_host_id]

            # Logfile
            node_sequence_log=open(file="CVE-Search-Validator/graphs/sequence/"+SNAPSHOT_ID+"_"+local_host_id+"_dumb_node_sequence_"+log_mod+".csv",mode="w",encoding="utf-8")
            cpe_sequence_log=open(file="CVE-Search-Validator/graphs/sequence/"+SNAPSHOT_ID+"_"+local_host_id+"_dumb_cpe_sequence_"+log_mod+".csv",mode="w",encoding="utf-8")

            node_sequence_log.write("Node;Score;Response\n")
            cpe_sequence_log.write("#Open_CVE;#Open_CPE\n")

            # Validation loop
            while (len(open_cpe)>0) and (len(open_cve)>0) and (len(rolling_graph)>2):
                selected_node = ""
                selected_node_pool = set()
                selected_node_type = ""
                selected_node_score = 0
                for neighbor in rolling_graph.neighbors(root["name"]):
                    if rolling_graph.nodes[neighbor]["score"] > selected_node_score:
                        selected_node_pool = set()
                        selected_node_pool.add(neighbor)
                        selected_node_score = rolling_graph.nodes[neighbor]["score"]
                        selected_node_type = rolling_graph.nodes[neighbor]["node_subtype"]
                        selected_node = neighbor
                    elif rolling_graph.nodes[neighbor]["score"] == selected_node_score:
                        selected_node_pool.add(neighbor)
                
                if len(selected_node_pool) > 1:
                    selected_node = random.choice(sorted(selected_node_pool))

                # I have one node
                if selected_node != "":
                    # Have a response according to inventory
                    validation_response = GraphRunner.validate_node(selected_node,local_validation_inventory_inert,selected_node_type)

                    if validation_response == True:
                        neighbor_list = list(rolling_graph.neighbors(selected_node))
                        if (len(neighbor_list)==1) and (selected_node in open_cpe):
                            open_cpe.remove(selected_node)
                            confirmed_cpe.add(selected_node)
                        for neighbor in neighbor_list:
                            rolling_graph.add_edge(root["name"],neighbor,weight=0,positive_weight=0)
                    else:
                        GraphRunner.remove_subtree_iter(rolling_graph,selected_node)
                        discarded_cpe_set = GraphRunner.get_cpe_from_node(selected_node,local_cpe_vendor_to_cpe,local_cpe_product_to_cpe,local_cpe_version_to_cpe)
                        open_cpe = open_cpe.difference(discarded_cpe_set)
                        discarded_cpe = discarded_cpe.union(discarded_cpe_set)

                    new_confirmed_cve = set()
                    new_discarded_cve = set()
                    for cve in open_cve:
                        _,confirmed,discarded = GraphRunner.check_if_cve_closed(cve,local_cve_to_cpe,discarded_cpe,confirmed_cpe)
                        if confirmed == True:
                            new_confirmed_cve.add(cve)
                        elif discarded == True:
                            new_discarded_cve.add(cve)
                    confirmed_cve = confirmed_cve.union(new_confirmed_cve)
                    discarded_cve = discarded_cve.union(new_discarded_cve)
                    open_cve = open_cve.difference(new_confirmed_cve.union(new_discarded_cve))

                    if selected_node in rolling_graph.nodes:
                        rolling_graph.remove_node(selected_node)

                    node_sequence_log.write(str(selected_node).replace(";","-")+";"+str(selected_node_score).replace(".",",").replace(";","-")+";"+str(validation_response)+"\n")
                    cpe_sequence_log.write(str(len(open_cve))+";"+str(len(open_cpe))+"\n")
                else:
                    node_sequence_log.write("sigterm;;\n")
                    cpe_sequence_log.write("sigterm;\n")
                    node_sequence_log.close()
                    cpe_sequence_log.close()

            node_sequence_log.close()
            cpe_sequence_log.close()



        for host_id in host_to_graph:
            print("-",host_id)
            run_1_exec(host_id,host_to_cve_to_cpe[host_id],host_to_graph[host_id],"version",
                    host_to_validation_inventory_inert[host_id],host_to_cpe_to_cpe_mod[host_id],
                    host_to_cpe_vendor_to_cpe[host_id],host_to_cpe_product_to_cpe[host_id],host_to_cpe_version_to_cpe[host_id])



        # Nonuseless Run
        # Use the graph as it is, remove useless elements
        print("2 - Nonuseless Run")

        # Rationale:
        # 1 Take the highest ranking element
        # 2 Validate it
        # 3 Remove useless items from graph if CVE is validated/invalidated
        # 4 Update graph


        def run_2_exec(local_host_id,local_graph,local_cve_to_cpe,log_mod,
                    local_validation_inventory_inert,local_cpe_to_cpe_mod,local_cpe_vendor_to_cpe,local_cpe_product_to_cpe,local_cpe_version_to_cpe,
                    local_cve_to_cpe_tree_vendor,local_cve_to_cpe_tree_product,local_cve_to_cpe_tree_version):
            # Fetch data
            open_cve = set()
            confirmed_cve = set()
            discarded_cve = set()

            open_cpe = set()
            confirmed_cpe = set()
            discarded_cpe = set()

            confirmed_node = set()
            discarded_node = set()

            for cve in local_cve_to_cpe:
                open_cve.add(cve)
                for and_cpe in local_cve_to_cpe[cve]:
                    for cpe in and_cpe:
                        open_cpe.add(cpe)
            
            # Copy graph
            rolling_graph = local_graph.copy()
            root = rolling_graph.nodes[local_host_id]

            # Logfile
            node_sequence_log=open(file="CVE-Search-Validator/graphs/sequence/"+SNAPSHOT_ID+"_"+local_host_id+"_nonuseless_node_sequence_"+log_mod+".csv",mode="w",encoding="utf-8")
            cpe_sequence_log=open(file="CVE-Search-Validator/graphs/sequence/"+SNAPSHOT_ID+"_"+local_host_id+"_nonuseless_cpe_sequence_"+log_mod+".csv",mode="w",encoding="utf-8")

            node_sequence_log.write("Node;Score;Response\n")
            cpe_sequence_log.write("#Open_CVE;#Open_CPE\n")

            # Validation loop
            while (len(open_cpe)>0) and (len(open_cve)>0) and (len(rolling_graph)>2):
                selected_node = ""
                selected_node_pool = set()
                selected_node_type = ""
                selected_node_score = 0
                for neighbor in rolling_graph.neighbors(root["name"]):
                    if rolling_graph.nodes[neighbor]["score"] > selected_node_score:
                        selected_node_pool = set()
                        selected_node_pool.add(neighbor)
                        selected_node_score = rolling_graph.nodes[neighbor]["score"]
                        selected_node_type = rolling_graph.nodes[neighbor]["node_subtype"]
                        selected_node = neighbor
                    elif rolling_graph.nodes[neighbor]["score"] == selected_node_score:
                        selected_node_pool.add(neighbor)
                
                if len(selected_node_pool) > 1:
                    selected_node = random.choice(sorted(selected_node_pool))

                # I have one node
                if selected_node != "":
                    # Have a response according to inventory
                    validation_response,local_confirmed,local_discarded = GraphRunner.validate_node_explicit(selected_node,local_validation_inventory_inert,selected_node_type)
                    #confirmed_node = confirmed_node.union(local_confirmed)
                    #discarded_node = discarded_node.union(local_discarded)

                    if validation_response == True:
                        neighbor_list = list(rolling_graph.neighbors(selected_node))
                        if (len(neighbor_list)==1) and (selected_node in open_cpe):
                            open_cpe.remove(selected_node)
                            confirmed_cpe.add(selected_node)
                        for neighbor in neighbor_list:
                            rolling_graph.add_edge(root["name"],neighbor,weight=0,positive_weight=0)
                    else:
                        GraphRunner.remove_subtree_iter(rolling_graph,selected_node)
                        discarded_cpe_set = GraphRunner.get_cpe_from_node(selected_node,local_cpe_vendor_to_cpe,local_cpe_product_to_cpe,local_cpe_version_to_cpe)
                        open_cpe = open_cpe.difference(discarded_cpe_set)
                        discarded_cpe = discarded_cpe.union(discarded_cpe_set)

                    new_confirmed_cve,new_discarded_cve = GraphRunner.prune_useless_items(rolling_graph,local_cve_to_cpe,local_cpe_to_cpe_mod,
                                                    local_cve_to_cpe_tree_vendor,local_cve_to_cpe_tree_product,local_cve_to_cpe_tree_version,
                                                    confirmed_cpe,discarded_cpe,open_cve)
                    confirmed_cve = confirmed_cve.union(new_confirmed_cve)
                    discarded_cve = discarded_cve.union(new_discarded_cve)
                    open_cve = open_cve.difference(new_confirmed_cve.union(new_discarded_cve))

                    if selected_node in rolling_graph.nodes:
                        rolling_graph.remove_node(selected_node)

                    node_sequence_log.write(selected_node+";"+str(selected_node_score).replace(".",",").replace(";","-")+";"+str(validation_response)+"\n")
                    cpe_sequence_log.write(str(len(open_cve))+";"+str(len(open_cpe))+"\n")
                else:
                    node_sequence_log.write("sigterm;;\n")
                    cpe_sequence_log.write("sigterm;\n")
                    node_sequence_log.close()
                    cpe_sequence_log.close()

            node_sequence_log.close()
            cpe_sequence_log.close()



        for host_id in host_to_graph:
            print("-",host_id)
            run_2_exec(host_id,host_to_graph[host_id],host_to_cve_to_cpe[host_id],"version",
                    host_to_validation_inventory_inert[host_id],host_to_cpe_to_cpe_mod[host_id],host_to_cpe_vendor_to_cpe[host_id],host_to_cpe_product_to_cpe[host_id],host_to_cpe_version_to_cpe[host_id],
                    host_to_cve_to_cpe_tree_vendor[host_id],host_to_cve_to_cpe_tree_product[host_id],host_to_cve_to_cpe_tree_version[host_id])
