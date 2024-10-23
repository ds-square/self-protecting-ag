import time
import json
import random

from filtering.engine.graph_runner import GraphRunner



DEBUG_STEP = 10
STARTTIME = time.time()



class DynamicGraphRunner():

    def do_run(SNAPSHOT_ID,host_id,LOG_DIR,log_mod,OUTPUT_DIR,scoring_function,
               graph,cve_to_cpe,validation_inventory_inert,cpe_to_cpe_mod,
               cpe_vendor_to_cpe,cpe_product_to_cpe,cpe_version_to_cpe,
               cve_to_cpe_tree_vendor,cve_to_cpe_tree_product,cve_to_cpe_tree_version,
               cpe_vendor_to_advisory,cpe_product_to_advisory,cpe_version_to_advisory,
               cpe_vendor_to_advisory_max,cpe_product_to_advisory_max,cpe_version_to_advisory_max):
        
        # Fetch data
        open_cve = set()
        confirmed_cve = set()
        discarded_cve = set()

        open_cpe = set()
        confirmed_cpe = set()
        discarded_cpe = set()

        confirmed_node = set()
        discarded_node = set()

        for cve in cve_to_cpe:
            open_cve.add(cve)
            for and_cpe in cve_to_cpe[cve]:
                for cpe in and_cpe:
                    open_cpe.add(cpe)
        
        # Copy graph
        rolling_graph = graph.copy()
        root = rolling_graph.nodes[host_id]

        # Recalc graph scores before ignition
        DynamicGraphRunner.recalc_graph_scores(rolling_graph,scoring_function,
                                                cpe_vendor_to_advisory,cpe_product_to_advisory,cpe_version_to_advisory,
                                                cpe_vendor_to_advisory_max,cpe_product_to_advisory_max,cpe_version_to_advisory_max,
                                                cve_to_cpe_tree_vendor,cve_to_cpe_tree_product,cve_to_cpe_tree_version)

        # Logfile
        node_sequence_log=open(file=LOG_DIR+"/"+SNAPSHOT_ID+"_"+host_id+"_dynamic_node_sequence_"+log_mod+".csv",mode="w",encoding="utf-8")
        cpe_sequence_log=open(file=LOG_DIR+"/"+SNAPSHOT_ID+"_"+host_id+"_dynamic_cpe_sequence_"+log_mod+".csv",mode="w",encoding="utf-8")

        node_sequence_log.write("Step;Node;Score;Response\n")
        cpe_sequence_log.write("Step;#Open_CVE;#Open_CPE\n")

        step_number = 0

        # Validation loop
        while (len(open_cpe)>0) and (len(open_cve)>0) and (len(rolling_graph)>2):
            if step_number%DEBUG_STEP == 0:
                print(round(time.time()-STARTTIME,2),"looping",host_id,step_number,len(open_cpe),len(open_cve),len(rolling_graph))

            selected_node = ""
            selected_node_pool = set()
            selected_node_type = ""
            selected_node_score = 0
            # Select from root neighbors
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
                #if step_number%DEBUG_STEP == 0:
                    #print(round(time.time()-STARTTIME,2),"L1")
                # Have a response according to inventory
                #validation_response,confirmed,discarded = GraphRunner.validate_node_explicit(selected_node,validation_inventory_inert,selected_node_type)
                validation_response = GraphRunner.validate_node(selected_node,validation_inventory_inert,selected_node_type)
                #confirmed_node = confirmed_node.union(confirmed)
                #discarded_node = discarded_node.union(discarded)

                check_required = False
                if validation_response == True:
                    # node in host, bypass it
                    neighbor_list = list(rolling_graph.neighbors(selected_node)) # neighbor == child
                    if (len(neighbor_list)==1) and (selected_node in open_cpe): # this is a full cpe string, i.e. leaf node. there is always a sink at the bottom
                        open_cpe.remove(selected_node)
                        confirmed_cpe.add(selected_node)
                        check_required = True
                    for neighbor in neighbor_list:
                        # add links to children
                        rolling_graph.add_edge(root["name"],neighbor,weight=0,positive_weight=0)
                else:
                    # node not in host, remove all subtree
                    GraphRunner.remove_subtree_iter(rolling_graph,selected_node)
                    discarded_cpe_set = GraphRunner.get_cpe_from_node(selected_node,cpe_vendor_to_cpe,cpe_product_to_cpe,cpe_version_to_cpe)
                    open_cpe = open_cpe.difference(discarded_cpe_set)
                    discarded_cpe = discarded_cpe.union(discarded_cpe_set)
                    check_required = True

                #if step_number%DEBUG_STEP == 0:
                    #print(round(time.time()-STARTTIME,2),"L2",check_required)
                # Check all cve on check required
                if check_required == True:
                    # A lot has been confirmed or removed
                    # Check impact on CVE trees
                    new_confirmed_cve,new_discarded_cve = GraphRunner.prune_useless_items(rolling_graph,cve_to_cpe,cpe_to_cpe_mod,
                                                            cve_to_cpe_tree_vendor,cve_to_cpe_tree_product,cve_to_cpe_tree_version,
                                                            confirmed_cpe,discarded_cpe,open_cve)
                    confirmed_cve = confirmed_cve.union(new_confirmed_cve)
                    discarded_cve = discarded_cve.union(new_discarded_cve)
                    open_cve = open_cve.difference(new_confirmed_cve.union(new_discarded_cve))

                #if step_number%DEBUG_STEP == 0:
                    #print(round(time.time()-STARTTIME,2),"L3")
                # Remove node from graph
                if selected_node in rolling_graph.nodes:
                    rolling_graph.remove_node(selected_node)

                #if step_number%DEBUG_STEP == 0:
                    #print(round(time.time()-STARTTIME,2),"L4")
                # Reroll trees on check required
                if check_required == True:
                    cve_to_cpe = GraphRunner.evaluate_cpe_tree(cve_to_cpe,confirmed_cpe,discarded_cpe)
                    #if step_number%DEBUG_STEP == 0:
                        #print(round(time.time()-STARTTIME,2),"L4.5")
                    cve_to_cpe_tree_vendor,cve_to_cpe_tree_product,cve_to_cpe_tree_version = GraphRunner.rebuild_truncated_cpe_trees(cve_to_cpe)

                #if step_number%DEBUG_STEP == 0:
                    #print(round(time.time()-STARTTIME,2),"L5")
                # Rescore graph on check required
                if check_required == True:
                    DynamicGraphRunner.recalc_graph_scores(rolling_graph,scoring_function,
                                                            cpe_vendor_to_advisory,cpe_product_to_advisory,cpe_version_to_advisory,
                                                            cpe_vendor_to_advisory_max,cpe_product_to_advisory_max,cpe_version_to_advisory_max,
                                                            cve_to_cpe_tree_vendor,cve_to_cpe_tree_product,cve_to_cpe_tree_version)

                #if step_number%DEBUG_STEP == 0:
                    #print(round(time.time()-STARTTIME,2),"L6")
                # Log progress
                node_sequence_log.write(str(step_number)+";"+selected_node+";"+str(selected_node_score).replace(".",",").replace(";","-")+";"+str(validation_response)+"\n")
                cpe_sequence_log.write(str(step_number)+";"+str(len(open_cve))+";"+str(len(open_cpe))+"\n")
            else:
                node_sequence_log.write(str(step_number)+";sigterm;;\n")
                cpe_sequence_log.write(str(step_number)+";sigterm;\n")
                node_sequence_log.close()
                cpe_sequence_log.close()

            step_number = step_number + 1

        node_sequence_log.close()
        cpe_sequence_log.close()

        f=open(file=OUTPUT_DIR+"/"+SNAPSHOT_ID+"_"+host_id+"_filtered_inventory_"+log_mod+".json",mode="w",encoding="utf-8")
        f.write(json.dumps({"host_id":host_id,"open_cve":list(open_cve),"confirmed_cve":list(confirmed_cve),"discarded_cve":list(discarded_cve)}))
        f.close()



    def recalc_graph_scores(target_graph,recalc_scores,
                            cpe_vendor_to_advisory,cpe_product_to_advisory,cpe_version_to_advisory,
                            cpe_vendor_to_advisory_max,cpe_product_to_advisory_max,cpe_version_to_advisory_max,
                            cve_to_cpe_tree_vendor,cve_to_cpe_tree_product,cve_to_cpe_tree_version):

        if len(target_graph)>2: # host and sink

            cpe_vendor_to_score = recalc_scores(cve_to_cpe_tree_vendor,cpe_vendor_to_advisory,cpe_vendor_to_advisory_max)
            cpe_product_to_score = recalc_scores(cve_to_cpe_tree_product,cpe_product_to_advisory,cpe_product_to_advisory_max)
            cpe_version_to_score = recalc_scores(cve_to_cpe_tree_version,cpe_version_to_advisory,cpe_version_to_advisory_max)


            # Recalc nodes
            for node_id in target_graph.nodes:
                node = target_graph.nodes[node_id]

                max_weight = 0
                if node["node_subtype"] == "vendor":
                    if node_id in cpe_vendor_to_score:
                        node["score"] = cpe_vendor_to_score[node_id]
                elif node["node_subtype"] == "product":
                    if node_id in cpe_product_to_score:
                        node["score"] = cpe_product_to_score[node_id]
                elif node["node_subtype"] == "version":
                    if node_id in cpe_version_to_score:
                        node["score"] = cpe_version_to_score[node_id]


            # Recalc edges
            for edge_id in target_graph.edges:
                edge = target_graph.edges[edge_id]

                node_id_from = edge_id[0]
                node_id_to = edge_id[1]

                node_from = target_graph.nodes[node_id_from]
                node_to = target_graph.nodes[node_id_to]

                if (node_to["node_subtype"] == "vendor") or (node_to["node_subtype"] == "product") or (node_to["node_subtype"] == "version"):
                    edge["weight"] = node_to["score"]
                    edge["positive_weight"] = max_weight-node_to["score"]

        #return target_graph
