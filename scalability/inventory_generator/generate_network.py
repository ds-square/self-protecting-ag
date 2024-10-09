import random, json, sys, os, logging, traceback
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import config



class SyntheticInventoryGenerator:

    INVENTORIES_ROOT_FOLDER = config.NETWORK_FOLDER
    INVENTORY_GENENERATOR_RESOURCE_FOLDER = config.ADVISORY_RESOURCES
    PATH_TO_NVD_DUMP = config.nvd_complete_dump

    def load():
        logging.basicConfig(filename='logging/dataset_generator.log', level=logging.DEBUG, 
            format='%(asctime)s - %(levelname)s: %(message)s')
        
        logging.info("[GENERATION] Loading inventory resources...")
        
        # Load resources
        f = open(SyntheticInventoryGenerator.INVENTORY_GENENERATOR_RESOURCE_FOLDER+"/VulnDB.GLSA.json",mode="r",encoding="utf-8")
        glsa_resource = json.loads(f.read())
        f.close()

        nessus_resource = list()
        f = open(SyntheticInventoryGenerator.INVENTORY_GENENERATOR_RESOURCE_FOLDER+"/VulnDB.NessusPlugin_chunk1.json",mode="r",encoding="utf-8")
        nessus_resource = nessus_resource + json.loads(f.read())
        f.close()
        f = open(SyntheticInventoryGenerator.INVENTORY_GENENERATOR_RESOURCE_FOLDER+"/VulnDB.NessusPlugin_chunk2.json",mode="r",encoding="utf-8")
        nessus_resource = nessus_resource + json.loads(f.read())
        f.close()
        f = open(SyntheticInventoryGenerator.INVENTORY_GENENERATOR_RESOURCE_FOLDER+"/VulnDB.NessusPlugin_chunk3.json",mode="r",encoding="utf-8")
        nessus_resource = nessus_resource + json.loads(f.read())
        f.close()

        f = open(SyntheticInventoryGenerator.INVENTORY_GENENERATOR_RESOURCE_FOLDER+"/VulnDB.ICS_CERT.json",mode="r",encoding="utf-8")
        icscert_resource = json.loads(f.read())
        f.close()

        # Path is in a file
        f = open(SyntheticInventoryGenerator.PATH_TO_NVD_DUMP,mode="r",encoding="utf-8")
        nvd_dump_path = f.read().strip()
        f.close()

        f = open(nvd_dump_path,mode="r",encoding="utf-8")
        nvd_resource = json.loads(f.read())
        f.close()    
        
        # Compile resources
        advisory_to_cve = dict()

        for glsa in glsa_resource:
            if "cve" in glsa:
                if len(glsa["cve"]) > 0:
                    advisory_to_cve["glsa-"+glsa["id"]] = glsa["cve"]

        for nessus in nessus_resource:
            if "cve" in nessus:
                if len(nessus["cve"]) > 0:
                    advisory_to_cve["nessus-"+nessus["id"]] = nessus["cve"]

        for icscert in icscert_resource:
            if "cve" in icscert:
                if len(icscert["cve"]) > 0:
                    advisory_to_cve["icscert-"+icscert["id"]] = icscert["cve"]

        sorted_advisory_keys = sorted(advisory_to_cve.keys())

        logging.info("[GENERATION] Inventory resources compiled, initiating generation.")

        return nvd_resource, sorted_advisory_keys, advisory_to_cve
        

    def run(params):
        
        logging.basicConfig(filename='logging/dataset_generator.log', level=logging.DEBUG, 
            format='%(asctime)s - %(levelname)s: %(message)s')
        
        r_seed,num_hosts,num_vulns,nvd_resource,sorted_advisory_keys,advisory_to_cve = params

        # Generate hosts
        total_vulnerability_set = set()
        random.seed(r_seed)

        logging.info("[GENERATION] Hosts with seed:%d-host:%d-vulns:%d", r_seed,num_hosts,num_vulns)
        host_list = list()

        try:
            for host_index in range(num_hosts):
                host_struct = dict()
                host_struct["id"] = "host-"+str(host_index)
                host_struct["hostname"] = "generated_host"
                host_struct["type"] = "synthetic"
                host_struct["network_interfaces"] = list()
                host_struct["local_applications"] = list()

                interface_struct = dict()
                interface_struct["ipaddress"] = "192.168.1.1"
                interface_struct["macaddress"] = "ff:ff:ff:ff:ff:ff"
                interface_struct["ports"] = list()

                current_vulnerability_set = set()
                current_port_number = 1
                while len(current_vulnerability_set) < num_vulns/2:
                    port_struct = dict()
                    port_struct["number"] = current_port_number
                    port_struct["state"] = "open"
                    port_struct["protocol"] = "TCP"

                    advisory = random.choice(sorted_advisory_keys)
                    chosen_cve = advisory_to_cve[advisory]

                    # Cut excess
                    elements_to_cut = int(len(chosen_cve)+len(current_vulnerability_set) - (num_vulns/2))
                    if elements_to_cut > 0:
                        chosen_cve = chosen_cve.copy()
                        for i in range(elements_to_cut):
                            chosen_cve.pop()

                    current_vulnerability_set = current_vulnerability_set.union(set(chosen_cve))

                    port_struct["service"] = {"name":"dummy_from_"+advisory,"cpe_list":list(),"cve_list":advisory_to_cve[advisory]}
                    # port_struct["cve_list"] = advisory_to_cve[advisory]

                    interface_struct["ports"].append(port_struct)
                    current_port_number = current_port_number + 1

                host_struct["network_interfaces"].append(interface_struct)

                current_local_number = 1
                while len(current_vulnerability_set) < num_vulns:
                    advisory = random.choice(sorted_advisory_keys)
                    chosen_cve = advisory_to_cve[advisory]

                    # Cut excess
                    elements_to_cut = len(chosen_cve)+len(current_vulnerability_set) - num_vulns
                    if elements_to_cut > 0:
                        chosen_cve = chosen_cve.copy()
                        for i in range(elements_to_cut):
                            chosen_cve.pop()

                    current_vulnerability_set = current_vulnerability_set.union(set(chosen_cve))

                    local_struct = dict()
                    local_struct["id"] = current_local_number
                    local_struct["name"] = "dummy_from_"+advisory
                    local_struct["service"] = list()

                    service_struct = dict()
                    service_struct["name"] = "dummy_from_"+advisory
                    service_struct["cpe_list"] = list()
                    service_struct["cve_list"] = advisory_to_cve[advisory]

                    local_struct["service"].append(service_struct)

                    host_struct["local_applications"].append(local_struct)
                    current_local_number = current_local_number + 1

                total_vulnerability_set = total_vulnerability_set.union(current_vulnerability_set)
                host_list.append(host_struct)



            # Generate edges
            logging.info("[GENERATION] Edges with seed:%d-host:%d-vulns:%d", r_seed,num_hosts,num_vulns)
            edge_list = list()
            edge_index_1 = 0
            for host1 in host_list:
                host1_id = host1["id"]

                edge_index_2 = 0
                for host2 in host_list:
                    host2_id = host2["id"]

                    edge_list.append({
                        "host_link": [edge_index_1,edge_index_2],
                        "id_link": [host1_id,host2_id]
                    })

                    edge_index_2 = edge_index_2 + 1
                edge_index_1 = edge_index_1 + 1



            # Fetch vulnerabilities
            logging.info("[GENERATION] Vulnerabilities seed:%d-host:%d-vulns:%d", r_seed,num_hosts,num_vulns)
            vulnerability_list = list()
            for page in nvd_resource:
                for nvd_cve_struct in page["vulnerabilities"]:
                    if nvd_cve_struct["cve"]["id"] in total_vulnerability_set:
                        vulnerability_list.append(nvd_cve_struct["cve"])


            if not os.path.exists(SyntheticInventoryGenerator.INVENTORIES_ROOT_FOLDER): os.mkdir(SyntheticInventoryGenerator.INVENTORIES_ROOT_FOLDER)

            # Compile environment
            f = open(SyntheticInventoryGenerator.INVENTORIES_ROOT_FOLDER+"synthetic_s"+str(r_seed)+"_h"+str(num_hosts)+"_v"+str(num_vulns)+".json",mode="w",encoding="utf-8")
            environment_struct = dict()
            environment_struct["devices"] = host_list
            environment_struct["vulnerabilities"] = vulnerability_list
            environment_struct["edges"] = edge_list
            f.write(json.dumps(environment_struct))
            f.close()

            logging.info("[GENERATION] END GENERATION of seed:%d-host:%d-vulns:%d", r_seed,num_hosts,num_vulns)
        
        except Exception as e:
            traceback.print_exc()
            logging.error("%s",e)