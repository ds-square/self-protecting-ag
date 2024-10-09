import random, json, sys, os, logging, traceback
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import config
from inventory_generator.router_generator import RouterGenerator



class RealTopologyInventoryGenerator:

    INVENTORIES_ROOT_FOLDER = config.NETWORK_FOLDER
    INVENTORY_GENENERATOR_RESOURCE_FOLDER = config.ADVISORY_RESOURCES
    PATH_TO_NVD_DUMP = config.nvd_complete_dump

    HOST_TYPE_TABLE = {
        "172.25.0.11":"generic",
        "172.25.0.12":"generic",
        "172.25.0.13":"office",
        "172.25.0.14":"office",
        "172.25.0.15":"development",
        "172.25.0.16":"development",
        "172.25.0.17":"server",
        "172.25.0.18":"server",
    }

    LAN_HOSTS = {
        "server":5,
        "admin":20,
        "informatica":100,
        "gestionale":70,
        "automatica":50,
    }

    LAN_TO_HOSTTYPE = {
        "server":["server"],
        "admin":["office","generic"],
        "informatica":["office","development","generic"],
        "gestionale":["office","development","generic"],
        "automatica":["office","development","generic"]
    }

    DMZ_ACCESS_RATIO = .10


    def load():
        logging.basicConfig(filename='logging/dataset_generator.log', level=logging.DEBUG, 
            format='%(asctime)s - %(levelname)s: %(message)s')
        
        logging.info("[GENERATION] Loading inventory resources...")

        # Load run data
        scanner_to_strategy_to_host_to_step_to_state = dict()
        scanner_to_strategy_to_host_to_step_to_state["merged"] = dict()
        f = open(RealTopologyInventoryGenerator.INVENTORY_GENENERATOR_RESOURCE_FOLDER+"/dockerized_environment/merged/moves_status_S101_M1.json",mode="r",encoding="utf-8")
        scanner_to_strategy_to_host_to_step_to_state["merged"]["m1"] = json.loads(f.read())
        f.close()
        f = open(RealTopologyInventoryGenerator.INVENTORY_GENENERATOR_RESOURCE_FOLDER+"/dockerized_environment/merged/moves_status_S101_M2.json",mode="r",encoding="utf-8")
        scanner_to_strategy_to_host_to_step_to_state["merged"]["m2"] = json.loads(f.read())
        f.close()
        f = open(RealTopologyInventoryGenerator.INVENTORY_GENENERATOR_RESOURCE_FOLDER+"/dockerized_environment/merged/moves_status_S101_M3.json",mode="r",encoding="utf-8")
        scanner_to_strategy_to_host_to_step_to_state["merged"]["m3"] = json.loads(f.read())
        f.close()
        f = open(RealTopologyInventoryGenerator.INVENTORY_GENENERATOR_RESOURCE_FOLDER+"/dockerized_environment/merged/moves_status_S101_M4.json",mode="r",encoding="utf-8")
        scanner_to_strategy_to_host_to_step_to_state["merged"]["m4"] = json.loads(f.read())
        f.close()
        f = open(RealTopologyInventoryGenerator.INVENTORY_GENENERATOR_RESOURCE_FOLDER+"/dockerized_environment/merged/moves_status_S101_M5.json",mode="r",encoding="utf-8")
        scanner_to_strategy_to_host_to_step_to_state["merged"]["m5"] = json.loads(f.read())
        f.close()
        f = open(RealTopologyInventoryGenerator.INVENTORY_GENENERATOR_RESOURCE_FOLDER+"/dockerized_environment/merged/moves_status_S101_M6.json",mode="r",encoding="utf-8")
        scanner_to_strategy_to_host_to_step_to_state["merged"]["m6"] = json.loads(f.read())
        f.close()

        scanner_to_strategy_to_host_to_step_to_state["nessus"] = dict()
        f = open(RealTopologyInventoryGenerator.INVENTORY_GENENERATOR_RESOURCE_FOLDER+"/dockerized_environment/nessus/moves_status_S101_M1.json",mode="r",encoding="utf-8")
        scanner_to_strategy_to_host_to_step_to_state["nessus"]["m1"] = json.loads(f.read())
        f.close()
        f = open(RealTopologyInventoryGenerator.INVENTORY_GENENERATOR_RESOURCE_FOLDER+"/dockerized_environment/nessus/moves_status_S101_M2.json",mode="r",encoding="utf-8")
        scanner_to_strategy_to_host_to_step_to_state["nessus"]["m2"] = json.loads(f.read())
        f.close()
        f = open(RealTopologyInventoryGenerator.INVENTORY_GENENERATOR_RESOURCE_FOLDER+"/dockerized_environment/nessus/moves_status_S101_M3.json",mode="r",encoding="utf-8")
        scanner_to_strategy_to_host_to_step_to_state["nessus"]["m3"] = json.loads(f.read())
        f.close()
        f = open(RealTopologyInventoryGenerator.INVENTORY_GENENERATOR_RESOURCE_FOLDER+"/dockerized_environment/nessus/moves_status_S101_M4.json",mode="r",encoding="utf-8")
        scanner_to_strategy_to_host_to_step_to_state["nessus"]["m4"] = json.loads(f.read())
        f.close()
        f = open(RealTopologyInventoryGenerator.INVENTORY_GENENERATOR_RESOURCE_FOLDER+"/dockerized_environment/nessus/moves_status_S101_M5.json",mode="r",encoding="utf-8")
        scanner_to_strategy_to_host_to_step_to_state["nessus"]["m5"] = json.loads(f.read())
        f.close()
        f = open(RealTopologyInventoryGenerator.INVENTORY_GENENERATOR_RESOURCE_FOLDER+"/dockerized_environment/nessus/moves_status_S101_M3.json",mode="r",encoding="utf-8")
        scanner_to_strategy_to_host_to_step_to_state["nessus"]["m6"] = json.loads(f.read())
        f.close()

        scanner_to_strategy_to_host_to_step_to_state["openvas"] = dict()
        f = open(RealTopologyInventoryGenerator.INVENTORY_GENENERATOR_RESOURCE_FOLDER+"/dockerized_environment/openvas/moves_status_S101_M1.json",mode="r",encoding="utf-8")
        scanner_to_strategy_to_host_to_step_to_state["openvas"]["m1"] = json.loads(f.read())
        f.close()
        f = open(RealTopologyInventoryGenerator.INVENTORY_GENENERATOR_RESOURCE_FOLDER+"/dockerized_environment/openvas/moves_status_S101_M2.json",mode="r",encoding="utf-8")
        scanner_to_strategy_to_host_to_step_to_state["openvas"]["m2"] = json.loads(f.read())
        f.close()
        f = open(RealTopologyInventoryGenerator.INVENTORY_GENENERATOR_RESOURCE_FOLDER+"/dockerized_environment/openvas/moves_status_S101_M3.json",mode="r",encoding="utf-8")
        scanner_to_strategy_to_host_to_step_to_state["openvas"]["m3"] = json.loads(f.read())
        f.close()
        f = open(RealTopologyInventoryGenerator.INVENTORY_GENENERATOR_RESOURCE_FOLDER+"/dockerized_environment/openvas/moves_status_S101_M4.json",mode="r",encoding="utf-8")
        scanner_to_strategy_to_host_to_step_to_state["openvas"]["m4"] = json.loads(f.read())
        f.close()
        f = open(RealTopologyInventoryGenerator.INVENTORY_GENENERATOR_RESOURCE_FOLDER+"/dockerized_environment/openvas/moves_status_S101_M5.json",mode="r",encoding="utf-8")
        scanner_to_strategy_to_host_to_step_to_state["openvas"]["m5"] = json.loads(f.read())
        f.close()
        f = open(RealTopologyInventoryGenerator.INVENTORY_GENENERATOR_RESOURCE_FOLDER+"/dockerized_environment/openvas/moves_status_S101_M3.json",mode="r",encoding="utf-8")
        scanner_to_strategy_to_host_to_step_to_state["openvas"]["m6"] = json.loads(f.read())
        f.close()

        # Path is in a file
        f = open(RealTopologyInventoryGenerator.PATH_TO_NVD_DUMP,mode="r",encoding="utf-8")
        nvd_dump_path = f.read().strip()
        f.close()

        f = open(nvd_dump_path,mode="r",encoding="utf-8")
        nvd_resource = json.loads(f.read())
        f.close()

        # Compile resources
        scanner_to_strategy_to_max_step = dict()
        for scanner in scanner_to_strategy_to_host_to_step_to_state:
            scanner_to_strategy_to_max_step[scanner] = dict()
            for strategy in scanner_to_strategy_to_host_to_step_to_state[scanner]:
                scanner_to_strategy_to_max_step[scanner][strategy] = 0
                for host in scanner_to_strategy_to_host_to_step_to_state[scanner][strategy]:
                    for step in scanner_to_strategy_to_host_to_step_to_state[scanner][strategy][host]:
                        scanner_to_strategy_to_max_step[scanner][strategy] = max(scanner_to_strategy_to_max_step[scanner][strategy], int(step))
        
        for scanner in scanner_to_strategy_to_host_to_step_to_state:
            for strategy in scanner_to_strategy_to_host_to_step_to_state[scanner]:
                for host in scanner_to_strategy_to_host_to_step_to_state[scanner][strategy]:
                    last_step = str(len(scanner_to_strategy_to_host_to_step_to_state[scanner][strategy][host])-1)
                    for step in range(scanner_to_strategy_to_max_step[scanner][strategy]+1):
                        step = str(step)
                        if step not in scanner_to_strategy_to_host_to_step_to_state[scanner][strategy][host]:
                            scanner_to_strategy_to_host_to_step_to_state[scanner][strategy][host][step] = scanner_to_strategy_to_host_to_step_to_state[scanner][strategy][host][last_step]

        logging.info("[GENERATION] Inventory resources compiled, initiating generation.")

        return scanner_to_strategy_to_max_step, scanner_to_strategy_to_host_to_step_to_state, nvd_resource


    def run(params):
        
        logging.basicConfig(filename='logging/dataset_generator.log', level=logging.DEBUG, 
            format='%(asctime)s - %(levelname)s: %(message)s')
        
        target_scanner,target_strategy,step_modulo,random_seed,scanner_to_strategy_to_max_step,scanner_to_strategy_to_host_to_step_to_state,nvd_resource = params

        # Seed random generator
        random.seed(random_seed)


        # Recreate hosts
        logging.info("[GENERATION] Real Scenario, Real Topology, Hosts")
        type_to_host_id = dict()
        type_to_step_to_host_list = dict()
        step_to_vulnerability_set = dict()

        try:
            max_step = scanner_to_strategy_to_max_step[target_scanner][target_strategy]
            for host in scanner_to_strategy_to_host_to_step_to_state[target_scanner][target_strategy]:
                host_type = RealTopologyInventoryGenerator.HOST_TYPE_TABLE[host]

                if host_type not in type_to_host_id:
                    type_to_host_id[host_type] = list()

                if host_type not in type_to_step_to_host_list:
                    type_to_step_to_host_list[host_type] = dict()
                    
                for step in scanner_to_strategy_to_host_to_step_to_state[target_scanner][target_strategy][host]:
                    if (int(step) % step_modulo == 0) or (int(step) == max_step):
                        if step not in type_to_step_to_host_list[host_type]:
                            type_to_step_to_host_list[host_type][step] = list()
                            step_to_vulnerability_set[step] = set()

                        host_struct = dict()
                        host_struct["id"] = "host-"+str(host)
                        host_struct["hostname"] = "generated_host"
                        host_struct["type"] = host_type
                        host_struct["network_interfaces"] = list()
                        host_struct["local_applications"] = list()

                        interface_struct = dict()
                        interface_struct["ipaddress"] = "192.168.1.1"
                        interface_struct["macaddress"] = "ff:ff:ff:ff:ff:ff"
                        interface_struct["ports"] = list()

                        port_struct = dict()
                        port_struct["number"] = 101
                        port_struct["state"] = "open"
                        port_struct["protocol"] = "TCP"

                        confirmed_cve = scanner_to_strategy_to_host_to_step_to_state[target_scanner][target_strategy][host][step]["confirmed_cve"]
                        open_cve = scanner_to_strategy_to_host_to_step_to_state[target_scanner][target_strategy][host][step]["open_cve"]

                        port_struct["service"] = {"name":"dummy","cpe_list":list(),"cve_list":list(set(confirmed_cve).union(set(open_cve)))}
                        # port_struct["cve_list"] = list(set(confirmed_cve).union(set(open_cve)))

                        step_to_vulnerability_set[step] = step_to_vulnerability_set[step].union(set(confirmed_cve).union(set(open_cve)))

                        interface_struct["ports"].append(port_struct)

                        host_struct["network_interfaces"].append(interface_struct)

                        local_struct = dict()
                        local_struct["id"] = 101
                        local_struct["name"] = "dummy"
                        local_struct["service"] = list()

                        service_struct = dict()
                        service_struct["name"] = "dummy"
                        service_struct["cpe_list"] = list()
                        service_struct["cve_list"] = list()

                        local_struct["service"].append(service_struct)

                        host_struct["local_applications"].append(local_struct)

                        type_to_step_to_host_list[host_type][step].append(host_struct)
                        type_to_host_id[host_type].append(host)


            # Note to future self: from now on, all filters are applied, since step_to_host_list is a new structure


            # Replicate hosts to form network
            step_to_host_list = dict()
            step_to_host_id = dict()
            for host_type in type_to_step_to_host_list:
                for step in type_to_step_to_host_list[host_type]:
                    if step not in step_to_host_list:
                        step_to_host_list[step] = list()
                        step_to_host_id[step] = list()
            

            lan_to_host_id = dict()
            for lan_id in RealTopologyInventoryGenerator.LAN_HOSTS:
                lan_to_host_id[lan_id] = set()
                hosts_per_lan = RealTopologyInventoryGenerator.LAN_HOSTS[lan_id]

                for host_number in range(hosts_per_lan):
                    host_type = RealTopologyInventoryGenerator.LAN_TO_HOSTTYPE[lan_id][host_number%len(RealTopologyInventoryGenerator.LAN_TO_HOSTTYPE[lan_id])]

                    chosen_host_id = random.choice(type_to_host_id[host_type])
                    lan_to_host_id[lan_id].add(("host-"+str(chosen_host_id)+"-"+str(lan_id)+"-"+str(host_number)))

                    for step in type_to_step_to_host_list[host_type]:
                        for host_struct in type_to_step_to_host_list[host_type][step]:
                            if host_struct["id"] == ("host-"+str(chosen_host_id)):
                                new_host_struct = host_struct.copy()
                                new_host_struct["id"] = ("host-"+str(chosen_host_id)+"-"+str(lan_id)+"-"+str(host_number))
                                step_to_host_list[step].append(new_host_struct)
                                step_to_host_id[step].append(new_host_struct["id"])
                
                lan_to_host_id[lan_id] = sorted(list(lan_to_host_id[lan_id]))


            # Add router
            router = RouterGenerator.generate_router_entry(0)
            router_index = 0
            for step in step_to_host_list:
                step_to_host_list[step].append(router)
                router_index = len(step_to_host_list[step])
            


            # Generate edges
            logging.info("[GENERATION] Real Scenario, Real Topology, edges")
            step_to_edge_list = dict()

            for step in step_to_host_list:
                step_to_edge_list[step] = list()

                for lan_id in RealTopologyInventoryGenerator.LAN_HOSTS:
                    for host_id_1 in lan_to_host_id[lan_id]:
                        host_index_1 = step_to_host_id[step].index(host_id_1)
                        for host_id_2 in lan_to_host_id[lan_id]:
                            host_index_2 = step_to_host_id[step].index(host_id_2)

                            step_to_edge_list[step].append({
                                "host_link": [host_index_1,host_index_2],
                                "id_link": [host_id_1,host_id_2]
                            })
            

            # Add router edges
            for step in step_to_host_list:
                for lan_id in RealTopologyInventoryGenerator.LAN_HOSTS:
                    for host_id in lan_to_host_id[lan_id]:
                        host_index = step_to_host_id[step].index(host_id_1)

                        step_to_edge_list[step].append({
                            "host_link": [router_index,host_index],
                            "id_link": [router["id"],host_id]
                        })

                        step_to_edge_list[step].append({
                            "host_link": [host_index,router_index],
                            "id_link": [host_id,router["id"]]
                        })
            

            # Add random edges to and from DMZ
            # Use DMZ_ACCESS_RATIO for ratio
            for lan_id in lan_to_host_id:
                random.shuffle(lan_to_host_id[lan_id])
            
            for step in step_to_host_list:
                for lan_id in RealTopologyInventoryGenerator.LAN_HOSTS:
                    if lan_id != "server":
                        hosts_to_link = RealTopologyInventoryGenerator.LAN_HOSTS[lan_id]*RealTopologyInventoryGenerator.DMZ_ACCESS_RATIO
                        hosts_linked = 0
                        for host_id in lan_to_host_id[lan_id]:
                            if hosts_linked < hosts_to_link:
                                host_index = step_to_host_id[step].index(host_id)
                                for host_id_dmz in lan_to_host_id["server"]:
                                    host_index_dmz = step_to_host_id[step].index(host_id_dmz)

                                    step_to_edge_list[step].append({
                                        "host_link": [host_index,host_index_dmz],
                                        "id_link": [host_id,host_id_dmz]
                                    })
                            hosts_linked = hosts_linked + 1



            # Fetch vulnerabilities
            logging.info("[GENERATION] Real Scenario, Real Topology, vulnerabilities")
            strategy_to_step_to_vulnerability_struct_list = dict()
            strategy_to_step_to_vulnerability_struct_list[target_strategy] = dict()

            for step in step_to_vulnerability_set:
                if step not in strategy_to_step_to_vulnerability_struct_list[target_strategy]:
                    strategy_to_step_to_vulnerability_struct_list[target_strategy][step] = list()

                for page in nvd_resource:
                    for nvd_cve_struct in page["vulnerabilities"]:
                        if nvd_cve_struct["cve"]["id"] in step_to_vulnerability_set[step]:
                            strategy_to_step_to_vulnerability_struct_list[target_strategy][step].append(nvd_cve_struct["cve"])


            # Fetch router vulnerabilities
            router_vulnerabilities = RouterGenerator.generate_router_vulnerability_entries()
            for vuln in router_vulnerabilities:
                for step in strategy_to_step_to_vulnerability_struct_list[target_strategy]:
                    if vuln not in strategy_to_step_to_vulnerability_struct_list[target_strategy][step]:
                        strategy_to_step_to_vulnerability_struct_list[target_strategy][step].append(router_vulnerabilities[vuln])




            # Compile environment
            if not os.path.exists(RealTopologyInventoryGenerator.INVENTORIES_ROOT_FOLDER): os.mkdir(RealTopologyInventoryGenerator.INVENTORIES_ROOT_FOLDER)

            for step in step_to_host_list:

                f = open(RealTopologyInventoryGenerator.INVENTORIES_ROOT_FOLDER+"real_topology_sc_"+str(target_scanner)+"_f_"+str(target_strategy)+"_st_"+str(step)+".json",mode="w",encoding="utf-8")
                environment_struct = dict()
                environment_struct["devices"] = step_to_host_list[step]
                environment_struct["vulnerabilities"] = strategy_to_step_to_vulnerability_struct_list[target_strategy][step]
                environment_struct["edges"] = step_to_edge_list[step]
                f.write(json.dumps(environment_struct))
                f.close()

            logging.info("[GENERATION] END GENERATION of real scenario, real topology",)
                        
        except Exception as e:
            traceback.print_exc()
            logging.error("%s",e)

"""
ministruct,megastruct,nvd_struct = RealTopologyInventoryGenerator.load()
print("")
f = open(file="test.json",mode="w",encoding="utf-8")
f.write(json.dumps(megastruct))
f.close()
RealTopologyInventoryGenerator.run(["merged","m3",10,101,ministruct,megastruct,nvd_struct])
#"""