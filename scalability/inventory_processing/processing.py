# Import lib
import json, sys, os, csv, time, logging

# Import subclasses
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))

from inventory_processing.aggregator import Aggregator
import config



class InventoryProcessor:

    INVENTORIES_ROOT_FOLDER = config.NETWORK_FOLDER

    def perform(params):
        
        logging.basicConfig(filename='logging/heuristics.log', level=logging.DEBUG, 
            format='%(asctime)s - %(levelname)s: %(message)s')
        
        name_to_inventory, inventory_name = params
        
        # # Load reference inventories
        # name_to_inventory = dict()
        # for file in os.listdir(InventoryProcessor.INVENTORIES_ROOT_FOLDER):
        #     if os.path.isfile(InventoryProcessor.INVENTORIES_ROOT_FOLDER+file):
        #         if file.endswith(".json"):
        #             f = open(file=InventoryProcessor.INVENTORIES_ROOT_FOLDER+file,mode="r",encoding="utf-8")
        #             name_to_inventory[file.replace(".json","")] = json.loads(f.read())
        #             f.close()

        reset_aggregation_time=True
        if not os.path.exists(config.ANALYSIS_AGGREGATION_FILE) or reset_aggregation_time:
            with open(config.ANALYSIS_AGGREGATION_FILE, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['network','seed','hosts','vulns','model','filter','aggregation','aggregation_time'])

        # # Begin working for each inventory
        # for inventory_name in name_to_inventory:
            
        logging.info("[HEURISTIC] START network %s", inventory_name)

        # Build output folder
        output_folder = InventoryProcessor.INVENTORIES_ROOT_FOLDER+inventory_name+"_aggregation/"
        if os.path.exists(output_folder):
            for file in os.listdir(output_folder):
                os.remove(output_folder+file)
            os.rmdir(output_folder)
        os.mkdir(output_folder)

        # Load inventory
        reference_inventory = name_to_inventory[inventory_name]

        # Parse inventory
        device_to_platforms = dict()
        device_to_interfaces = dict()
        #device_to_vulnerabilities = dict()
        device_to_interface_to_vulnerabilities = dict()
        device_to_local_vulnerabilities = dict()

        #device_to_application_to_platforms = dict()
        #device_to_application_to_vulnerabilities = dict()

        for device_struct in reference_inventory["devices"]:
            device_to_platforms[device_struct["id"]] = set()
            #device_to_vulnerabilities[device_struct["id"]] = set()
            device_to_local_vulnerabilities[device_struct["id"]] = set()

            #device_to_application_to_platforms[device_struct["id"]] = dict()
            #device_to_application_to_vulnerabilities[device_struct["id"]] = dict()

            for application_struct in device_struct["local_applications"]:
                #device_to_application_to_platforms[device_struct["id"]][application_struct["id"]] = set()
                #device_to_application_to_vulnerabilities[device_struct["id"]][application_struct["id"]] = set()

                for service_struct in application_struct["service"]:
                    for cve_id in service_struct["cve_list"]:
                        #device_to_vulnerabilities[device_struct["id"]].add(cve_id)
                        device_to_local_vulnerabilities[device_struct["id"]].add(cve_id)
                        #device_to_application_to_vulnerabilities[device_struct["id"]][application_struct["id"]].add(cve_id)
                    for cpe in service_struct["cpe_list"]:
                        device_to_platforms[device_struct["id"]].add(cpe)
                        #device_to_application_to_platforms[device_struct["id"]][application_struct["id"]].add(cpe)


        #device_to_network_to_port_to_platforms = dict()
        #device_to_network_to_port_to_vulnerabilities = dict()

        for device_struct in reference_inventory["devices"]:
            device_to_interfaces[device_struct["id"]] = set()
            device_to_interface_to_vulnerabilities[device_struct["id"]] = dict()
            #device_to_network_to_port_to_platforms[device_struct["id"]] = dict()
            #device_to_network_to_port_to_vulnerabilities[device_struct["id"]] = dict()

            for interface_struct in device_struct["network_interfaces"]:
                device_to_interfaces[device_struct["id"]].add(interface_struct["ipaddress"])
                device_to_interface_to_vulnerabilities[device_struct["id"]][interface_struct["ipaddress"]] = set()
                #device_to_network_to_port_to_platforms[device_struct["id"]][interface_struct["ipaddress"]] = dict()
                #device_to_network_to_port_to_vulnerabilities[device_struct["id"]][interface_struct["ipaddress"]] = dict()

                for port_struct in interface_struct["ports"]:
                    #device_to_network_to_port_to_platforms[device_struct["id"]][interface_struct["ipaddress"]][port_struct["number"]] = set()
                    #device_to_network_to_port_to_vulnerabilities[device_struct["id"]][interface_struct["ipaddress"]][port_struct["number"]] = set()

                    service_struct = port_struct["service"]
                    for cve_id in service_struct["cve_list"]:
                        #device_to_vulnerabilities[device_struct["id"]].add(cve_id)
                        device_to_interface_to_vulnerabilities[device_struct["id"]][interface_struct["ipaddress"]].add(cve_id)
                        #device_to_network_to_port_to_vulnerabilities[device_struct["id"]][interface_struct["ipaddress"]][port_struct["number"]].add(cve_id)
                    for cpe in service_struct["cpe_list"]:
                        device_to_platforms[device_struct["id"]].add(cpe)
                        #device_to_network_to_port_to_platforms[device_struct["id"]][interface_struct["ipaddress"]][port_struct["number"]].add(cpe)



        # Iterate aggregation variable
        for aggregation_mode in range(4):
            start = time.perf_counter()

            # Prepare output
            output_struct = dict()
            output_struct["devices"] = reference_inventory["devices"]
            output_struct["vulnerabilities"] = reference_inventory["vulnerabilities"]
            output_struct["edges"] = reference_inventory["edges"]
            output_struct["meta_devices"] = list()
            output_struct["meta_vulnerabilities"] = list()

            # Iterate devices
            for device_id in device_to_platforms:

                # Prepare payload for aggregator subprocesses
                local_vulnerability_list = list()
                for cve_struct in reference_inventory["vulnerabilities"]:
                    if cve_struct["id"] in device_to_local_vulnerabilities[device_id]:
                        local_vulnerability_list.append(cve_struct)

                network_vulnerability_list = list()
                for interface_id in device_to_interfaces[device_id]:
                    for cve_struct in reference_inventory["vulnerabilities"]:
                        if cve_struct["id"] in device_to_interface_to_vulnerabilities[device_id][interface_id]:
                            network_vulnerability_list.append(cve_struct)

                # Perform Aggregator subprocesses
                aggregation_class_to_local_vulnerabilities = Aggregator.perform(aggregation_mode,local_vulnerability_list)
                aggregation_class_to_network_vulnerabilities = Aggregator.perform(aggregation_mode,network_vulnerability_list)


                # Get reference structure
                reference_device_structure = dict()
                for device_struct in reference_inventory["devices"]:
                    if device_struct["id"] == device_id:
                        reference_device_structure = device_struct
                        break


                # Device output struct
                device_output_struct = dict()
                device_output_struct["id"] = device_id
                device_output_struct["network_meta_cve_list"] = list()
                device_output_struct["local_meta_cve_list"] = list()
                device_output_struct["cpe_list"] = list(device_to_platforms[device_id])

                # Network vulnerabilities
                for aggregation_class_id in aggregation_class_to_network_vulnerabilities:
                    if len(aggregation_class_to_network_vulnerabilities[aggregation_class_id]["vulnerability_id_list"]) > 0:
                        device_output_struct["network_meta_cve_list"].append(device_id+"_network_"+aggregation_class_id)

                        # Now add the meta vuln to the general file
                        output_struct["meta_vulnerabilities"].append({
                            "id": device_id+"_network_"+aggregation_class_id,
                            "device_id": device_id,
                            "cve_list": aggregation_class_to_network_vulnerabilities[aggregation_class_id]["vulnerability_id_list"],
                            "pre_condition": aggregation_class_to_network_vulnerabilities[aggregation_class_id]["pre_condition"],
                            "post_condition": aggregation_class_to_network_vulnerabilities[aggregation_class_id]["post_condition"],
                            "cvss_metrics": aggregation_class_to_network_vulnerabilities[aggregation_class_id]["cvss_metrics"],
                            "type": "network"
                        })

                # Local vulnerabilities
                for aggregation_class_id in aggregation_class_to_local_vulnerabilities:
                    if len(aggregation_class_to_local_vulnerabilities[aggregation_class_id]["vulnerability_id_list"]) > 0:
                        device_output_struct["local_meta_cve_list"].append(device_id+"_local_"+aggregation_class_id)

                        # Now add the meta vuln to the general file
                        output_struct["meta_vulnerabilities"].append({
                            "id": device_id+"_local_"+aggregation_class_id,
                            "device_id": device_id,
                            "cve_list": aggregation_class_to_local_vulnerabilities[aggregation_class_id]["vulnerability_id_list"],
                            "pre_condition": aggregation_class_to_local_vulnerabilities[aggregation_class_id]["pre_condition"],
                            "post_condition": aggregation_class_to_local_vulnerabilities[aggregation_class_id]["post_condition"],
                            "cvss_metrics": aggregation_class_to_local_vulnerabilities[aggregation_class_id]["cvss_metrics"],
                            "type": "local"
                        })

                output_struct["meta_devices"].append(device_output_struct)

            end = time.perf_counter()

            if aggregation_mode == 0: tot_time = 0
            else: tot_time = end-start
            

            inventory_params = inventory_name.split("_")
            n_seed = int(inventory_params[0].replace("s",""))
            n_host = int(inventory_params[1].replace("h",""))
            n_vuln = int(inventory_params[2].replace("v",""))
            params_network = [inventory_name+"_aggregation",n_seed,n_host,n_vuln]

            
            with open(config.ANALYSIS_AGGREGATION_FILE, 'a', newline='') as fd:
                writer = csv.writer(fd)
                writer.writerow([inventory_name+"_aggregation",n_seed,n_host,n_vuln,"NETSPA",aggregation_mode,tot_time])
                writer.writerow([inventory_name+"_aggregation",n_seed,n_host,n_vuln,"TVA",aggregation_mode,tot_time])
                writer.writerow([inventory_name+"_aggregation",n_seed,n_host,n_vuln,"MULTI",aggregation_mode,tot_time])


            # Dump output
            f = open(file=output_folder+"a"+str(aggregation_mode)+"_inventory.json",mode="w",encoding="utf-8")
            f.write(json.dumps(output_struct))
            f.close()

        logging.info("[HEURISTIC] END network %s", inventory_name)
