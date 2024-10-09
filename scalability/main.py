import logging, os, json, csv
from pebble import ProcessPool

from inventory_generator.generate_network import SyntheticInventoryGenerator
from inventory_processing.processing import InventoryProcessor

from attack_graph.generation import generate_graph
from attack_graph.main_analysis_ag import main_analysis
import config

INVENTORIES_ROOT_FOLDER = config.NETWORK_FOLDER

if __name__ == "__main__":
    if not os.path.exists("logging/"): os.mkdir("logging/")

    logging.basicConfig(filename='logging/main.log', level=logging.INFO, 
        format='%(asctime)s - %(levelname)s: %(message)s')

    """
    Generate synthetic networks (do not run together with real network generator)
    """
    if not os.path.exists(config.NETWORK_FOLDER): os.mkdir(config.NETWORK_FOLDER)
    nvd_res,adv_k,adv_cve = SyntheticInventoryGenerator.load()

    params_network=[]
    for ns in config.diversity:
        for nh in config.nhosts:
            for nv in config.nvulns:
                params_network.append([ns,nh,nv,nvd_res,adv_k,adv_cve])
    
    with ProcessPool(max_workers=config.num_cores) as pool:
        process = pool.map(SyntheticInventoryGenerator.run, params_network)

    logging.info("************** [GENERATED SYNTHETIC NETWORKS] **************")


    """
    Compute aggregation heuristics
    """
    reset_aggregation_time=True
    if not os.path.exists(config.ANALYSIS_FOLDER): os.mkdir(config.ANALYSIS_FOLDER)
    if not os.path.exists(config.ANALYSIS_AGGREGATION_FILE) or reset_aggregation_time:
        with open(config.ANALYSIS_AGGREGATION_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['network','seed','hosts','vulns','model','filter','aggregation','aggregation_time'])

    name_to_inventory = dict()
    for file in os.listdir(INVENTORIES_ROOT_FOLDER):
        if os.path.isfile(INVENTORIES_ROOT_FOLDER+file):
            if file.endswith(".json"):
                f = open(file=INVENTORIES_ROOT_FOLDER+file,mode="r",encoding="utf-8")
                name_to_inventory[file.replace(".json","")] = json.loads(f.read())
                f.close()
    
    params_heuristics = []
    for inventory_name in name_to_inventory:
        params_heuristics.append([name_to_inventory, inventory_name])

    with ProcessPool(max_workers=config.num_cores) as pool:
        process = pool.map(InventoryProcessor.perform, params_heuristics)


    logging.info("************ [PERFORMED AGGREGATION HEURISTICS] ************")

    """
    Generate Attack Graphs
    """
    if not os.path.exists(config.GRAPH_FOLDER): os.mkdir(config.GRAPH_FOLDER)
    
    reset_generation_time=True
    if not os.path.exists(config.ANALYSIS_TIME_FILE) or reset_generation_time:
        with open(config.ANALYSIS_TIME_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['network','seed','hosts','vulns','model','filter','aggregation','generation_time'])

    params_graph=[]
    for fdir in os.listdir(config.NETWORK_FOLDER):
        params_graph.append(fdir)
    
    with ProcessPool(max_workers=config.num_cores) as pool:
        process = pool.map(generate_graph, params_graph)

    logging.info("***************** [ATTACK GRAPH GENERATED] *****************")

    """
    Run attack graph analyses
    """
    main_analysis()
    logging.info("END APPROACH (analysis performed)")
