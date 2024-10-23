import os, time, csv, logging
import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))

from attack_graph.netspa import generate_netspa_model
from attack_graph.tva import generate_tva_model
from attack_graph.multig import generate_multig_model
import config

def generate_graph(params):
    logging.basicConfig(filename='logging/attack_graph.log', level=logging.DEBUG, 
        format='%(asctime)s - %(levelname)s: %(message)s')
    
    fdir = params

    if os.path.isdir(config.NETWORK_FOLDER+fdir):
        try:
            logging.info("[ATTACK GRAPH] START generation %s", fdir)


            base_folder = config.NETWORK_FOLDER+fdir+"/"
            graph_folder = config.GRAPH_FOLDER+fdir+"/"
            
            for net_file in os.listdir(base_folder):
                if not os.path.exists(graph_folder): os.mkdir(graph_folder)
                
                start_netspa=time.perf_counter()
                generate_netspa_model(base_folder+net_file,graph_folder)
                end_netspa=time.perf_counter()

                start_tva=time.perf_counter()
                generate_tva_model(base_folder+net_file,graph_folder)
                end_tva=time.perf_counter()

                start_multi=time.perf_counter()
                generate_multig_model(base_folder+net_file,graph_folder)
                end_multi=time.perf_counter()


                network_type = base_folder.split("/")[2]
                network_params = network_type.split("_")
                info_file = net_file.split("-")
                filter_level = int(info_file[0].replace("f",""))
                aggregation_level = int(info_file[1].replace("a",""))

                n_seed = int(network_params[0].replace("s",""))
                n_host = int(network_params[1].replace("h",""))
                n_vuln = int(network_params[2].replace("v",""))

                with open(config.ANALYSIS_TIME_FILE, 'a', newline='') as fd:
                    writer = csv.writer(fd)
                    writer.writerow([
                        network_type,n_seed,n_host,n_vuln,"NETSPA",filter_level,aggregation_level,
                        end_netspa-start_netspa]
                    )
                    writer.writerow([
                        network_type,n_seed,n_host,n_vuln,"TVA",filter_level,aggregation_level,
                        end_tva-start_tva]
                    )
                    writer.writerow([
                        network_type,n_seed,n_host,n_vuln,"MULTI",filter_level,aggregation_level,
                        end_multi-start_multi]
                    )
            
            logging.info("[ATTACK GRAPH] END generation %s", fdir)
        except Exception as e:
            logging.error(e)