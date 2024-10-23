import os
import sys
import json
import random

import sympy

import networkx as nx

#from filtering.engine.sequential_graph_runner import SequentialGraphRunner
from filtering.engine.dynamic_graph_runner import DynamicGraphRunner
from filtering.engine.graph_runner import GraphRunner

from filtering.engine.scoring_engine import ScoringEngine



class GraphFilter:
    def run(
        # Version driver
        NO_VERSION = False,
        VERSION = False,
        VERSION_EXTENDED = True,
        SPLIT_VERSION = False,
        SPLIT_OPTIMIZATION = False,


        # Strategy driver
        #CALC_SCORES_ONCE = False
        VALIDATION_MODE = 3,
        # 1 - completely random
        # 2 - cutting out useless cpe
        # 3 - heuristic
        # 4 - worst cve first
        # 5 - worst cve first, then heuristic among cpe
        # 6 - heuristic first, then worst cve - only if USE_PLATFORM_THEN_VERSIONS == True, paper 3


        # Random Driver
        RANDOM_SEED = 101,


        # Snapshot driver
        SNAPSHOT_ID = "cyberrange_merged",


        # Directories
        FOLDER_PREFIX = ""
    ):



        """
        # Check if parameters have been passed
        if len(sys.argv) > 1:
            # argv0 is always title
            # argv1 is keyword
            if sys.argv[1] == "parallel_validation":
                print("Parameters Recieved!:")
                print(" - snapshot_id: "+sys.argv[2])
                print(" - mode: "+sys.argv[6])
                print(" - seed: "+sys.argv[4])
                print("Godspeed!")

                # argv2 is SNAPSHOT_ID
                SNAPSHOT_ID = sys.argv[2]

                # argv3 is FOLDER_PREFIX
                FOLDER_PREFIX = sys.argv[3]

                # argv4 is RANDOM_SEED
                RANDOM_SEED = int(sys.argv[4])

                # argv5 is VALIDATION_MODE
                VALIDATION_MODE = int(sys.argv[5])

                # argv6 is USE_NO_VERSION
                NO_VERSION = sys.argv[6] == "True"

                # argv7 is USE_VERSIONS
                VERSION = sys.argv[7] == "True"

                # argv8 is USE_EXTENDED_VERSIONS
                VERSION_EXTENDED = sys.argv[8] == "True"
                
                # argv9 is USE_SPLITTED_VERSION
                SPLIT_VERSION = sys.argv[9] == "True"

                # argv10 is USE_SPLITTED_VERSION_OPTIMIZATION
                SPLIT_OPTIMIZATION = sys.argv[10] == "True"
            """



        # Directories
        BASE_DIR = FOLDER_PREFIX
        DATASET_DIR = BASE_DIR+"dataset"
        LOG_DIR = BASE_DIR+"filtering/log"
        OUTPUT_DIR = DATASET_DIR+"/filtered_inventories"
        INPUT_DIR = DATASET_DIR+"/raw_inventories"


        # Seed
        random.seed(RANDOM_SEED)



        # Load snapshots
        host_to_advisory_to_cve_noversion = dict()
        host_to_cpe_to_advisory_noversion = dict()
        host_to_cve_to_cpe_noversion = dict()
        host_to_validation_inventory_noversion = dict()
        host_to_validation_inventory_inert_noversion = dict()

        host_to_advisory_to_cve_version = dict()
        host_to_cpe_to_advisory_version = dict()
        host_to_cve_to_cpe_version = dict()
        host_to_validation_inventory_version = dict()
        host_to_validation_inventory_inert_version = dict()

        host_to_advisory_to_cve_extended_version = dict()
        host_to_cpe_to_advisory_extended_version = dict()
        host_to_cve_to_cpe_extended_version = dict()
        host_to_validation_inventory_extended_version = dict()
        host_to_validation_inventory_inert_extended_version = dict()

        host_to_advisory_to_cve_splitversion = dict()
        host_to_cpe_to_advisory_splitversion = dict()
        host_to_cve_to_cpe_splitversion = dict()
        host_to_validation_inventory_splitversion = dict()
        host_to_validation_inventory_inert_splitversion = dict()

        host_to_advisory_to_cve_splitversion_opt = dict()
        host_to_cpe_to_advisory_splitversion_opt = dict()
        host_to_cve_to_cpe_splitversion_opt = dict()
        host_to_validation_inventory_splitversion_opt = dict()
        host_to_validation_inventory_inert_splitversion_opt = dict()


        f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/snapshot_meta.json",mode="r",encoding="utf-8")
        hosts_meta = json.loads(f.read())
        f.close()

        for host_id in hosts_meta["hosts"]:
            if NO_VERSION == True:
                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/no_version/advisory_to_cve.json")
                host_to_advisory_to_cve_noversion[host_id] = json.loads(f.read())
                f.close()

                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/no_version/cpe_to_advisory.json")
                host_to_cpe_to_advisory_noversion[host_id] = json.loads(f.read())
                f.close()

                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/no_version/cve_to_cpe.json")
                host_to_cve_to_cpe_noversion[host_id] = json.loads(f.read())
                f.close()

                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/no_version/validation_inventory.json")
                host_to_validation_inventory_noversion[host_id] = json.loads(f.read())
                f.close()

                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/no_version/validation_inventory_inert.json")
                host_to_validation_inventory_inert_noversion[host_id] = json.loads(f.read())
                f.close()

            if VERSION == True:
                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/version/advisory_to_cve.json")
                host_to_advisory_to_cve_version[host_id] = json.loads(f.read())
                f.close()

                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/version/cpe_to_advisory.json")
                host_to_cpe_to_advisory_version[host_id] = json.loads(f.read())
                f.close()

                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/version/cve_to_cpe.json")
                host_to_cve_to_cpe_version[host_id] = json.loads(f.read())
                f.close()

                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/version/validation_inventory.json")
                host_to_validation_inventory_version[host_id] = json.loads(f.read())
                f.close()

                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/version/validation_inventory_inert.json")
                host_to_validation_inventory_inert_version[host_id] = json.loads(f.read())
                f.close()

            if VERSION_EXTENDED == True:
                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/version_expanded/advisory_to_cve.json")
                host_to_advisory_to_cve_extended_version[host_id] = json.loads(f.read())
                f.close()

                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/version_expanded/cpe_to_advisory.json")
                host_to_cpe_to_advisory_extended_version[host_id] = json.loads(f.read())
                f.close()

                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/version_expanded/cve_to_cpe.json")
                host_to_cve_to_cpe_extended_version[host_id] = json.loads(f.read())
                f.close()

                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/version_expanded/validation_inventory.json")
                host_to_validation_inventory_extended_version[host_id] = json.loads(f.read())
                f.close()

                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/version_expanded/validation_inventory_inert.json")
                host_to_validation_inventory_inert_extended_version[host_id] = json.loads(f.read())
                f.close()

            if SPLIT_VERSION == True:
                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/splitversion/advisory_to_cve.json")
                host_to_advisory_to_cve_splitversion[host_id] = json.loads(f.read())
                f.close()

                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/splitversion/cpe_to_advisory.json")
                host_to_cpe_to_advisory_splitversion[host_id] = json.loads(f.read())
                f.close()

                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/splitversion/cve_to_cpe.json")
                host_to_cve_to_cpe_splitversion[host_id] = json.loads(f.read())
                f.close()

                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/splitversion/validation_inventory.json")
                host_to_validation_inventory_splitversion[host_id] = json.loads(f.read())
                f.close()

                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/splitversion/validation_inventory_inert.json")
                host_to_validation_inventory_inert_splitversion[host_id] = json.loads(f.read())
                f.close()

            if SPLIT_OPTIMIZATION == True:
                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/splitversion_opt/advisory_to_cve.json")
                host_to_advisory_to_cve_splitversion_opt[host_id] = json.loads(f.read())
                f.close()

                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/splitversion_opt/cpe_to_advisory.json")
                host_to_cpe_to_advisory_splitversion_opt[host_id] = json.loads(f.read())
                f.close()

                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/splitversion_opt/cve_to_cpe.json")
                host_to_cve_to_cpe_splitversion_opt[host_id] = json.loads(f.read())
                f.close()

                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/splitversion_opt/validation_inventory.json")
                host_to_validation_inventory_splitversion_opt[host_id] = json.loads(f.read())
                f.close()

                f = open(file = INPUT_DIR+"/"+SNAPSHOT_ID+"/"+host_id+"/splitversion_opt/validation_inventory_inert.json")
                host_to_validation_inventory_inert_splitversion_opt[host_id] = json.loads(f.read())
                f.close()




        # Service functions
        # Grab cpe_to_advisory
        def grab_cpe_to_advisory(original_cpe_to_advisory):
            cpe_vendor_to_cpe = dict()
            cpe_vendor_to_advisory = dict()

            cpe_product_to_cpe = dict()
            cpe_product_to_advisory = dict()

            cpe_version_to_cpe = dict()
            cpe_version_to_advisory = dict()

            for cpe in original_cpe_to_advisory:
                part,vendor,product,version = GraphRunner.coherent_cpe_split(cpe)

                if part+":"+vendor not in cpe_vendor_to_cpe:
                    cpe_vendor_to_cpe[part+":"+vendor] = set()
                if part+":"+vendor not in cpe_vendor_to_advisory:
                    cpe_vendor_to_advisory[part+":"+vendor] = set()
                
                cpe_vendor_to_cpe[part+":"+vendor].add(cpe)
                cpe_vendor_to_advisory[part+":"+vendor] = cpe_vendor_to_advisory[part+":"+vendor].union(set(original_cpe_to_advisory[cpe]))

                if part+":"+vendor+":"+product not in cpe_product_to_cpe:
                    cpe_product_to_cpe[part+":"+vendor+":"+product] = set()
                if part+":"+vendor+":"+product not in cpe_product_to_advisory:
                    cpe_product_to_advisory[part+":"+vendor+":"+product] = set()

                cpe_product_to_cpe[part+":"+vendor+":"+product].add(cpe)
                cpe_product_to_advisory[part+":"+vendor+":"+product] = cpe_product_to_advisory[part+":"+vendor+":"+product].union(set(original_cpe_to_advisory[cpe]))

                if part+":"+vendor+":"+product+":"+version not in cpe_version_to_cpe:
                    cpe_version_to_cpe[part+":"+vendor+":"+product+":"+version] = set()
                if part+":"+vendor+":"+product+":"+version not in cpe_version_to_advisory:
                    cpe_version_to_advisory[part+":"+vendor+":"+product+":"+version] = set()

                cpe_version_to_cpe[part+":"+vendor+":"+product+":"+version].add(cpe)
                cpe_version_to_advisory[part+":"+vendor+":"+product+":"+version] = cpe_version_to_advisory[part+":"+vendor+":"+product+":"+version].union(set(original_cpe_to_advisory[cpe]))

            return cpe_vendor_to_cpe,cpe_vendor_to_advisory,cpe_product_to_cpe,cpe_product_to_advisory,cpe_version_to_cpe,cpe_version_to_advisory




        ## RECALC TREES AND GRAPHS FOR SCORING
        print("## RECALC TREES")

        # Noversion
        host_to_cpe_vendor_to_cpe_noversion = dict()
        host_to_cpe_product_to_cpe_noversion = dict()
        #host_to_cpe_version_to_cpe_noversion = dict()

        host_to_cpe_to_cpe_mod_noversion = dict()

        host_to_cpe_vendor_to_advisory_noversion = dict()
        host_to_cpe_product_to_advisory_noversion = dict()
        #host_to_cpe_version_to_advisory_noversion = dict()

        host_to_cpe_vendor_to_advisory_max_noversion = dict()
        host_to_cpe_product_to_advisory_max_noversion = dict()
        #host_to_cpe_version_to_advisory_max_noversion = dict()

        host_to_cve_to_cpe_tree_vendor_noversion = dict()
        host_to_cve_to_cpe_tree_product_noversion = dict()
        #host_to_cve_to_cpe_tree_version_noversion = dict()

        if NO_VERSION == True:
            for host_id in host_to_cve_to_cpe_noversion:
                host_to_cve_to_cpe_tree_vendor_noversion[host_id] = dict()
                host_to_cve_to_cpe_tree_product_noversion[host_id] = dict()
                #host_to_cve_to_cpe_tree_version_noversion[host_id] = dict()

                # Grab cpe_to_advisory
                cpe_vendor_to_cpe,cpe_vendor_to_advisory,cpe_product_to_cpe,cpe_product_to_advisory,cpe_version_to_cpe,cpe_version_to_advisory = grab_cpe_to_advisory(host_to_cpe_to_advisory_noversion[host_id])

                host_to_cpe_vendor_to_cpe_noversion[host_id] = cpe_vendor_to_cpe
                host_to_cpe_product_to_cpe_noversion[host_id] = cpe_product_to_cpe
                #host_to_cpe_version_to_cpe_noversion[host_id] = cpe_version_to_cpe

                # Reverse cpe to cpe
                host_to_cpe_to_cpe_mod_noversion[host_id] = dict()
                for cpe_mod in cpe_vendor_to_cpe:
                    for cpe in cpe_vendor_to_cpe[cpe_mod]:
                        if cpe not in host_to_cpe_to_cpe_mod_noversion[host_id]:
                            host_to_cpe_to_cpe_mod_noversion[host_id][cpe] = set()
                        host_to_cpe_to_cpe_mod_noversion[host_id][cpe].add(cpe_mod)
                for cpe_mod in cpe_product_to_cpe:
                    for cpe in cpe_product_to_cpe[cpe_mod]:
                        if cpe not in host_to_cpe_to_cpe_mod_noversion[host_id]:
                            host_to_cpe_to_cpe_mod_noversion[host_id][cpe] = set()
                        host_to_cpe_to_cpe_mod_noversion[host_id][cpe].add(cpe_mod)
                #for cpe_mod in cpe_version_to_cpe:
                    #for cpe in cpe_version_to_cpe[cpe_mod]:
                        #if cpe not in host_to_cpe_to_cpe_mod_noversion[host_id]:
                            #host_to_cpe_to_cpe_mod_noversion[host_id][cpe] = set()
                        #host_to_cpe_to_cpe_mod_noversion[host_id][cpe].add(cpe_mod)

                host_to_cpe_vendor_to_advisory_noversion[host_id] = cpe_vendor_to_advisory
                host_to_cpe_product_to_advisory_noversion[host_id] = cpe_product_to_advisory
                #host_to_cpe_version_to_advisory_noversion[host_id] = cpe_version_to_advisory
                
                host_to_cpe_vendor_to_advisory_max_noversion[host_id] = 0
                host_to_cpe_product_to_advisory_max_noversion[host_id] = 0
                #host_to_cpe_version_to_advisory_max_noversion[host_id] = 0
                
                # Assemble tree
                for cve in host_to_cve_to_cpe_noversion[host_id]:
                    cve_tree_vendor,cve_tree_product,cve_tree_version = GraphRunner.assemble_logic_tree(host_to_cve_to_cpe_noversion[host_id][cve])

                    cve_tree_vendor_struct = GraphRunner.sympy_to_structure(cve_tree_vendor)
                    cve_tree_product_struct = GraphRunner.sympy_to_structure(cve_tree_product)
                    #cve_tree_version_struct = GraphRunner.sympy_to_structure(cve_tree_version)

                    host_to_cve_to_cpe_tree_vendor_noversion[host_id][cve] = cve_tree_vendor_struct
                    host_to_cve_to_cpe_tree_product_noversion[host_id][cve] = cve_tree_product_struct
                    #host_to_cve_to_cpe_tree_version_noversion[host_id][cve] = cve_tree_version_struct

            # Get max values
            for host_id in host_to_cpe_vendor_to_cpe_noversion:

                for cpe in host_to_cpe_vendor_to_cpe_noversion[host_id]:
                    host_to_cpe_vendor_to_advisory_max_noversion[host_id] = max(host_to_cpe_vendor_to_advisory_max_noversion[host_id],len(host_to_cpe_vendor_to_cpe_noversion[host_id][cpe]))

                for cpe in host_to_cpe_product_to_cpe_noversion[host_id]:
                    host_to_cpe_product_to_advisory_max_noversion[host_id] = max(host_to_cpe_product_to_advisory_max_noversion[host_id],len(host_to_cpe_product_to_cpe_noversion[host_id][cpe]))
                
                #for cpe in host_to_cpe_version_to_cpe_noversion[host_id]:
                    #host_to_cpe_version_to_advisory_max_noversion[host_id] = max(host_to_cpe_version_to_advisory_max_noversion[host_id],len(host_to_cpe_version_to_cpe_noversion[host_id][cpe]))




        # Version
        host_to_cpe_vendor_to_cpe_version = dict()
        host_to_cpe_product_to_cpe_version = dict()
        host_to_cpe_version_to_cpe_version = dict()

        host_to_cpe_to_cpe_mod_version = dict()

        host_to_cpe_vendor_to_advisory_version = dict()
        host_to_cpe_product_to_advisory_version = dict()
        host_to_cpe_version_to_advisory_version = dict()

        host_to_cpe_vendor_to_advisory_max_version = dict()
        host_to_cpe_product_to_advisory_max_version = dict()
        host_to_cpe_version_to_advisory_max_version = dict()

        host_to_cve_to_cpe_tree_vendor_version = dict()
        host_to_cve_to_cpe_tree_product_version = dict()
        host_to_cve_to_cpe_tree_version_version = dict()

        if VERSION == True:
            for host_id in host_to_cve_to_cpe_version:
                host_to_cve_to_cpe_tree_vendor_version[host_id] = dict()
                host_to_cve_to_cpe_tree_product_version[host_id] = dict()
                host_to_cve_to_cpe_tree_version_version[host_id] = dict()

                # Grab cpe_to_advisory
                cpe_vendor_to_cpe,cpe_vendor_to_advisory,cpe_product_to_cpe,cpe_product_to_advisory,cpe_version_to_cpe,cpe_version_to_advisory = grab_cpe_to_advisory(host_to_cpe_to_advisory_version[host_id])

                host_to_cpe_vendor_to_cpe_version[host_id] = cpe_vendor_to_cpe
                host_to_cpe_product_to_cpe_version[host_id] = cpe_product_to_cpe
                host_to_cpe_version_to_cpe_version[host_id] = cpe_version_to_cpe

                # Reverse cpe to cpe
                host_to_cpe_to_cpe_mod_version[host_id] = dict()
                for cpe_mod in cpe_vendor_to_cpe:
                    for cpe in cpe_vendor_to_cpe[cpe_mod]:
                        if cpe not in host_to_cpe_to_cpe_mod_version[host_id]:
                            host_to_cpe_to_cpe_mod_version[host_id][cpe] = set()
                        host_to_cpe_to_cpe_mod_version[host_id][cpe].add(cpe_mod)
                for cpe_mod in cpe_product_to_cpe:
                    for cpe in cpe_product_to_cpe[cpe_mod]:
                        if cpe not in host_to_cpe_to_cpe_mod_version[host_id]:
                            host_to_cpe_to_cpe_mod_version[host_id][cpe] = set()
                        host_to_cpe_to_cpe_mod_version[host_id][cpe].add(cpe_mod)
                for cpe_mod in cpe_version_to_cpe:
                    for cpe in cpe_version_to_cpe[cpe_mod]:
                        if cpe not in host_to_cpe_to_cpe_mod_version[host_id]:
                            host_to_cpe_to_cpe_mod_version[host_id][cpe] = set()
                        host_to_cpe_to_cpe_mod_version[host_id][cpe].add(cpe_mod)

                host_to_cpe_vendor_to_advisory_version[host_id] = cpe_vendor_to_advisory
                host_to_cpe_product_to_advisory_version[host_id] = cpe_product_to_advisory
                host_to_cpe_version_to_advisory_version[host_id] = cpe_version_to_advisory
                
                host_to_cpe_vendor_to_advisory_max_version[host_id] = 0
                host_to_cpe_product_to_advisory_max_version[host_id] = 0
                host_to_cpe_version_to_advisory_max_version[host_id] = 0
                
                # Assemble tree
                for cve in host_to_cve_to_cpe_version[host_id]:
                    cve_tree_vendor,cve_tree_product,cve_tree_version = GraphRunner.assemble_logic_tree(host_to_cve_to_cpe_version[host_id][cve])

                    cve_tree_vendor_struct = GraphRunner.sympy_to_structure(cve_tree_vendor)
                    cve_tree_product_struct = GraphRunner.sympy_to_structure(cve_tree_product)
                    cve_tree_version_struct = GraphRunner.sympy_to_structure(cve_tree_version)

                    host_to_cve_to_cpe_tree_vendor_version[host_id][cve] = cve_tree_vendor_struct
                    host_to_cve_to_cpe_tree_product_version[host_id][cve] = cve_tree_product_struct
                    host_to_cve_to_cpe_tree_version_version[host_id][cve] = cve_tree_version_struct

            # Get max values
            for host_id in host_to_cpe_vendor_to_cpe_version:

                for cpe in host_to_cpe_vendor_to_cpe_version[host_id]:
                    host_to_cpe_vendor_to_advisory_max_version[host_id] = max(host_to_cpe_vendor_to_advisory_max_version[host_id],len(host_to_cpe_vendor_to_cpe_version[host_id][cpe]))

                for cpe in host_to_cpe_product_to_cpe_version[host_id]:
                    host_to_cpe_product_to_advisory_max_version[host_id] = max(host_to_cpe_product_to_advisory_max_version[host_id],len(host_to_cpe_product_to_cpe_version[host_id][cpe]))
                
                for cpe in host_to_cpe_version_to_cpe_version[host_id]:
                    host_to_cpe_version_to_advisory_max_version[host_id] = max(host_to_cpe_version_to_advisory_max_version[host_id],len(host_to_cpe_version_to_cpe_version[host_id][cpe]))



        # Extended version
        host_to_cpe_vendor_to_cpe_extended_version = dict()
        host_to_cpe_product_to_cpe_extended_version = dict()
        host_to_cpe_version_to_cpe_extended_version = dict()

        host_to_cpe_to_cpe_mod_extended_version = dict()

        host_to_cpe_vendor_to_advisory_extended_version = dict()
        host_to_cpe_product_to_advisory_extended_version = dict()
        host_to_cpe_version_to_advisory_extended_version = dict()

        host_to_cpe_vendor_to_advisory_max_extended_version = dict()
        host_to_cpe_product_to_advisory_max_extended_version = dict()
        host_to_cpe_version_to_advisory_max_extended_version = dict()

        host_to_cve_to_cpe_tree_vendor_extended_version = dict()
        host_to_cve_to_cpe_tree_product_extended_version = dict()
        host_to_cve_to_cpe_tree_version_extended_version = dict()

        if VERSION_EXTENDED == True:
            for host_id in host_to_cve_to_cpe_extended_version:
                host_to_cve_to_cpe_tree_vendor_extended_version[host_id] = dict()
                host_to_cve_to_cpe_tree_product_extended_version[host_id] = dict()
                host_to_cve_to_cpe_tree_version_extended_version[host_id] = dict()

                # Grab cpe_to_advisory
                cpe_vendor_to_cpe,cpe_vendor_to_advisory,cpe_product_to_cpe,cpe_product_to_advisory,cpe_extended_version_to_cpe,cpe_extended_version_to_advisory = grab_cpe_to_advisory(host_to_cpe_to_advisory_extended_version[host_id])

                host_to_cpe_vendor_to_cpe_extended_version[host_id] = cpe_vendor_to_cpe
                host_to_cpe_product_to_cpe_extended_version[host_id] = cpe_product_to_cpe
                host_to_cpe_version_to_cpe_extended_version[host_id] = cpe_extended_version_to_cpe

                # Reverse cpe to cpe
                host_to_cpe_to_cpe_mod_extended_version[host_id] = dict()
                for cpe_mod in cpe_vendor_to_cpe:
                    for cpe in cpe_vendor_to_cpe[cpe_mod]:
                        if cpe not in host_to_cpe_to_cpe_mod_extended_version[host_id]:
                            host_to_cpe_to_cpe_mod_extended_version[host_id][cpe] = set()
                        host_to_cpe_to_cpe_mod_extended_version[host_id][cpe].add(cpe_mod)
                for cpe_mod in cpe_product_to_cpe:
                    for cpe in cpe_product_to_cpe[cpe_mod]:
                        if cpe not in host_to_cpe_to_cpe_mod_extended_version[host_id]:
                            host_to_cpe_to_cpe_mod_extended_version[host_id][cpe] = set()
                        host_to_cpe_to_cpe_mod_extended_version[host_id][cpe].add(cpe_mod)
                for cpe_mod in cpe_extended_version_to_cpe:
                    for cpe in cpe_extended_version_to_cpe[cpe_mod]:
                        if cpe not in host_to_cpe_to_cpe_mod_extended_version[host_id]:
                            host_to_cpe_to_cpe_mod_extended_version[host_id][cpe] = set()
                        host_to_cpe_to_cpe_mod_extended_version[host_id][cpe].add(cpe_mod)

                host_to_cpe_vendor_to_advisory_extended_version[host_id] = cpe_vendor_to_advisory
                host_to_cpe_product_to_advisory_extended_version[host_id] = cpe_product_to_advisory
                host_to_cpe_version_to_advisory_extended_version[host_id] = cpe_extended_version_to_advisory
                
                host_to_cpe_vendor_to_advisory_max_extended_version[host_id] = 0
                host_to_cpe_product_to_advisory_max_extended_version[host_id] = 0
                host_to_cpe_version_to_advisory_max_extended_version[host_id] = 0
                
                # Assemble tree
                for cve in host_to_cve_to_cpe_extended_version[host_id]:
                    cve_tree_vendor,cve_tree_product,cve_tree_extended_version = GraphRunner.assemble_logic_tree(host_to_cve_to_cpe_extended_version[host_id][cve])

                    cve_tree_vendor_struct = GraphRunner.sympy_to_structure(cve_tree_vendor)
                    cve_tree_product_struct = GraphRunner.sympy_to_structure(cve_tree_product)
                    cve_tree_extended_version_struct = GraphRunner.sympy_to_structure(cve_tree_extended_version)

                    host_to_cve_to_cpe_tree_vendor_extended_version[host_id][cve] = cve_tree_vendor_struct
                    host_to_cve_to_cpe_tree_product_extended_version[host_id][cve] = cve_tree_product_struct
                    host_to_cve_to_cpe_tree_version_extended_version[host_id][cve] = cve_tree_extended_version_struct

            # Get max values
            for host_id in host_to_cpe_vendor_to_cpe_extended_version:

                for cpe in host_to_cpe_vendor_to_cpe_extended_version[host_id]:
                    host_to_cpe_vendor_to_advisory_max_extended_version[host_id] = max(host_to_cpe_vendor_to_advisory_max_extended_version[host_id],len(host_to_cpe_vendor_to_cpe_extended_version[host_id][cpe]))

                for cpe in host_to_cpe_product_to_cpe_extended_version[host_id]:
                    host_to_cpe_product_to_advisory_max_extended_version[host_id] = max(host_to_cpe_product_to_advisory_max_extended_version[host_id],len(host_to_cpe_product_to_cpe_extended_version[host_id][cpe]))
                
                for cpe in host_to_cpe_version_to_cpe_extended_version[host_id]:
                    host_to_cpe_version_to_advisory_max_extended_version[host_id] = max(host_to_cpe_version_to_advisory_max_extended_version[host_id],len(host_to_cpe_version_to_cpe_extended_version[host_id][cpe]))



        # Splitversion
        host_to_cpe_vendor_to_cpe_splitversion = dict()
        host_to_cpe_product_to_cpe_splitversion = dict()
        host_to_cpe_version_to_cpe_splitversion = dict()

        host_to_cpe_to_cpe_mod_splitversion = dict()

        host_to_cpe_vendor_to_advisory_splitversion = dict()
        host_to_cpe_product_to_advisory_splitversion = dict()
        host_to_cpe_version_to_advisory_splitversion = dict()

        host_to_cpe_vendor_to_advisory_max_splitversion = dict()
        host_to_cpe_product_to_advisory_max_splitversion = dict()
        host_to_cpe_version_to_advisory_max_splitversion = dict()

        host_to_cve_to_cpe_tree_vendor_splitversion = dict()
        host_to_cve_to_cpe_tree_product_splitversion = dict()
        host_to_cve_to_cpe_tree_version_splitversion = dict()

        if SPLIT_VERSION == True:
            for host_id in host_to_cve_to_cpe_splitversion:
                host_to_cve_to_cpe_tree_vendor_splitversion[host_id] = dict()
                host_to_cve_to_cpe_tree_product_splitversion[host_id] = dict()
                host_to_cve_to_cpe_tree_version_splitversion[host_id] = dict()

                # Grab cpe_to_advisory
                cpe_vendor_to_cpe,cpe_vendor_to_advisory,cpe_product_to_cpe,cpe_product_to_advisory,cpe_version_to_cpe,cpe_version_to_advisory = grab_cpe_to_advisory(host_to_cpe_to_advisory_splitversion[host_id])

                host_to_cpe_vendor_to_cpe_splitversion[host_id] = cpe_vendor_to_cpe
                host_to_cpe_product_to_cpe_splitversion[host_id] = cpe_product_to_cpe
                host_to_cpe_version_to_cpe_splitversion[host_id] = cpe_version_to_cpe

                # Reverse cpe to cpe
                host_to_cpe_to_cpe_mod_splitversion[host_id] = dict()
                for cpe_mod in cpe_vendor_to_cpe:
                    for cpe in cpe_vendor_to_cpe[cpe_mod]:
                        if cpe not in host_to_cpe_to_cpe_mod_splitversion[host_id]:
                            host_to_cpe_to_cpe_mod_splitversion[host_id][cpe] = set()
                        host_to_cpe_to_cpe_mod_splitversion[host_id][cpe].add(cpe_mod)
                for cpe_mod in cpe_product_to_cpe:
                    for cpe in cpe_product_to_cpe[cpe_mod]:
                        if cpe not in host_to_cpe_to_cpe_mod_splitversion[host_id]:
                            host_to_cpe_to_cpe_mod_splitversion[host_id][cpe] = set()
                        host_to_cpe_to_cpe_mod_splitversion[host_id][cpe].add(cpe_mod)
                for cpe_mod in cpe_version_to_cpe:
                    for cpe in cpe_version_to_cpe[cpe_mod]:
                        if cpe not in host_to_cpe_to_cpe_mod_splitversion[host_id]:
                            host_to_cpe_to_cpe_mod_splitversion[host_id][cpe] = set()
                        host_to_cpe_to_cpe_mod_splitversion[host_id][cpe].add(cpe_mod)

                host_to_cpe_vendor_to_advisory_splitversion[host_id] = cpe_vendor_to_advisory
                host_to_cpe_product_to_advisory_splitversion[host_id] = cpe_product_to_advisory
                host_to_cpe_version_to_advisory_splitversion[host_id] = cpe_version_to_advisory
                
                host_to_cpe_vendor_to_advisory_max_splitversion[host_id] = 0
                host_to_cpe_product_to_advisory_max_splitversion[host_id] = 0
                host_to_cpe_version_to_advisory_max_splitversion[host_id] = 0
                
                # Assemble tree
                for cve in host_to_cve_to_cpe_splitversion[host_id]:
                    cve_tree_vendor,cve_tree_product,cve_tree_version = GraphRunner.assemble_logic_tree(host_to_cve_to_cpe_splitversion[host_id][cve])

                    cve_tree_vendor_struct = GraphRunner.sympy_to_structure(cve_tree_vendor)
                    cve_tree_product_struct = GraphRunner.sympy_to_structure(cve_tree_product)
                    cve_tree_version_struct = GraphRunner.sympy_to_structure(cve_tree_version)

                    host_to_cve_to_cpe_tree_vendor_splitversion[host_id][cve] = cve_tree_vendor_struct
                    host_to_cve_to_cpe_tree_product_splitversion[host_id][cve] = cve_tree_product_struct
                    host_to_cve_to_cpe_tree_version_splitversion[host_id][cve] = cve_tree_version_struct

            # Get max values
            for host_id in host_to_cpe_vendor_to_cpe_splitversion:

                for cpe in host_to_cpe_vendor_to_cpe_splitversion[host_id]:
                    host_to_cpe_vendor_to_advisory_max_splitversion[host_id] = max(host_to_cpe_vendor_to_advisory_max_splitversion[host_id],len(host_to_cpe_vendor_to_cpe_splitversion[host_id][cpe]))

                for cpe in host_to_cpe_product_to_cpe_splitversion[host_id]:
                    host_to_cpe_product_to_advisory_max_splitversion[host_id] = max(host_to_cpe_product_to_advisory_max_splitversion[host_id],len(host_to_cpe_product_to_cpe_splitversion[host_id][cpe]))
                
                for cpe in host_to_cpe_version_to_cpe_splitversion[host_id]:
                    host_to_cpe_version_to_advisory_max_splitversion[host_id] = max(host_to_cpe_version_to_advisory_max_splitversion[host_id],len(host_to_cpe_version_to_cpe_splitversion[host_id][cpe]))




        # Splitversion opt
        host_to_cpe_vendor_to_cpe_splitversion_opt = dict()
        host_to_cpe_product_to_cpe_splitversion_opt = dict()
        host_to_cpe_version_to_cpe_splitversion_opt = dict()

        host_to_cpe_to_cpe_mod_splitversion_opt = dict()

        host_to_cpe_vendor_to_advisory_splitversion_opt = dict()
        host_to_cpe_product_to_advisory_splitversion_opt = dict()
        host_to_cpe_version_to_advisory_splitversion_opt = dict()

        host_to_cpe_vendor_to_advisory_max_splitversion_opt = dict()
        host_to_cpe_product_to_advisory_max_splitversion_opt = dict()
        host_to_cpe_version_to_advisory_max_splitversion_opt = dict()

        host_to_cve_to_cpe_tree_vendor_splitversion_opt = dict()
        host_to_cve_to_cpe_tree_product_splitversion_opt = dict()
        host_to_cve_to_cpe_tree_version_splitversion_opt = dict()

        if SPLIT_OPTIMIZATION == True:
            for host_id in host_to_cve_to_cpe_splitversion_opt:
                host_to_cve_to_cpe_tree_vendor_splitversion_opt[host_id] = dict()
                host_to_cve_to_cpe_tree_product_splitversion_opt[host_id] = dict()
                host_to_cve_to_cpe_tree_version_splitversion_opt[host_id] = dict()

                # Grab cpe_to_advisory
                cpe_vendor_to_cpe,cpe_vendor_to_advisory,cpe_product_to_cpe,cpe_product_to_advisory,cpe_version_to_cpe,cpe_version_to_advisory = grab_cpe_to_advisory(host_to_cpe_to_advisory_splitversion_opt[host_id])

                host_to_cpe_vendor_to_cpe_splitversion_opt[host_id] = cpe_vendor_to_cpe
                host_to_cpe_product_to_cpe_splitversion_opt[host_id] = cpe_product_to_cpe
                host_to_cpe_version_to_cpe_splitversion_opt[host_id] = cpe_version_to_cpe

                # Reverse cpe to cpe
                host_to_cpe_to_cpe_mod_splitversion_opt[host_id] = dict()
                for cpe_mod in cpe_vendor_to_cpe:
                    for cpe in cpe_vendor_to_cpe[cpe_mod]:
                        if cpe not in host_to_cpe_to_cpe_mod_splitversion_opt[host_id]:
                            host_to_cpe_to_cpe_mod_splitversion_opt[host_id][cpe] = set()
                        host_to_cpe_to_cpe_mod_splitversion_opt[host_id][cpe].add(cpe_mod)
                for cpe_mod in cpe_product_to_cpe:
                    for cpe in cpe_product_to_cpe[cpe_mod]:
                        if cpe not in host_to_cpe_to_cpe_mod_splitversion_opt[host_id]:
                            host_to_cpe_to_cpe_mod_splitversion_opt[host_id][cpe] = set()
                        host_to_cpe_to_cpe_mod_splitversion_opt[host_id][cpe].add(cpe_mod)
                for cpe_mod in cpe_version_to_cpe:
                    for cpe in cpe_version_to_cpe[cpe_mod]:
                        if cpe not in host_to_cpe_to_cpe_mod_splitversion_opt[host_id]:
                            host_to_cpe_to_cpe_mod_splitversion_opt[host_id][cpe] = set()
                        host_to_cpe_to_cpe_mod_splitversion_opt[host_id][cpe].add(cpe_mod)

                host_to_cpe_vendor_to_advisory_splitversion_opt[host_id] = cpe_vendor_to_advisory
                host_to_cpe_product_to_advisory_splitversion_opt[host_id] = cpe_product_to_advisory
                host_to_cpe_version_to_advisory_splitversion_opt[host_id] = cpe_version_to_advisory
                
                host_to_cpe_vendor_to_advisory_max_splitversion_opt[host_id] = 0
                host_to_cpe_product_to_advisory_max_splitversion_opt[host_id] = 0
                host_to_cpe_version_to_advisory_max_splitversion_opt[host_id] = 0
                
                # Assemble tree
                for cve in host_to_cve_to_cpe_splitversion_opt[host_id]:
                    cve_tree_vendor,cve_tree_product,cve_tree_version = GraphRunner.assemble_logic_tree(host_to_cve_to_cpe_splitversion_opt[host_id][cve])

                    cve_tree_vendor_struct = GraphRunner.sympy_to_structure(cve_tree_vendor)
                    cve_tree_product_struct = GraphRunner.sympy_to_structure(cve_tree_product)
                    cve_tree_version_struct = GraphRunner.sympy_to_structure(cve_tree_version)

                    host_to_cve_to_cpe_tree_vendor_splitversion_opt[host_id][cve] = cve_tree_vendor_struct
                    host_to_cve_to_cpe_tree_product_splitversion_opt[host_id][cve] = cve_tree_product_struct
                    host_to_cve_to_cpe_tree_version_splitversion_opt[host_id][cve] = cve_tree_version_struct

            # Get max values
            for host_id in host_to_cpe_vendor_to_cpe_splitversion_opt:

                for cpe in host_to_cpe_vendor_to_cpe_splitversion_opt[host_id]:
                    host_to_cpe_vendor_to_advisory_max_splitversion_opt[host_id] = max(host_to_cpe_vendor_to_advisory_max_splitversion_opt[host_id],len(host_to_cpe_vendor_to_cpe_splitversion_opt[host_id][cpe]))

                for cpe in host_to_cpe_product_to_cpe_splitversion_opt[host_id]:
                    host_to_cpe_product_to_advisory_max_splitversion_opt[host_id] = max(host_to_cpe_product_to_advisory_max_splitversion_opt[host_id],len(host_to_cpe_product_to_cpe_splitversion_opt[host_id][cpe]))
                
                for cpe in host_to_cpe_version_to_cpe_splitversion_opt[host_id]:
                    host_to_cpe_version_to_advisory_max_splitversion_opt[host_id] = max(host_to_cpe_version_to_advisory_max_splitversion_opt[host_id],len(host_to_cpe_version_to_cpe_splitversion_opt[host_id][cpe]))




        ## NOTE
        # To calc the scores I need:
        # An up-to-date cve_to_cpe_dnf_tree which will be rolling
        # This is used in function compute_true_false_score
        # The result is cve_to_cpe_to_true_score_max,cve_to_cpe_to_false_score

        # cpe_to_advisory,cpe_to_advisory_max are never changing structures
        # cve_to_cpe_to_true_score_max,cve_to_cpe_to_false_score are the result of function compute_true_false_score
        # All 4 are used in function compute_weighted_true_false_score
        # The result is cve_to_cpe_to_weighted_true_score_max,cve_to_cpe_to_weighted_false_score,cve_to_cpe_to_combined_score_max

        # Lastly, cve_to_cpe_to_combined_score_max is used for function compute_mean_sum_score
        # The result is cpe_to_mean_score, cpe_to_sum_score, cpe_to_cross_cve_score
        # Where cpe_to_sum_score is our prioritization score

        # To sum up:
        # cve_to_cpe_dnf_tree is updated externally
        # cpe_to_advisory,cpe_to_advisory_max never change
        # cve_to_cpe_to_true_score_max,cve_to_cpe_to_false_score ;
        # cve_to_cpe_to_weighted_true_score_max,cve_to_cpe_to_weighted_false_score,cve_to_cpe_to_combined_score_max ; 
        # cpe_to_mean_score,cpe_to_sum_score,cpe_to_cross_cve_score
        # Are calculated by the chain of functions
        ## END NOTE




        ## FIRST SCORE CALC
        print("## FIRST SCORE CALC")

        # No version
        host_to_cpe_vendor_to_score_noversion = dict()
        host_to_cpe_product_to_score_noversion = dict()
        #host_to_cpe_version_to_score_noversion = dict()
        if NO_VERSION == True:
            for host_id in host_to_cve_to_cpe_tree_vendor_noversion:
                host_to_cpe_vendor_to_score_noversion[host_id] = ScoringEngine.recalc_scores(host_to_cve_to_cpe_tree_vendor_noversion[host_id],host_to_cpe_vendor_to_advisory_noversion[host_id],host_to_cpe_vendor_to_advisory_max_noversion[host_id])
                host_to_cpe_product_to_score_noversion[host_id] = ScoringEngine.recalc_scores(host_to_cve_to_cpe_tree_product_noversion[host_id],host_to_cpe_product_to_advisory_noversion[host_id],host_to_cpe_product_to_advisory_max_noversion[host_id])
                #host_to_cpe_version_to_score_noversion[host_id] = ScoringEngine.recalc_scores(host_to_cve_to_cpe_tree_version_noversion[host_id],host_to_cpe_version_to_advisory_noversion[host_id],host_to_cpe_version_to_advisory_max_noversion[host_id])



        # Version
        host_to_cpe_vendor_to_score_version = dict()
        host_to_cpe_product_to_score_version = dict()
        host_to_cpe_version_to_score_version = dict()
        if VERSION == True:
            for host_id in host_to_cve_to_cpe_tree_vendor_version:
                host_to_cpe_vendor_to_score_version[host_id] = ScoringEngine.recalc_scores(host_to_cve_to_cpe_tree_vendor_version[host_id],host_to_cpe_vendor_to_advisory_version[host_id],host_to_cpe_vendor_to_advisory_max_version[host_id])
                host_to_cpe_product_to_score_version[host_id] = ScoringEngine.recalc_scores(host_to_cve_to_cpe_tree_product_version[host_id],host_to_cpe_product_to_advisory_version[host_id],host_to_cpe_product_to_advisory_max_version[host_id])
                host_to_cpe_version_to_score_version[host_id] = ScoringEngine.recalc_scores(host_to_cve_to_cpe_tree_version_version[host_id],host_to_cpe_version_to_advisory_version[host_id],host_to_cpe_version_to_advisory_max_version[host_id])



        # Version
        host_to_cpe_vendor_to_score_extended_version = dict()
        host_to_cpe_product_to_score_extended_version = dict()
        host_to_cpe_version_to_score_extended_version = dict()
        if VERSION_EXTENDED == True:
            for host_id in host_to_cve_to_cpe_tree_vendor_extended_version:
                host_to_cpe_vendor_to_score_extended_version[host_id] = ScoringEngine.recalc_scores(host_to_cve_to_cpe_tree_vendor_extended_version[host_id],host_to_cpe_vendor_to_advisory_extended_version[host_id],host_to_cpe_vendor_to_advisory_max_extended_version[host_id])
                host_to_cpe_product_to_score_extended_version[host_id] = ScoringEngine.recalc_scores(host_to_cve_to_cpe_tree_product_extended_version[host_id],host_to_cpe_product_to_advisory_extended_version[host_id],host_to_cpe_product_to_advisory_max_extended_version[host_id])
                host_to_cpe_version_to_score_extended_version[host_id] = ScoringEngine.recalc_scores(host_to_cve_to_cpe_tree_version_extended_version[host_id],host_to_cpe_version_to_advisory_extended_version[host_id],host_to_cpe_version_to_advisory_max_extended_version[host_id])



        # Split version
        host_to_cpe_vendor_to_score_splitversion = dict()
        host_to_cpe_product_to_score_splitversion = dict()
        host_to_cpe_version_to_score_splitversion = dict()
        if SPLIT_VERSION == True:
            for host_id in host_to_cve_to_cpe_tree_vendor_splitversion:
                host_to_cpe_vendor_to_score_splitversion[host_id] = ScoringEngine.recalc_scores(host_to_cve_to_cpe_tree_vendor_splitversion[host_id],host_to_cpe_vendor_to_advisory_splitversion[host_id],host_to_cpe_vendor_to_advisory_max_splitversion[host_id])
                host_to_cpe_product_to_score_splitversion[host_id] = ScoringEngine.recalc_scores(host_to_cve_to_cpe_tree_product_splitversion[host_id],host_to_cpe_product_to_advisory_splitversion[host_id],host_to_cpe_product_to_advisory_max_splitversion[host_id])
                host_to_cpe_version_to_score_splitversion[host_id] = ScoringEngine.recalc_scores(host_to_cve_to_cpe_tree_version_splitversion[host_id],host_to_cpe_version_to_advisory_splitversion[host_id],host_to_cpe_version_to_advisory_max_splitversion[host_id])



        # Split version optimization
        host_to_cpe_vendor_to_score_splitversion_opt = dict()
        host_to_cpe_product_to_score_splitversion_opt = dict()
        host_to_cpe_version_to_score_splitversion_opt = dict()
        if SPLIT_OPTIMIZATION == True:
            for host_id in host_to_cve_to_cpe_tree_vendor_splitversion_opt:
                host_to_cpe_vendor_to_score_splitversion_opt[host_id] = ScoringEngine.recalc_scores(host_to_cve_to_cpe_tree_vendor_splitversion_opt[host_id],host_to_cpe_vendor_to_advisory_splitversion_opt[host_id],host_to_cpe_vendor_to_advisory_max_splitversion_opt[host_id])
                host_to_cpe_product_to_score_splitversion_opt[host_id] = ScoringEngine.recalc_scores(host_to_cve_to_cpe_tree_product_splitversion_opt[host_id],host_to_cpe_product_to_advisory_splitversion_opt[host_id],host_to_cpe_product_to_advisory_max_splitversion_opt[host_id])
                host_to_cpe_version_to_score_splitversion_opt[host_id] = ScoringEngine.recalc_scores(host_to_cve_to_cpe_tree_version_splitversion_opt[host_id],host_to_cpe_version_to_advisory_splitversion_opt[host_id],host_to_cpe_version_to_advisory_max_splitversion_opt[host_id])




        ## BUILD NETWORKX GRAPH
        print("## BUILD NX GRAPH")

        # No version
        host_to_graph_noversion = dict()
        if NO_VERSION == True:
            local_host_to_max_weight = dict()
            for host_id in host_to_cpe_vendor_to_score_noversion:
                host_to_graph_noversion[host_id] = nx.DiGraph()

                # Add host as root
                host_to_graph_noversion[host_id].add_node(host_id,name=host_id,node_type="host",node_subtype="",score=0)

                # Add sink
                host_to_graph_noversion[host_id].add_node(host_id+"_sink",name=host_id,node_type="sink",node_subtype="",score=0)

                # Record max weight
                local_host_to_max_weight[host_id] = 0

                # Add cpe as nodes
                for cpe_vendor in host_to_cpe_vendor_to_score_noversion[host_id]:
                    host_to_graph_noversion[host_id].add_node(cpe_vendor,name=cpe_vendor,node_type="cpe",node_subtype="vendor",score=host_to_cpe_vendor_to_score_noversion[host_id][cpe_vendor])
                    local_host_to_max_weight[host_id] = max(local_host_to_max_weight[host_id],host_to_cpe_vendor_to_score_noversion[host_id][cpe_vendor])
                for cpe_product in host_to_cpe_product_to_score_noversion[host_id]:
                    host_to_graph_noversion[host_id].add_node(cpe_product,name=cpe_product,node_type="cpe",node_subtype="product",score=host_to_cpe_product_to_score_noversion[host_id][cpe_product])
                    local_host_to_max_weight[host_id] = max(local_host_to_max_weight[host_id],host_to_cpe_product_to_score_noversion[host_id][cpe_product])
                #for cpe_version in host_to_cpe_version_to_score_noversion[host_id]:
                #    host_to_graph_noversion[host_id].add_node(cpe_version,name=cpe_version,node_type="cpe",node_subtype="version",score=host_to_cpe_version_to_score_noversion[host_id][cpe_version])
                #    local_host_to_max_weight[host_id] = max(local_host_to_max_weight[host_id],host_to_cpe_version_to_score_noversion[host_id][cpe_version])
                    
            # Add edges between nodes
            for host_id in host_to_cpe_to_cpe_mod_noversion:
                for orig_cpe in host_to_cpe_to_cpe_mod_noversion[host_id]:
                    for new_cpe_1 in host_to_cpe_to_cpe_mod_noversion[host_id][orig_cpe]:
                        node_1 = host_to_graph_noversion[host_id].nodes[new_cpe_1]

                        # host to vendor
                        if node_1["node_subtype"] == "vendor":
                            host_to_graph_noversion[host_id].add_edge(host_id,new_cpe_1,weight=node_1["score"],positive_weight=local_host_to_max_weight[host_id]-node_1["score"])
                        
                        # version or product to sink
                        if node_1["node_subtype"] == "product":
                            host_to_graph_noversion[host_id].add_edge(new_cpe_1,host_id+"_sink",weight=0,positive_weight=0)

                        for new_cpe_2 in host_to_cpe_to_cpe_mod_noversion[host_id][orig_cpe]:
                            node_2 = host_to_graph_noversion[host_id].nodes[new_cpe_2]

                            # Build cpe cpe edges
                            if (node_1["node_subtype"] == "vendor") and (node_2["node_subtype"] == "product"):
                                # vendor to product
                                host_to_graph_noversion[host_id].add_edge(new_cpe_1,new_cpe_2,weight=node_2["score"],positive_weight=local_host_to_max_weight[host_id]-node_2["score"])
                            elif (node_1["node_subtype"] == "product") and (node_2["node_subtype"] == "version"):
                                # product to version
                                host_to_graph_noversion[host_id].add_edge(new_cpe_1,new_cpe_2,weight=node_2["score"],positive_weight=local_host_to_max_weight[host_id]-node_2["score"])



        # Version
        host_to_graph_version = dict()
        if VERSION == True:
            local_host_to_max_weight = dict()
            for host_id in host_to_cpe_vendor_to_score_version:
                host_to_graph_version[host_id] = nx.DiGraph()

                # Add host as root
                host_to_graph_version[host_id].add_node(host_id,name=host_id,node_type="host",node_subtype="",score=0)

                # Add sink
                host_to_graph_version[host_id].add_node(host_id+"_sink",name=host_id,node_type="sink",node_subtype="",score=0)

                # Record max weight
                local_host_to_max_weight[host_id] = 0

                # Add cpe as nodes
                for cpe_vendor in host_to_cpe_vendor_to_score_version[host_id]:
                    host_to_graph_version[host_id].add_node(cpe_vendor,name=cpe_vendor,node_type="cpe",node_subtype="vendor",score=host_to_cpe_vendor_to_score_version[host_id][cpe_vendor])
                    local_host_to_max_weight[host_id] = max(local_host_to_max_weight[host_id],host_to_cpe_vendor_to_score_version[host_id][cpe_vendor])
                for cpe_product in host_to_cpe_product_to_score_version[host_id]:
                    host_to_graph_version[host_id].add_node(cpe_product,name=cpe_product,node_type="cpe",node_subtype="product",score=host_to_cpe_product_to_score_version[host_id][cpe_product])
                    local_host_to_max_weight[host_id] = max(local_host_to_max_weight[host_id],host_to_cpe_product_to_score_version[host_id][cpe_product])
                for cpe_version in host_to_cpe_version_to_score_version[host_id]:
                    host_to_graph_version[host_id].add_node(cpe_version,name=cpe_version,node_type="cpe",node_subtype="version",score=host_to_cpe_version_to_score_version[host_id][cpe_version])
                    local_host_to_max_weight[host_id] = max(local_host_to_max_weight[host_id],host_to_cpe_version_to_score_version[host_id][cpe_version])
                    
            # Add edges between nodes
            for host_id in host_to_cpe_to_cpe_mod_version:
                for orig_cpe in host_to_cpe_to_cpe_mod_version[host_id]:
                    for new_cpe_1 in host_to_cpe_to_cpe_mod_version[host_id][orig_cpe]:
                        node_1 = host_to_graph_version[host_id].nodes[new_cpe_1]

                        # host to vendor
                        if node_1["node_subtype"] == "vendor":
                            host_to_graph_version[host_id].add_edge(host_id,new_cpe_1,weight=node_1["score"],positive_weight=local_host_to_max_weight[host_id]-node_1["score"])

                        # version or product to sink
                        if node_1["node_subtype"] == "version":
                            host_to_graph_version[host_id].add_edge(new_cpe_1,host_id+"_sink",weight=0,positive_weight=0)

                        for new_cpe_2 in host_to_cpe_to_cpe_mod_version[host_id][orig_cpe]:
                            node_2 = host_to_graph_version[host_id].nodes[new_cpe_2]

                            # Build cpe cpe edges
                            if (node_1["node_subtype"] == "vendor") and (node_2["node_subtype"] == "product"):
                                # vendor to product
                                host_to_graph_version[host_id].add_edge(new_cpe_1,new_cpe_2,weight=node_2["score"],positive_weight=local_host_to_max_weight[host_id]-node_2["score"])
                            elif (node_1["node_subtype"] == "product") and (node_2["node_subtype"] == "version"):
                                # product to version
                                host_to_graph_version[host_id].add_edge(new_cpe_1,new_cpe_2,weight=node_2["score"],positive_weight=local_host_to_max_weight[host_id]-node_2["score"])



        # Version
        host_to_graph_extended_version = dict()
        if VERSION_EXTENDED == True:
            local_host_to_max_weight = dict()
            for host_id in host_to_cpe_vendor_to_score_extended_version:
                host_to_graph_extended_version[host_id] = nx.DiGraph()

                # Add host as root
                host_to_graph_extended_version[host_id].add_node(host_id,name=host_id,node_type="host",node_subtype="",score=0)

                # Add sink
                host_to_graph_extended_version[host_id].add_node(host_id+"_sink",name=host_id,node_type="sink",node_subtype="",score=0)

                # Record max weight
                local_host_to_max_weight[host_id] = 0

                # Add cpe as nodes
                for cpe_vendor in host_to_cpe_vendor_to_score_extended_version[host_id]:
                    host_to_graph_extended_version[host_id].add_node(cpe_vendor,name=cpe_vendor,node_type="cpe",node_subtype="vendor",score=host_to_cpe_vendor_to_score_extended_version[host_id][cpe_vendor])
                    local_host_to_max_weight[host_id] = max(local_host_to_max_weight[host_id],host_to_cpe_vendor_to_score_extended_version[host_id][cpe_vendor])
                for cpe_product in host_to_cpe_product_to_score_extended_version[host_id]:
                    host_to_graph_extended_version[host_id].add_node(cpe_product,name=cpe_product,node_type="cpe",node_subtype="product",score=host_to_cpe_product_to_score_extended_version[host_id][cpe_product])
                    local_host_to_max_weight[host_id] = max(local_host_to_max_weight[host_id],host_to_cpe_product_to_score_extended_version[host_id][cpe_product])
                for cpe_version in host_to_cpe_version_to_score_extended_version[host_id]:
                    host_to_graph_extended_version[host_id].add_node(cpe_version,name=cpe_version,node_type="cpe",node_subtype="version",score=host_to_cpe_version_to_score_extended_version[host_id][cpe_version])
                    local_host_to_max_weight[host_id] = max(local_host_to_max_weight[host_id],host_to_cpe_version_to_score_extended_version[host_id][cpe_version])
                    
            # Add edges between nodes
            for host_id in host_to_cpe_to_cpe_mod_extended_version:
                for orig_cpe in host_to_cpe_to_cpe_mod_extended_version[host_id]:
                    for new_cpe_1 in host_to_cpe_to_cpe_mod_extended_version[host_id][orig_cpe]:
                        node_1 = host_to_graph_extended_version[host_id].nodes[new_cpe_1]

                        # host to vendor
                        if node_1["node_subtype"] == "vendor":
                            host_to_graph_extended_version[host_id].add_edge(host_id,new_cpe_1,weight=node_1["score"],positive_weight=local_host_to_max_weight[host_id]-node_1["score"])

                        # version or product to sink
                        if node_1["node_subtype"] == "version":
                            host_to_graph_extended_version[host_id].add_edge(new_cpe_1,host_id+"_sink",weight=0,positive_weight=0)

                        for new_cpe_2 in host_to_cpe_to_cpe_mod_extended_version[host_id][orig_cpe]:
                            node_2 = host_to_graph_extended_version[host_id].nodes[new_cpe_2]

                            # Build cpe cpe edges
                            if (node_1["node_subtype"] == "vendor") and (node_2["node_subtype"] == "product"):
                                # vendor to product
                                host_to_graph_extended_version[host_id].add_edge(new_cpe_1,new_cpe_2,weight=node_2["score"],positive_weight=local_host_to_max_weight[host_id]-node_2["score"])
                            elif (node_1["node_subtype"] == "product") and (node_2["node_subtype"] == "version"):
                                # product to version
                                host_to_graph_extended_version[host_id].add_edge(new_cpe_1,new_cpe_2,weight=node_2["score"],positive_weight=local_host_to_max_weight[host_id]-node_2["score"])



        # Split version
        host_to_graph_splitversion = dict()
        if SPLIT_VERSION == True:
            local_host_to_max_weight = dict()
            for host_id in host_to_cpe_vendor_to_score_splitversion:
                host_to_graph_splitversion[host_id] = nx.DiGraph()

                # Add host as root
                host_to_graph_splitversion[host_id].add_node(host_id,name=host_id,node_type="host",node_subtype="",score=0)

                # Add sink
                host_to_graph_splitversion[host_id].add_node(host_id+"_sink",name=host_id,node_type="sink",node_subtype="",score=0)

                # Record max weight
                local_host_to_max_weight[host_id] = 0

                # Add cpe as nodes
                for cpe_vendor in host_to_cpe_vendor_to_score_splitversion[host_id]:
                    host_to_graph_splitversion[host_id].add_node(cpe_vendor,name=cpe_vendor,node_type="cpe",node_subtype="vendor",score=host_to_cpe_vendor_to_score_splitversion[host_id][cpe_vendor])
                    local_host_to_max_weight[host_id] = max(local_host_to_max_weight[host_id],host_to_cpe_vendor_to_score_splitversion[host_id][cpe_vendor])
                for cpe_product in host_to_cpe_product_to_score_splitversion[host_id]:
                    host_to_graph_splitversion[host_id].add_node(cpe_product,name=cpe_product,node_type="cpe",node_subtype="product",score=host_to_cpe_product_to_score_splitversion[host_id][cpe_product])
                    local_host_to_max_weight[host_id] = max(local_host_to_max_weight[host_id],host_to_cpe_product_to_score_splitversion[host_id][cpe_product])
                for cpe_version in host_to_cpe_version_to_score_splitversion[host_id]:
                    host_to_graph_splitversion[host_id].add_node(cpe_version,name=cpe_version,node_type="cpe",node_subtype="version",score=host_to_cpe_version_to_score_splitversion[host_id][cpe_version])
                    local_host_to_max_weight[host_id] = max(local_host_to_max_weight[host_id],host_to_cpe_version_to_score_splitversion[host_id][cpe_version])
                    
            # Add edges between nodes
            for host_id in host_to_cpe_to_cpe_mod_splitversion:
                for orig_cpe in host_to_cpe_to_cpe_mod_splitversion[host_id]:
                    for new_cpe_1 in host_to_cpe_to_cpe_mod_splitversion[host_id][orig_cpe]:
                        node_1 = host_to_graph_splitversion[host_id].nodes[new_cpe_1]

                        # host to vendor
                        if node_1["node_subtype"] == "vendor":
                            host_to_graph_splitversion[host_id].add_edge(host_id,new_cpe_1,weight=node_1["score"],positive_weight=local_host_to_max_weight[host_id]-node_1["score"])
                        
                        # version or product to sink
                        if node_1["node_subtype"] == "version":
                            host_to_graph_splitversion[host_id].add_edge(new_cpe_1,host_id+"_sink",weight=0,positive_weight=0)

                        for new_cpe_2 in host_to_cpe_to_cpe_mod_splitversion[host_id][orig_cpe]:
                            node_2 = host_to_graph_splitversion[host_id].nodes[new_cpe_2]

                            # Build cpe cpe edges
                            if (node_1["node_subtype"] == "vendor") and (node_2["node_subtype"] == "product"):
                                # vendor to product
                                host_to_graph_splitversion[host_id].add_edge(new_cpe_1,new_cpe_2,weight=node_2["score"],positive_weight=local_host_to_max_weight[host_id]-node_2["score"])
                            elif (node_1["node_subtype"] == "product") and (node_2["node_subtype"] == "version"):
                                # product to version
                                host_to_graph_splitversion[host_id].add_edge(new_cpe_1,new_cpe_2,weight=node_2["score"],positive_weight=local_host_to_max_weight[host_id]-node_2["score"])



        # Split version optimization
        host_to_graph_splitversion_opt = dict()
        if SPLIT_OPTIMIZATION == True:
            local_host_to_max_weight = dict()
            for host_id in host_to_cpe_vendor_to_score_splitversion_opt:
                host_to_graph_splitversion_opt[host_id] = nx.DiGraph()

                # Add host as root
                host_to_graph_splitversion_opt[host_id].add_node(host_id,name=host_id,node_type="host",node_subtype="",score=0)

                # Add sink
                host_to_graph_splitversion_opt[host_id].add_node(host_id+"_sink",name=host_id,node_type="sink",node_subtype="",score=0)

                # Record max weight
                local_host_to_max_weight[host_id] = 0

                # Add cpe as nodes
                for cpe_vendor in host_to_cpe_vendor_to_score_splitversion_opt[host_id]:
                    host_to_graph_splitversion_opt[host_id].add_node(cpe_vendor,name=cpe_vendor,node_type="cpe",node_subtype="vendor",score=host_to_cpe_vendor_to_score_splitversion_opt[host_id][cpe_vendor])
                    local_host_to_max_weight[host_id] = max(local_host_to_max_weight[host_id],host_to_cpe_vendor_to_score_splitversion_opt[host_id][cpe_vendor])
                for cpe_product in host_to_cpe_product_to_score_splitversion_opt[host_id]:
                    host_to_graph_splitversion_opt[host_id].add_node(cpe_product,name=cpe_product,node_type="cpe",node_subtype="product",score=host_to_cpe_product_to_score_splitversion_opt[host_id][cpe_product])
                    local_host_to_max_weight[host_id] = max(local_host_to_max_weight[host_id],host_to_cpe_product_to_score_splitversion_opt[host_id][cpe_product])
                for cpe_version in host_to_cpe_version_to_score_splitversion_opt[host_id]:
                    host_to_graph_splitversion_opt[host_id].add_node(cpe_version,name=cpe_version,node_type="cpe",node_subtype="version",score=host_to_cpe_version_to_score_splitversion_opt[host_id][cpe_version])
                    local_host_to_max_weight[host_id] = max(local_host_to_max_weight[host_id],host_to_cpe_version_to_score_splitversion_opt[host_id][cpe_version])
                    
            # Add edges between nodes
            for host_id in host_to_cpe_to_cpe_mod_splitversion_opt:
                for orig_cpe in host_to_cpe_to_cpe_mod_splitversion_opt[host_id]:
                    for new_cpe_1 in host_to_cpe_to_cpe_mod_splitversion_opt[host_id][orig_cpe]:
                        node_1 = host_to_graph_splitversion_opt[host_id].nodes[new_cpe_1]

                        # host to vendor
                        if node_1["node_subtype"] == "vendor":
                            host_to_graph_splitversion_opt[host_id].add_edge(host_id,new_cpe_1,weight=node_1["score"],positive_weight=local_host_to_max_weight[host_id]-node_1["score"])
                        
                        # version or product to sink
                        if node_1["node_subtype"] == "version":
                            host_to_graph_splitversion_opt[host_id].add_edge(new_cpe_1,host_id+"_sink",weight=0,positive_weight=0)

                        for new_cpe_2 in host_to_cpe_to_cpe_mod_splitversion_opt[host_id][orig_cpe]:
                            node_2 = host_to_graph_splitversion_opt[host_id].nodes[new_cpe_2]

                            # Build cpe cpe edges
                            if (node_1["node_subtype"] == "vendor") and (node_2["node_subtype"] == "product"):
                                # vendor to product
                                host_to_graph_splitversion_opt[host_id].add_edge(new_cpe_1,new_cpe_2,weight=node_2["score"],positive_weight=local_host_to_max_weight[host_id]-node_2["score"])
                            elif (node_1["node_subtype"] == "product") and (node_2["node_subtype"] == "version"):
                                # product to version
                                host_to_graph_splitversion_opt[host_id].add_edge(new_cpe_1,new_cpe_2,weight=node_2["score"],positive_weight=local_host_to_max_weight[host_id]-node_2["score"])




        ## NOTE
        # I now have scores, rolling trees and directed graphs in networkx
        # This is sufficient for the initialization
        # At this point in time, the dynamic part of the algorithm must start

        # Dynamic part:
        # 1 - Run any path algorithm between source and sink (source == host, sink == singleton called "sink")
        # 2 - Either let the algo finish and return a path or look into each algo step
        # 3 - Resolve each element of the path or resolve the current algo step
        # 4 - Recalculate rolling tree
        # 5 - Remove nodes from graph if necessary
        # 6 - Recalculate scores and apply to the graph

        ## END NOTE




        ## DYNAMIC VALIDATION
        print("## DYNAMIC VALIDATION")

        ## RUNNER BEGIN ##
        """
        if CALC_SCORES_ONCE == True:

            ## SEQUENTIAL LEGACY RUNNER ##
            if NO_VERSION == True:
                SequentialGraphRunner.do_run(SNAPSHOT_ID,host_to_graph_noversion,host_to_cve_to_cpe_noversion,host_to_validation_inventory_inert_noversion,host_to_cpe_to_cpe_mod_noversion,
                                            host_to_cpe_vendor_to_cpe_noversion,host_to_cpe_product_to_cpe_noversion,dict(),
                                            host_to_cve_to_cpe_tree_vendor_noversion,host_to_cve_to_cpe_tree_product_noversion,dict())

            if VERSION == True:
                SequentialGraphRunner.do_run(SNAPSHOT_ID,host_to_graph_version,host_to_cve_to_cpe_version,host_to_validation_inventory_inert_version,host_to_cpe_to_cpe_mod_version,
                                            host_to_cpe_vendor_to_cpe_version,host_to_cpe_product_to_cpe_version,host_to_cpe_version_to_cpe_version,
                                            host_to_cve_to_cpe_tree_vendor_version,host_to_cve_to_cpe_tree_product_version,host_to_cve_to_cpe_tree_version_version)

            if VERSION_EXTENDED == True:
                SequentialGraphRunner.do_run(SNAPSHOT_ID,host_to_graph_extended_version,host_to_cve_to_cpe_extended_version,host_to_validation_inventory_inert_extended_version,host_to_cpe_to_cpe_mod_extended_version,
                                            host_to_cpe_vendor_to_cpe_extended_version,host_to_cpe_product_to_cpe_extended_version,host_to_cpe_version_to_cpe_extended_version,
                                            host_to_cve_to_cpe_tree_vendor_extended_version,host_to_cve_to_cpe_tree_product_extended_version,host_to_cve_to_cpe_tree_version_extended_version)

            if SPLIT_VERSION == True:
                SequentialGraphRunner.do_run(SNAPSHOT_ID,host_to_graph_splitversion,host_to_cve_to_cpe_splitversion,host_to_validation_inventory_inert_splitversion,host_to_cpe_to_cpe_mod_splitversion,
                                            host_to_cpe_vendor_to_cpe_splitversion,host_to_cpe_product_to_cpe_splitversion,host_to_cpe_version_to_cpe_splitversion,
                                            host_to_cve_to_cpe_tree_vendor_splitversion,host_to_cve_to_cpe_tree_product_splitversion,host_to_cve_to_cpe_tree_version_splitversion)

            if SPLIT_OPTIMIZATION == True:
                SequentialGraphRunner.do_run(SNAPSHOT_ID,host_to_graph_splitversion_opt,host_to_cve_to_cpe_splitversion_opt,host_to_validation_inventory_inert_splitversion_opt,host_to_cpe_to_cpe_mod_splitversion_opt,
                                            host_to_cpe_vendor_to_cpe_splitversion_opt,host_to_cpe_product_to_cpe_splitversion_opt,host_to_cpe_version_to_cpe_splitversion_opt,
                                            host_to_cve_to_cpe_tree_vendor_splitversion_opt,host_to_cve_to_cpe_tree_product_splitversion_opt,host_to_cve_to_cpe_tree_version_splitversion_opt)
        """
        #else:
        ## DYNAMIC NEW RUNNER ##
        random.seed(RANDOM_SEED)

        print("S-"+str(RANDOM_SEED))

        COMMON_PREFIX = "S"+str(RANDOM_SEED)

        scoring_function = ScoringEngine.random_score # default 1, RN
        if VALIDATION_MODE == 2: # SR
            COMMON_PREFIX = COMMON_PREFIX + "_M2_"
            scoring_function = ScoringEngine.smart_random_score
        elif VALIDATION_MODE == 3: # PP
            COMMON_PREFIX = COMMON_PREFIX + "_M3_"
            scoring_function = ScoringEngine.heuristic_score
        elif VALIDATION_MODE == 4: # VS
            COMMON_PREFIX = COMMON_PREFIX + "_M4_"
            cve_set = set()
            for host_id in host_to_cve_to_cpe_noversion:
                cve_set = cve_set.union(set(host_to_cve_to_cpe_noversion[host_id].keys()))
            scoring_function = ScoringEngine.vulnerability_score_primer(cve_set)
        elif VALIDATION_MODE == 5: # VP
            COMMON_PREFIX = COMMON_PREFIX + "_M5_"
            cve_set = set()
            for host_id in host_to_cve_to_cpe_noversion:
                cve_set = cve_set.union(set(host_to_cve_to_cpe_noversion[host_id].keys()))
            scoring_function = ScoringEngine.vulnerability_heuristic_score_primer(cve_set)
        else:
            COMMON_PREFIX=COMMON_PREFIX+"_M1_"




        if NO_VERSION == True:
            print("noversion")
            for host_id in host_to_graph_noversion:
                DynamicGraphRunner.do_run(SNAPSHOT_ID,host_id,LOG_DIR,COMMON_PREFIX+"noversion",OUTPUT_DIR,scoring_function,
                                        host_to_graph_noversion[host_id],host_to_cve_to_cpe_noversion[host_id],host_to_validation_inventory_inert_noversion[host_id],host_to_cpe_to_cpe_mod_noversion[host_id],
                                        host_to_cpe_vendor_to_cpe_noversion[host_id],host_to_cpe_product_to_cpe_noversion[host_id],dict(),
                                        host_to_cve_to_cpe_tree_vendor_noversion[host_id],host_to_cve_to_cpe_tree_product_noversion[host_id],dict(),
                                        host_to_cpe_vendor_to_advisory_noversion[host_id],host_to_cpe_product_to_advisory_noversion[host_id],dict(),
                                        host_to_cpe_vendor_to_advisory_max_noversion[host_id],host_to_cpe_product_to_advisory_max_noversion[host_id],dict())

        if VERSION == True:
            print("version")
            for host_id in host_to_graph_version:
                DynamicGraphRunner.do_run(SNAPSHOT_ID,host_id,LOG_DIR,COMMON_PREFIX+"version",OUTPUT_DIR,scoring_function,
                                        host_to_graph_version[host_id],host_to_cve_to_cpe_version[host_id],host_to_validation_inventory_inert_version[host_id],host_to_cpe_to_cpe_mod_version[host_id],
                                        host_to_cpe_vendor_to_cpe_version[host_id],host_to_cpe_product_to_cpe_version[host_id],host_to_cpe_version_to_cpe_version[host_id],
                                        host_to_cve_to_cpe_tree_vendor_version[host_id],host_to_cve_to_cpe_tree_product_version[host_id],host_to_cve_to_cpe_tree_version_version[host_id],
                                        host_to_cpe_vendor_to_advisory_version[host_id],host_to_cpe_product_to_advisory_version[host_id],host_to_cpe_version_to_advisory_version[host_id],
                                        host_to_cpe_vendor_to_advisory_max_version[host_id],host_to_cpe_product_to_advisory_max_version[host_id],host_to_cpe_version_to_advisory_max_version[host_id])

        if VERSION_EXTENDED == True:
            print("version_extended")
            for host_id in host_to_graph_extended_version:
                DynamicGraphRunner.do_run(SNAPSHOT_ID,host_id,LOG_DIR,COMMON_PREFIX+"extended_version",OUTPUT_DIR,scoring_function,
                                        host_to_graph_extended_version[host_id],host_to_cve_to_cpe_extended_version[host_id],host_to_validation_inventory_inert_extended_version[host_id],host_to_cpe_to_cpe_mod_extended_version[host_id],
                                        host_to_cpe_vendor_to_cpe_extended_version[host_id],host_to_cpe_product_to_cpe_extended_version[host_id],host_to_cpe_version_to_cpe_extended_version[host_id],
                                        host_to_cve_to_cpe_tree_vendor_extended_version[host_id],host_to_cve_to_cpe_tree_product_extended_version[host_id],host_to_cve_to_cpe_tree_version_extended_version[host_id],
                                        host_to_cpe_vendor_to_advisory_extended_version[host_id],host_to_cpe_product_to_advisory_extended_version[host_id],host_to_cpe_version_to_advisory_extended_version[host_id],
                                        host_to_cpe_vendor_to_advisory_max_extended_version[host_id],host_to_cpe_product_to_advisory_max_extended_version[host_id],host_to_cpe_version_to_advisory_max_extended_version[host_id])

        if SPLIT_VERSION == True:
            print("split version")
            for host_id in host_to_graph_splitversion:
                DynamicGraphRunner.do_run(SNAPSHOT_ID,host_id,LOG_DIR,COMMON_PREFIX+"splitversion",OUTPUT_DIR,scoring_function,
                                        host_to_graph_splitversion[host_id],host_to_cve_to_cpe_splitversion[host_id],host_to_validation_inventory_inert_splitversion[host_id],host_to_cpe_to_cpe_mod_splitversion[host_id],
                                        host_to_cpe_vendor_to_cpe_splitversion[host_id],host_to_cpe_product_to_cpe_splitversion[host_id],host_to_cpe_version_to_cpe_splitversion[host_id],
                                        host_to_cve_to_cpe_tree_vendor_splitversion[host_id],host_to_cve_to_cpe_tree_product_splitversion[host_id],host_to_cve_to_cpe_tree_version_splitversion[host_id],
                                        host_to_cpe_vendor_to_advisory_splitversion[host_id],host_to_cpe_product_to_advisory_splitversion[host_id],host_to_cpe_version_to_advisory_splitversion[host_id],
                                        host_to_cpe_vendor_to_advisory_max_splitversion[host_id],host_to_cpe_product_to_advisory_max_splitversion[host_id],host_to_cpe_version_to_advisory_max_splitversion[host_id])

        if SPLIT_OPTIMIZATION == True:
            print("split version optimization")
            for host_id in host_to_graph_splitversion_opt:
                DynamicGraphRunner.do_run(SNAPSHOT_ID,host_id,LOG_DIR,COMMON_PREFIX+"splitversion_opt",OUTPUT_DIR,scoring_function,
                                        host_to_graph_splitversion_opt[host_id],host_to_cve_to_cpe_splitversion_opt[host_id],host_to_validation_inventory_inert_splitversion_opt[host_id],host_to_cpe_to_cpe_mod_splitversion_opt[host_id],
                                        host_to_cpe_vendor_to_cpe_splitversion_opt[host_id],host_to_cpe_product_to_cpe_splitversion_opt[host_id],host_to_cpe_version_to_cpe_splitversion_opt[host_id],
                                        host_to_cve_to_cpe_tree_vendor_splitversion_opt[host_id],host_to_cve_to_cpe_tree_product_splitversion_opt[host_id],host_to_cve_to_cpe_tree_version_splitversion_opt[host_id],
                                        host_to_cpe_vendor_to_advisory_splitversion_opt[host_id],host_to_cpe_product_to_advisory_splitversion_opt[host_id],host_to_cpe_version_to_advisory_splitversion_opt[host_id],
                                        host_to_cpe_vendor_to_advisory_max_splitversion_opt[host_id],host_to_cpe_product_to_advisory_max_splitversion_opt[host_id],host_to_cpe_version_to_advisory_max_splitversion_opt[host_id])
