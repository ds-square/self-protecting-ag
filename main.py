import os
import json
import time
import requests

from filtering.engine.graph_engine import GraphFilter
from aggregation.aggregator import Aggregator


# DRIVERS
SNAPSHOT_ID = "cyberrange_merged"

AGGREGATION_LEVEL = 1
# 0 - Don't do anything
# 1 - Max precision
# 2 - Same likelihood
# 3 - Max compression


## FILTERING
print("FILTERING")
GraphFilter.run(False,True,False,False,False,3,101,SNAPSHOT_ID,"")

host_to_filtered_inventory = dict()
for filename in os.listdir("dataset/filtered_inventories/"):
    if "_filtered_inventory_" in filename:
        f=open(file="dataset/filtered_inventories/"+filename,mode="r",encoding="utf-8")
        filecontent = json.loads(f.read())
        f.close()

        host_to_filtered_inventory[filecontent["host_id"]] = filecontent


## AGGREGATION
print("AGGREGATION")
host_to_aggregated_inventory = dict()
for host_id in host_to_filtered_inventory:
    print("Aggregating "+host_id)
    cve_nvd_list = list()
    for cve_id in host_to_filtered_inventory[host_id]["confirmed_cve"]:
        time.sleep(7) ## NVD FORCES A MAX OF 5 REQUESTS OVER 30 SECONDS... SORRY!
        try:
            print("Fetching ["+cve_id+"] from NVD")
            req = requests.get(url="https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="+cve_id.strip().upper())
            cve_nvd_list.append(req.json()["vulnerabilities"][0]["cve"])
            #print(req.json()["vulnerabilities"][0]["cve"])
            #input(">")
        except Exception as e:
            # If you are lucky, no errors arise
            # For us, NVD seems to generate a lot of 503 errors, unfortunately
            # If this happens, we reccommend to download a local copy of NVD or to implement a retry-on-error system and arm yourself with patience
            print(cve_id,e)

    host_to_aggregated_inventory[host_id] = Aggregator.perform(AGGREGATION_LEVEL,cve_nvd_list)

    aggregated_inventory = dict()
    aggregated_inventory["host_id"] = host_id
    aggregated_inventory["aggregation_id_to_vulnerability_list"] = host_to_aggregated_inventory[host_id]

    f = open(file="dataset/aggregated_inventories/"+host_id+"_aggregated_inventory.json",mode="w",encoding="utf-8")
    f.write(json.dumps(aggregated_inventory))
    f.close()
