### Running System parameters
num_cores=3

### Reachability and Vulnerability configurations
num_src_risk = 10
num_dst_risk = 10

### Real scenario configurations
real_generator_scanner = "merged" ### "nessus", "openvas" and "merged" with "merged" being the result of a set-union. If in doubt, default to "merged"
real_generator_strategy = "m3" ### string m1-6, with "m3" being the heuristic. If in doubt, default to "m3"
real_generator_step_modulo = 10 ### Used to generate a snapshot each "modulo" steps. As in if #step % step_modulo == 0, then generate the snapshot

# Strategy legend
# 1 - completely random
# 2 - cutting out useless cpe
# 3 - heuristic
# 4 - worst cve first
# 5 - worst cve first, then heuristic among cpe
# 6 - heuristic first, then worst cve - paper rebuttal

real_generator_strategies = ["m1","m2","m3","m4","m5","m6"] ### Used to loop over all strategies

### Inventories
NETWORK_FOLDER = "dataset/inventories/"
GRAPH_FOLDER = "dataset/graphs/"
ANALYSIS_FOLDER = "analysis/"
PLOT_FOLDER = ANALYSIS_FOLDER+"plot/"

ANALYSIS_SPACE_FILE = ANALYSIS_FOLDER+"space.csv"
PLOT_SPACE_FOLDER = PLOT_FOLDER+"space/"

ANALYSIS_ACCURACY_FILE = ANALYSIS_FOLDER+"accuracy.csv"
PLOT_ACCURACY_FOLDER = PLOT_FOLDER+"accuracy/"

ANALYSIS_TIME_FILE = ANALYSIS_FOLDER+"generation_time.csv"
ANALYSIS_PATH_FILE = ANALYSIS_FOLDER+"time_paths.csv"
PLOT_TIME_FOLDER = PLOT_FOLDER+"time/"

ANALYSIS_AGGREGATION_FILE = ANALYSIS_FOLDER+"aggregation_time.csv"

# real_inventory=NETWORK_FOLDER+"real_inventory.json"
# panacea_device="dataset/real/deviceInventory.json"
# panacea_vulnerabilities="dataset/real/vulnerabilityCatalog.json"
# panacea_reachability="dataset/real/reachabilityInventory.json"

ADVISORY_RESOURCES = "inventory_generator/resources"

### NIST backup
nvd_complete_dump = "../dataset/NIST/path_to_nvd_dump.txt"