# Improving Attack Graph-based Self-Protecting Systems: A Computational Pipeline for Accuracy-Scalability Trade-off

Main repository for CRiSIS 2024 submission.

### Abstract

Self-protection is a desired property of many modern ICT systems as it enriches them with the ability to detect and react to security threats at run-time.
Recently, several solutions leveraging vulnerability scanners and attack graph models have been proposed to monitor and analyze cyber risks and trigger security adaptations accordingly.
While such systems provide effective self-protection, they mainly focus on the system design without investigating the potential drawbacks of their components, such as accuracy and scalability.
This hinders their applicability in real large-scale scenarios.

To this aim, this paper introduces and investigates the intrinsic relationships between the accuracy of security monitoring through vulnerability scanners and the computational complexity of risk assessment through attack graphs. 
We propose a computational pipeline that includes vulnerability filtering and aggregation modules that can be used in isolation or combined to tune the accuracy-scalability trade-off.
We also define several heuristics for our pipeline and provide an experimental evaluation to assess its benefits and limitations.

### Installation requirements

- nvdlib
- numpy
- networkx
- pebble
- pandas
- seaborn

### Running the code

Running the experiments on the case study:

`cd case_study\`
`python main.py`

Running the experiments for scalability:

`cd scalability\`
`python main.py`
