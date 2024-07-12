#files with needed code
import auxiliar_functions
import visit_functions
import decompose

import sys
import json
import copy

def openFile(file, cfg):
    if cfg == "r":
        with open(file, cfg) as f:
            JSONFile = json.loads(f.read())
        return JSONFile
    if cfg == "w":
        outputFile = open(file, cfg)
        return outputFile

def buildOtuput(vulnerabilities, tainted_flows, sanitizers_by_vuln):
    output = []
    it = {}
    for key in vulnerabilities:
        it[str(key)] = 1
        for sink in vulnerabilities[key]["sinks"]:
            
            for flow_key, tainted_variables in tainted_flows.items():
                
                for source in tainted_variables[key]:
                    new_vuln = {}
                    
                    if sink in tainted_variables[key][source]:
                        new_vuln["vulnerability"] = str(
                            key) + "_" + str(it[str(key)])
                        new_vuln["source"] = source
                        new_vuln["sink"] = sink
                        new_vuln["unsanitized flows"] = "yes"
                        new_vuln["sanitized flows"] = []
                        
                        if (''+source, ''+sink) in sanitizers_by_vuln[key]:
                            new_vuln["unsanitized flows"] = sanitizers_by_vuln[key][(
                                ''+source, ''+sink)][1]
                            for el in sanitizers_by_vuln[key][(''+source, ''+sink)][0]:
                                new_vuln["sanitized flows"].append(el) 
                        
                        if output != []:
                            flag = 0
                            for s in output:
                                vuln_key = s["vulnerability"].split("_")
                                if vuln_key[0] == key and source in s["source"] and sink in s["sink"]:
                                    flag = 1
                            if flag == 0:
                                output.append(new_vuln)
                                it[str(key)] += 1
                        else:
                            output.append(new_vuln)
                            it[str(key)] += 1       
                        
    return output

def testVulnerabilities(vulnerabilities, ast, analysisFile, tainted_variables, sanitizers_by_vuln):
    initialized_variables = {}
    for el in vulnerabilities.items():
        initialized_variables[el[0]] = []

    # run the respective ast line-by-line 
    for node in ast["body"]:
        # evaluate the same node for all possible vulnerabilities
        for vulnerability, vuln_info in vulnerabilities.items():
            # vulnerability (e.g: A)
            # vuln_info (e.g: {'sources': ['c'], 'sanitizers': [], 'sinks': ['d', 'e'], 'implicit': 'no'})

            if vulnerability not in tainted_variables:
                tainted_variables[vulnerability] = {}

            if vulnerability not in sanitizers_by_vuln:
                sanitizers_by_vuln[vulnerability] = {}

            for source in vuln_info["sources"]:
                if source not in tainted_variables[vulnerability]:
                    tainted_variables[vulnerability][source] = []

                tainted_variables[vulnerability][source] = visit_functions.visitSubNode(
                    node, source, tainted_variables[vulnerability][source], initialized_variables[vulnerability], sanitizers_by_vuln[vulnerability], vuln_info["sanitizers"], vuln_info["sinks"], vuln_info["implicit"])

                if vuln_info["implicit"] == "yes":
                    if node["ast_type"] == "IfCond" or node["ast_type"] == "WhileCond":
                        infected_implicit_variables, copycat_list = auxiliar_functions.implicitEvaluation(
                            node["ast_type"], ast["body"])

                        implicit_variables = visit_functions.visitImplicitCond(
                            node["test"], source, initialized_variables[vulnerability], tainted_variables[vulnerability][source])
                        
                        auxiliar_functions.addInfectedToTainted(
                            implicit_variables, infected_implicit_variables, tainted_variables, vulnerability)

                        #new source can be found as n_source=x (x is the new source) 
                        auxiliar_functions.checkAndAddIfNewSourceFound(
                            implicit_variables, infected_implicit_variables, tainted_variables, vulnerability, source, copycat_list, initialized_variables, sanitizers_by_vuln, vuln_info, True, {})      

                #new source can be found as n_source=x (x is the new source) 
                auxiliar_functions.checkAndAddIfNewSourceFound(
                            [], [], tainted_variables, vulnerability, source, [], initialized_variables, sanitizers_by_vuln, vuln_info, False, node)

    return tainted_variables, sanitizers_by_vuln

if __name__ == "__main__":
    # read input from the command line
    programFile = sys.argv[1]
    patternsFile = sys.argv[2]

    # open all needed files
    programAST = openFile(programFile, "r")
    patterns = openFile(patternsFile, "r")
    analysisFile = openFile(patternsFile.split(
        "-")[0] + "-analysis-output.json", "w")

    #decompose functions needed before test possible vulnerabilities
    programPaths = decompose.decomposeProgram(programAST)
    vulnerabilities = decompose.decomposePatterns(patterns)

    tainted_flows = {}
    sanitizers_by_vuln = {}

    # run the tool and find vulnerabilities
    flow_number = 0
    for path in programPaths:
        tainted_variables = {}
        tainted_variables, sanitizers_by_vuln = testVulnerabilities(
            vulnerabilities, path, analysisFile, tainted_variables, sanitizers_by_vuln)
        tainted_flows[flow_number] = tainted_variables
        flow_number += 1
    
    #create a readable output
    output = buildOtuput(
        vulnerabilities, tainted_flows, sanitizers_by_vuln)
    json.dump(output, analysisFile, indent=4)  

    # name of file created with the output
    print("Output inserted in: " + patternsFile.split(
        "-")[0] + "-analysis-output.json")