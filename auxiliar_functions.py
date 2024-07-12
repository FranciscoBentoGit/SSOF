import visit_functions
import copy

"""
Auxiliar fucntions used in tool.py and recursive_functions.py
"""

def checkNewSource(var_to_check, source, initialized_variables, tainted_variables):
    if source != var_to_check and var_to_check not in initialized_variables:
        to_add = "n_source=" + var_to_check
        insertTaintedVar(tainted_variables, to_add, source)
    return tainted_variables

def insertTaintedVar(tainted_variables, variable, source):
    if variable not in tainted_variables and variable != source:
        tainted_variables.append(variable)
    return tainted_variables

def implicitEvaluation(implicit_type, body):
    # TUDO ATE ENCONTRAR ENDIFCOND/ENDWHILECOND FICA DENTRO DO C NA TAINTED VAR
    if implicit_type == "IfCond":
        implicit_end = "EndIfCond"
    
    if implicit_type == "WhileCond":
        implicit_end = "EndWhileCond"

    copycat_list = copy.copy(body)
    flag = 0
    for nd in list(copycat_list):
        if nd["ast_type"] != implicit_type:  # removes all lines before if/while
            copycat_list.remove(nd)
        else:
            if implicit_type == "IfCond":
                flag = 1
            break
    
    if flag == 1:
        to_remove = 0
        for nd in list(copycat_list):
            if nd["ast_type"] == "Repetition":
                to_remove = 1
            if to_remove == 1:
                copycat_list.remove(nd)
            if nd["ast_type"] == "EndWhileCond":
                to_remove = 0
                
    infected_implicit_variables = []
    for inside_nd in copycat_list:
        # inserts infect variables by implicit until it meets end of if/ end of while
        if inside_nd["ast_type"] != implicit_end:
            if inside_nd["ast_type"] == "Assign":
                for inside_nd_target in inside_nd["targets"]:
                    if inside_nd_target["id"] not in infected_implicit_variables:
                        infected_implicit_variables.append(
                            inside_nd_target["id"])
        else:
            break
    
    return infected_implicit_variables, copycat_list

def addInfectedToTainted(implicit_variables, infected_implicit_variables, tainted_variables, vulnerability):
    if implicit_variables != [] and infected_implicit_variables != []:
        for var_impl in implicit_variables:
            for key, value in tainted_variables.items():
                for sources in value:
                    if var_impl == sources or (sources in tainted_variables[vulnerability] and var_impl in tainted_variables[vulnerability][sources]):
                        for infected_implicit in infected_implicit_variables:
                            if infected_implicit != sources and sources in tainted_variables[vulnerability]:
                                insertTaintedVar(tainted_variables[vulnerability][sources], infected_implicit, sources)



def checkAndAddIfNewSourceFound(implicit_variables, infected_implicit_variables, tainted_variables, vulnerability, source, copycat_list, initialized_variables, sanitizers_by_vuln, vuln_info, is_implicit, node):
    for var in tainted_variables[vulnerability][source]:
        n_source = var.split("=")
        if n_source[0] == "n_source":
            new_source = n_source[1]

            if is_implicit:  
                if new_source not in tainted_variables[vulnerability]:
                    tainted_variables[vulnerability][new_source] = []
                    if implicit_variables != [] and infected_implicit_variables != []:
                        for var_impl in implicit_variables:
                            for key, value in tainted_variables.items():
                                for sources in value:
                                    if var_impl == sources or (sources in tainted_variables[vulnerability] and var_impl in tainted_variables[vulnerability][sources]):
                                        for infected_implicit in infected_implicit_variables:
                                            if infected_implicit != sources:
                                                insertTaintedVar(tainted_variables[vulnerability][sources], infected_implicit, sources)
                
                for chave, valor in tainted_variables.items():
                    for chaves in valor:
                        if chaves in tainted_variables[vulnerability]:
                            for node_cond in copycat_list:
                                tainted_variables[vulnerability][chaves] = visit_functions.visitSubNode(
                                    node_cond, chaves, tainted_variables[vulnerability][chaves], initialized_variables[vulnerability], sanitizers_by_vuln[vulnerability], vuln_info["sanitizers"], vuln_info["sinks"], vuln_info["implicit"])
            
            else:   
                if new_source not in tainted_variables[vulnerability]:
                    tainted_variables[vulnerability][new_source] = []
                
                tainted_variables[vulnerability][new_source] = visit_functions.visitSubNode(
                    node, new_source, tainted_variables[vulnerability][new_source], initialized_variables[vulnerability], sanitizers_by_vuln[vulnerability], vuln_info["sanitizers"], vuln_info["sinks"], vuln_info["implicit"])
            
            tainted_variables[vulnerability][source].remove(var)