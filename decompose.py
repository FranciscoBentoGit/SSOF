import copy

def multiplyPaths(paths):
    '''
    This function copies lists of paths in a mirror form.
    Allowing for the combination of multiple paths.

    E.g
    Input: [[A][B]]
    Output: [[A][B][B][A]]
    '''
    pathsCopy = list(paths)
    for path in paths[::-1]:
        pathsCopy.append(copy.deepcopy(path))
    paths = list(pathsCopy)
    return paths


def addPaths(paths, number):
    number = number - len(paths)
    pathsToAdd = copy.deepcopy(paths)
    for i in range(number):
        for p in pathsToAdd:
            paths.append(copy.deepcopy(p))
    return paths


def joinPaths(paths, pathsToAppend, isIf=False, isMain=False):
    '''
    This function joins paths with all the combinations possible

    E.g
    Input: Paths: [[A]] PathsToAppend: [[B][C]]

    Since Paths < PathsToAppend it will multiply the Paths.
    Paths: [[A][A]]

    Output: [[AB][AC]]
    '''
    if(isMain):
        return joinPathsToBody(paths, pathsToAppend)
    while(len(paths) < len(pathsToAppend)):
        paths = multiplyPaths(paths)
    if(isIf):
        for path in pathsToAppend:
            for i in range(0, len(paths)+1, 2):
                for p in path:
                    paths[i].append(copy.deepcopy(p))
    else:
        for path in pathsToAppend:
            for i in range(0, len(paths), 2):
                for p in path:
                    paths[i].append(copy.deepcopy(p))
    return paths


def joinPathsToBody(paths, pathsToAppend):
    '''
    This function joins paths with one to one combinations

    E.g
    Input: Paths: [[A]] PathsToAppend: [[B][C]]

    Since Paths < PathsToAppend it will multiply the Paths.
    Paths: [[A][A]]

    Output: [[AB][AC]]
    '''
    while(len(paths) < len(pathsToAppend)):
        paths = multiplyPaths(paths)
    i = -1
    for path in pathsToAppend:
        i = i + 1
        for p in path:
            paths[i].append(p)

    return paths


def JoinPathsMain(paths, pathsToAppend):
    paths = addPaths(paths, len(pathsToAppend))
    i = -1
    for pathToAppend in pathsToAppend:
        i = i + 1
        for p in pathToAppend:
            paths[i].append(p)
    return paths


def CombinePath(path):
    '''
    This function combines one path with it self in all the diffrent ways

    E.g
    Input [[A],[B]]

    Output [[AA],[BA],[BB],[AB]]

    '''
    path1 = copy.deepcopy(path)
    path2 = copy.deepcopy(path)
    combs = len(path)

    for path in path2:
        path1.append(copy.deepcopy(path))
    for path in path1:
        path.append({'ast_type': 'Repetition'})
    for k in range(combs):
        for i in range(combs):
            path1[combs*k + i] = path1[combs*k + i] + copy.deepcopy(path2[k])
    return path1


def decomposeWhile(whileProgramSection, isMain=False):
    paths = [[]]
    for node in whileProgramSection:
        if(node['ast_type'] == "While"):
            for p in paths:
                p.append({'ast_type': 'WhileCond', 'test': node['test']})
            paths = joinPaths(paths, decomposeWhile(node['body']), isMain=True)
            for p in paths:
                p.append({'ast_type': 'EndWhileCond'})
        elif(node['ast_type'] == "If"):
            paths = joinPaths(paths, decomposeIf([node, ]), isMain=True)
        else:
            for path in paths:
                path.append(node)
    if not isMain:  # combine everything in 1 while
        return CombinePath(paths)
    return paths


def decomposeIf(ifProgramSection, isMain=False):
    '''
    returns the paths inside of an if
    position even -> else
    postion odd -> if

    '''
    paths = [[]]
    for node in ifProgramSection:
        if(node['ast_type'] == "If"):
            pathsIf = copy.deepcopy(paths)
            pathsElse = [[]]
            if(isMain):
                pathsElse = copy.deepcopy(paths)
            for p in pathsIf:
                p.append({'ast_type': 'IfCond', 'test': node['test']})
            pathsToAppendIf = decomposeIf(node["body"])
            pathsIf = joinPaths(pathsIf, pathsToAppendIf, True, isMain)
            for p in pathsIf:
                p.append({'ast_type': 'EndIfCond'})
            if(node["orelse"] != []):
                pathsElse = copy.deepcopy(paths)
                for p in pathsElse:
                    p.append({'ast_type': 'IfCond', 'test': node['test']})
                pathsToAppendElse = decomposeIf(node["orelse"])
                if(len(pathsToAppendElse) == 2):
                    pathsElse = multiplyPaths(pathsElse)
                pathsElse = joinPaths(
                    pathsElse, pathsToAppendElse, False, isMain)
                for p in pathsElse:
                    p.append({'ast_type': 'EndIfCond'})
            paths = pathsIf + pathsElse
        elif(node['ast_type'] == "While"):
            pathsWhile = decomposeWhile(node["body"])
            for path in pathsWhile:
                path.append(pathsWhile)
        else:
            for path in paths:
                path.append(node)
            pass
    return paths


def decomposeProgram(mainProgram):

    mainPath = []
    paths = [[]]
    main = False
    for node in mainProgram["body"]:
        if(node["ast_type"] == "If"):
            paths = JoinPathsMain(paths, decomposeIf([node, ], True))
        elif(node["ast_type"] == "While"):
            paths = JoinPathsMain(paths, decomposeWhile([node, ], True))
        else:
            for path in paths:
                path.append(node)
            mainPath.append(node)
            pass
    if(main):
        paths.append(mainPath)

    finalPaths = []
    for p in paths:
        finalPaths.append({"ast_type": "Module", "body": p})
    paths = finalPaths
    return paths


def decomposePatterns(pattern):
    vulnerabilities = {}
    for i in pattern:
        vulnerability = i["vulnerability"]
        i.pop("vulnerability")
        vulnerabilities[vulnerability] = i
    return vulnerabilities
