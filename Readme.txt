In order to run our tool automatically (which outputs a file per slice), the following instructions need to be followed:
    1- chmod u+r+x runTest.sh
    2- ./runTest.sh
    3- Observe each xxx-analysis-output.json file

In order to run the tool for a specific slice (let's assume slice 7), the following instruction is:
    1- python3 tool.py 7-conds.implicit.py.json 7-patterns.json
