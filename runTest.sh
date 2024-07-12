# python3 tool.py 1a-basic-flow.py.json 1a-patterns.json
# python3 tool.py 1b-basic-flow.py.json 1b-patterns.json
# python3 tool.py 2-expr-binary-ops.py.json 2-patterns.json
# python3 tool.py 3a-expr-func-calls.py.json 3a-patterns.json
# python3 tool.py 3b-expr-func-calls.py.json 3b-patterns.json
# python3 tool.py 4a-conds-branching.py.json 4a-patterns.json
# python3 tool.py 4b-conds-branching.py.json 4b-patterns.json
# python3 tool.py 5a-loops-unfolding.py.json 5a-patterns.json
# python3 tool.py 5b-loops-unfolding.py.json 5b-patterns.json
# python3 tool.py 5c-loops-unfolding.py.json 5c-patterns.json
# python3 tool.py 6a-sanitization.py.json 6a-patterns.json
# python3 tool.py 6b-sanitization.py.json 6b-patterns.json
# python3 tool.py 7-conds-implicit.py.json 7-patterns.json
# python3 tool.py 8-loops-implici.py.json 8-patterns.json
# python3 tool.py 9-regions-guards.py.json 9-patterns.json


for FILE in *; do
    if [[ $FILE == *.py.json ]]; then 
        number=$(echo $FILE | awk -F"-" '{print $1}')
        patterns="$number-patterns.json"
        echo "Running $number"
        python3 tool.py $FILE $patterns > /dev/null
    fi
done
