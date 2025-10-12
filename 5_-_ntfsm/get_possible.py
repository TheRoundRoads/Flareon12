'''
For a given state, data[state]
Keys: Possible letters
Values: New state

Go until 16 characters reached.
'''

import json

def process_jsons():
    data = {}

    for i in range(0, 91000, 1000):
        temp = json.loads(open(f"assets\\out{i}.json", "r").read())

        for k, v in temp.items():
            data[k] = v

    return data

data = json.loads(open("out1.json", "r").read())
# data = process_jsons()
FLAG = [None] * 16
def dfs(state, idx):
    global data, FLAG

    # base case: successful
    if idx == 16:   
        open("out.txt", "a").write("".join(FLAG)+"\n")
        print("Found:", "".join(FLAG))

        return True

    
    # base case: fail
    if len(data[str(state)]) == 0:
        return False

    for val, new_state in data[str(state)].items():
        FLAG[idx] = chr(int(val))
        # if foo(new_state, idx+1):
            # return True

        dfs(new_state, idx+1)
        
    return False

def get_states(password):
    states = [0]
    for c in password:
        states.append(data[str(states[-1])][str(ord(c))])

    print(states)

dfs(0, 0)
