def reset():
    filename = "ntfsm.exe"
    
    with open(f"{filename}:input", "wb") as outfile:
        outfile.write(b"\x00"*16)
        
    with open(f"{filename}:position", "wb") as outfile:
        outfile.write(b"\x00"*8)
    
    with open(f"{filename}:transitions", "wb") as outfile:
        outfile.write(b"\x00"*8)
        
    with open(f"{filename}:state", "wb") as outfile:
        outfile.write(b"\xff"*8)
        
    return
    
def read_streams():
    filename = "ntfsm.exe"
    try:
        with open(f"{filename}:input", "rb") as infile:
            print("input:", infile.read())
    except:
        print("Input is closed")
    
    try:
        with open(f"{filename}:position", "rb") as infile:
            print("position:", infile.read())
    except:
        print("Positions is closed")
        
    try:
        with open(f"{filename}:transitions", "rb") as infile:
            print("transitions:", infile.read())
    except:
        print("Transitions is closed")
        
    try:
        with open(f"{filename}:state", "rb") as infile:
            print("state:", infile.read())
    except:
        print("State is closed")

    return
    
def modify(name, value):
    filename = "ntfsm.exe"
    try:
        with open(f"{filename}:{name}", "wb") as outfile:
            if name == "input":
                outfile.write(value.encode())
            else:
                outfile.write(int.to_bytes(int(value), 8, "little"))
        print("Done writing!")
    except:
        print(f"Error writing to {filename}:{name}")
        
def overwrite():
    input_ = input("Enter input: ")
    position = int(input("Enter position: "))
    state = int(input("Enter state: "))
    
    filename = "ntfsm.exe"
    
    with open(f"{filename}:input", "wb") as outfile:
        outfile.write(input_.encode())
        
    with open(f"{filename}:position", "wb") as outfile:
        outfile.write(int.to_bytes(int(position), 8, "little"))
    
    with open(f"{filename}:transitions", "wb") as outfile:
        outfile.write(int.to_bytes(int(position), 8, "little"))
        
    with open(f"{filename}:state", "wb") as outfile:
        outfile.write(int.to_bytes(int(state), 8, "little"))
        
    return
    
if __name__ == "__main__":
    print("1. Reset")
    print("2. Read streams")
    print("3. Modify stream value")
    print("4. Overwrite")
    option = int(input("Enter option: "))
    
    if option == 1:
        reset()
    elif option == 2:
        read_streams()
    elif option == 3:
        name = input("Enter stream name (e.g. state): ")
        value = input("Enter the value you want to change it to: ")
        modify(name, value)
    elif option == 4:
        overwrite()