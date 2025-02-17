# Sample challenge which just prints the flag

if __name__ == "__main__":
    with open("./flag.txt", "r") as f:
        print("Hello I am challenge: {name} and my flag is " + f.read())