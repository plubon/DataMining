from sys import argv
import Connection
from DecisionTree import DecisionTree

def main():
    training_data = Connection.read(argv[1])
    test_data = Connection.read(argv[2])
    print("Data loaded!")
    tree = DecisionTree()
    tree.train(training_data)
    acc = tree.test(test_data)
    print(acc)

if __name__ == "__main__":
    main()