from sklearn import tree

class DecisionTree:

    def __init__(self):
        self.classifier = tree.DecisionTreeClassifier(max_depth=5)

    def train(self, data):
        X = []
        Y = []
        for con in data:
            X.append(con.to_training_data()[0])
            Y.append(con.to_training_data()[1])
        self.classifier.fit(X, Y)

    def test(self, test_data):
        X = []
        Y = []
        for con in test_data:
            X.append(con.to_training_data()[0])
            Y.append(con.to_training_data()[1])
        results = self.classifier.predict(X)
        sum = 0
        for idx in range(Y):
            if results[idx] == Y[idx]:
                sum += 1
        return float(sum)/len(Y)

