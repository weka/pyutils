# This is a circular linked list implementation in Python.

# Usage:
#   Using it in a for loop will iterate through the list once, like a standard list
#   Using the next() method will iterate through the list indefinitely

from threading import Lock


class CircularListNode:
    def __init__(self, data):
        self.data = data
        self.next = None


class CircularList:
    def __init__(self, inputlist=None):
        self.head = None
        self.tail = None
        self.current = None
        self._lock = Lock()  # for thread safety
        if inputlist:
            if type(inputlist) is not list:
                raise TypeError("input must be a list")
            for item in inputlist:
                self.append(item)

    def append(self, data):
        with self._lock:
            if not self.head:
                self.head = CircularListNode(data)
                self.head.next = self.head
                self.tail = self.head
            else:
                new_node = CircularListNode(data)
                self.tail.next = new_node
                self.tail = new_node
                new_node.next = self.head

    def __next__(self):
        with self._lock:
            return self._next()

    def _next(self):    # assumes lock is already held
        if not self.current:
            self.current = self.head
        else:
            self.current = self.current.next
        return self.current.data

    def next(self):
        return self.__next__()

    def __iter__(self):
        with self._lock:
            self.current = None
            while self.current != self.tail:
                yield self._next()

    def print_list(self):
        for item in self:
            print(item)

if __name__ == '__main__':
    cl = CircularList([1, 2, 3, 4, 5])
    cl.print_list()
    print("iterating")
    for i in range(9):
        print(cl.next())
    print("iterating again")
    for i in range(9):
        print(next(cl))

    print("iterating with for loop")
    for item in cl:
        print(item)

    print("iterating with while loop")
    count = 0
    while item := cl.next():
        count += 1
        if count > 20:
            break
        print(item)