import sys

# print( something without a newline )
def announce(text):
    sys.stdout.flush()
    sys.stdout.write(text)
    sys.stdout.flush()