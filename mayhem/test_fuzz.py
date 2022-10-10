#!/usr/bin/python3
import atheris
import sys

with atheris.instrument_imports():
    import simplematch as sm

def testOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    num = fdp.ConsumeIntInRange(0, 1)

    str_1 = fdp.ConsumeString(64)
    str_2 = fdp.ConsumeString(64)

    if num == 0:
        sm.match(pattern=str_1, string=str_2)
    if num == 1:
        sm.test(str_1, str_2)
        
def main():
    atheris.Setup(sys.argv, testOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()