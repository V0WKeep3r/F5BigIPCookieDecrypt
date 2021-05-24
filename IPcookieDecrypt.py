# python3
import struct
import sys

def decode(cookie_value):
     (host, port, end) = cookie_value.split('.')
     (a, b, c, d) = [ord(i) for i in struct.pack("<I", int(host))]
     p = [ord(i) for i in struct.pack("<I", int(port))]
     port = p[0]*256 + p[1]
     print("{0}.{1}.{2}.{3}:{4}".format(a,b,c,d,port))

if len(sys.argv) != 3:
     print("Usage: {} input_type encoded_string".format(sys.argv[0]))
     print("-c cookie value")
     print("-f File Name containing cookie values on each linen")
     print("exapmle. {} -c 487098378.24095.0000".format(sys.argv[0]))
     print("example. {} -f file.txt".format(sys.argv[0]))
     exit(1)
if sys.argv[1] == "-c":
     cookie_text = sys.argv[2]
     decode(cookie_text)
if sys.argv[1] == "-f":
     file_name = sys.argv[2]
     with open(file_name,"r") as f:
          for x in f:
               x = x.rstrip()
               if not x: continue
               decode(x)