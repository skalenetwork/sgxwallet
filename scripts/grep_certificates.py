import os
import re
import sys

def main():
    if len(sys.argv) != 2:
        print("Wrong number of command line arguments: need exactly one")
        exit(1)

    path = sys.argv[1]
    if not os.path.exists(path):
        print("No such file or directory: ", path)
        exit(2)
    
    certs_path = os.path.join(path, "cert_data", "new_certs")
    if not os.path.exists(certs_path):
        print("No such file or directory: ", certs_path)
        exit(3)

    if len(os.listdir(certs_path)) == 0:
        print("Empty certificates directory. Nothing to review.")
        return
    
    print("Total number of elements in folder:", len(os.listdir(certs_path)))
    for entity in os.listdir(certs_path):
        print("Reviewing", entity)
        entity_path = os.path.join(certs_path, entity)
        if not os.path.isfile(entity_path):
            print("Not a regular file. Skipping.")
            continue
        _, extension = os.path.splitext(entity_path)
        if extension != '.pem':
            print("Not a ssl certificate file. Skipping.")
            continue
        with open(entity_path,"r") as file_one:
            pattern = "Not Before"
            for line in file_one:
                if re.search(pattern, line):
                    print(line)
                    break

if __name__ == '__main__':
    main()