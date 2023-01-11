#imports
from pathlib import Path
from datetime import datetime
import hashlib
import os
import sys


#Locate/declare file with malicious hashes
parentDirectory = os.path.dirname(sys.argv[0])
SHA256_hashes = os.path.join(parentDirectory, "badHashes.txt")
custom_hashes = ""


#define directory traversal method given a string indicating a file path ex: r"C:\Users"
#if called w/no args will taverse current directory
def traverse(directory="."):

    #define hashlist, define files in directory by file path
    hashlist = {}
    filePaths = Path(directory).rglob('*')

    #traverse given directory based on file path
    for filePath in filePaths:

        #check if directory, do not attempt to open directory as file
        if filePath.is_dir():
            continue

        #get contents of file
        contents = open(filePath, "rb").read()
        #hash contents of file, store in hashlist by file path
        hashlist[filePath] = hashlib.sha256(contents).hexdigest()

    #set up current date/time
    currentTime = datetime.now().strftime("%d-%b-%y_%H-%M-%S")
    #define output file name, place in directory 'traverse' was called in
    fileName = r"%s/hashlist_%s.txt" % (directory, currentTime)

    #write hashes to file with ; as deliniator
    with open(fileName, 'w') as f:
        for path in hashlist:
            f.write("%s;%s\n" % (path, hashlist[path]))

    #Tell user location of results
    print(fileName)



def scan(directory = "."):
    #Dictionary to store hashes and their corresponding file paths
    hashes_and_paths = {}
    scan_hashes = SHA256_hashes
    if custom_hashes != "":
        scan_hashes = custom_hashes

    #define directory to scan
    filePaths = Path(directory).rglob('*')

    #traverse given directory based on file path
    for filePath in filePaths:

        #check if directory, do not attempt to open directory as file
        if filePath.is_dir():
            continue

        # Calculate the hash of the file contents
        file_hash = hashlib.sha256()
        try:
            with open(filePath, "rb") as f:
                # Read the contents of the file in chunks
                for chunk in iter(lambda: f.read(4096), b""):
                    file_hash.update(chunk)
            # Get the hexadecimal representation of the hash
            file_hash = file_hash.hexdigest()
            
            # Check if the hash is in the list of known malicious hashes
            with open(scan_hashes,'r') as f:
                badHashes = f.readlines()
                for badHash in badHashes:
                    if file_hash == badHash.split(";")[0]:
                        hashes_and_paths[filePath] = file_hash
                        # Remove the file
                        os.remove(filePath)
                        #print("Fake/test file remove")
        except FileNotFoundError:
            print(f"File not found: {filePath}")
        except Exception as e:
            print(f"An error occurred: {e}")

    #Set up output
    output = "Removed %s files" % (len(hashes_and_paths))
    
    #If scan() removed any files, generate output file and add to output message
    if len(hashes_and_paths) != 0:
        
        #set up current date/time
        currentTime = datetime.now().strftime("%d-%b-%y_%H-%M-%S")
        #define output file name, place in directory 'scan' was called in
        fileName = r"%s/removed_%s.txt" % (directory, currentTime)

        output += ", logged in %s" % (fileName)

        #write hashes to file with ; as deliniator
        with open(fileName, 'w') as f:
            for path in hashes_and_paths:
                f.write("%s;%s\n" % (path, hashes_and_paths[path]))
    
    print(output)



#Take two files previously created by traverse() and create an output file detailing any differences
#Proper usage is that both files were created by calling traverse() on the same directory and that file1 is the older of the two
def compare(file1, file2):

    #define dictionaries
    hashlist1 = {}
    hashlist2 = {}

    #define output file components
    newFiles = {}
    changedFiles = {}
    removedFiles = {}

    #define output file name
    fileName = "compare_%s_%s" % (file1[-22:], file2[-22:])
    
    #read all found hashes into a dictionary for file1
    with open(file1, "r") as f:
        lines = f.readlines()

        #Key is file path, value is hash
        for line in lines:
            splitLine = line.split(";")
            hashlist1[splitLine[0]] = splitLine[1]

    #repeat for file2
    with open(file2, "r") as f:
        lines = f.readlines()

        for line in lines:
            splitLine = line.split(";")
            hashlist2[splitLine[0]] = splitLine[1]

    #declare placeholder dictionary so we can remove keys from originals while iterating through
    templist1 = dict(hashlist1)

    #Iterate through dictionaries of stored hashes
    for key in templist1:
        
        #Record any not present in hashlist2 as 'removed'
        if key not in hashlist2:
            removedFiles[key] = hashlist1[key]

        #Record any present with different hash as 'changed'
        #To make it easier on myself later and since this isn't gonna be referenced by anything, I'm just doing the string formatting for output now
        elif hashlist1[key] != hashlist2[key]:
            changedFiles[key] = "%s;%s" % (hashlist1[key], hashlist2[key])

        #Remove key from input dictionaries. Identical keys will not be recorded, this is intentional.
        hashlist1.pop(key)
        if key in hashlist2:
            hashlist2.pop(key)
    
        #Record any hashes not present in hashlist1 as 'new'
    for key in hashlist2:
        if key not in hashlist1:
            newFiles[key] = hashlist2[key]
        
    #Write recorded results to output file
    with open(fileName, 'w') as f:
        f.write("New Files:\n\n")
        for path in newFiles:
            f.write("%s;%s" % (path, newFiles[path]))

        f.write("\nChanged Files (path;former hash;new hash):\n\n")
        for path in changedFiles:
            f.write("%s;%s" % (path, changedFiles[path]))

        f.write("\nRemoved Files:\n\n")
        for path in removedFiles:
            f.write("%s;%s" % (path, removedFiles[path]))

    print(fileName)



#Main function to take input from command line and execute method calls as requested
def Main():

    #define input variable, help message, custom hash file
    command = ""
    global custom_hashes

    help = "help / ?- view this message\n"
    help += "trav [*dir] - traverse given directory (defaults to current) and output list of file hashes\n"
    help += "scan [*dir] - scan for malicious hashes in given directory (defaults to current) & remove any found\n"
    help += "comp [file1] [file2] - compare two hashlists previosly generated by trav\n"
    help += "custom [hashlist] - use custom list to identify malicious hashes to be removed\n"
    help += "exit / quit - end program"

    #define commands
    validComs = ["?", "help", "trav", "scan", "comp", "exit", "quit", "custom", "cd", "pwd", "ls"]

    #Welcome msg
    print("Welcome! Use '?' or 'help' to see commands")

    #loop until user quits
    while command != "exit" and command != "quit":
        
        #take input
        command = input("breakfastPotatoes: ")
        splitCom = command.split(" ", 1)

        #Invalid command
        if command == "" or splitCom[0] not in validComs:
            print("Invalid command enter. Use \'help\' or \'?\' to display valid commands")
        
        #Help
        elif command == "help" or command == "?":
            print(help)

        #traverse
        elif splitCom[0] == "trav":

            try:
            #Current directory
                if len(splitCom) == 1:
                    traverse()
            #Given directory
                elif len(splitCom) == 2:
                    traverse(splitCom[1])
            #Invalid argument count
                else:
                    print("Provide no more than 1 directory to traverse (defaults to current directory)")
                
            except:
                print("directory traversal failed")
        
        #scan
        elif splitCom[0] == "scan":
            try:
            #Current directory
                if len(splitCom) == 1:
                    scan()
            #Given directory
                elif len(splitCom) == 2:
                    scan(splitCom[1])
            #Invalid argument count
                else:
                    print("Provide no more than 1 directory to scan (defaults to current directory)")
                
            except:
                print("directory scan failed")

        #compare
        elif splitCom[0] == "comp":

            #Correct splitcom to allow for more than 1 arg
            splitCom = command.split()

            #ensure proper number of arguments provided
            if len(splitCom) != 3:
                print("Provide 2 files to compare")
                continue

            try:
                compare(splitCom[1], splitCom[2])
            except:
                print("file comparison failed")

        #Set custom malicios hash list
        elif splitCom[0] == "custom":

            #check to ensure path is valid
            try:
                with open(splitCom[1],'r') as f:
                    pass
            except Exception as e:
                print(f"An error occurred: {e}\nPlease provide file path to custom bad hash list")
            else:
                custom_hashes = splitCom[1]

        #Change directory
        elif splitCom[0] == "cd":
            newPath = ""
            try:
                #if no path provided
                if len(splitCom) == 1:
                    
                    newPath = os.path.dirname(os.getcwd())
                #if path provided
                else:
                    newPath = splitCom[1]
                
                os.chdir(newPath)

            #catch and display some possible errors
            except FileNotFoundError:
                print("Directory {0} not found".format(newPath))
            except NotADirectoryError:
                print("{0} is not a directory".format(newPath))
            except PermissionError:
                print("Unable to change to {0}, permission denied".format(newPath))

        #print working directory
        elif splitCom[0] == "pwd":
            print(os.getcwd())

        #list
        elif splitCom[0] == "ls":
            print(os.listdir())



#Run main
if __name__ == "__main__":
    Main()