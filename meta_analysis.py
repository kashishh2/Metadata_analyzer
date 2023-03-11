import PyPDF2
import pefile
import shlex
import docx

filename = input("Enter file path: ")

if filename.endswith('.pdf'):
    with open(filename, 'rb') as f:
        pdf = PyPDF2.PdfReader(f)
        text = ""
        for page in pdf.pages:
            text += page.extract_text()

        doc_meta = pdf.metadata

        print(f"PDF metadata:\n{doc_meta}")
        print(f"\nPDF text content:\n{text}")
        with open("metadata_pdf.txt", "w") as f:
            f.write(f"PDF metadata:\n{doc_meta}")
            f.write(f"\nPDF text content:\n{text}")

if filename.endswith('.exe'):
    pe = pefile.PE(filename)
    with open("metadata_exe.txt", "w") as f:
        # Write out the metadata to the file
        f.write("DOS Header:\n")
        print("DOS Header:\n")
        print(str(pe.DOS_HEADER) + "\n\n")
        f.write(str(pe.DOS_HEADER) + "\n\n")

        print("\nNT Header:")
        print(pe.NT_HEADERS)
        f.write("NT Header:\n")
        f.write(str(pe.NT_HEADERS) + "\n\n")

        print("\nFile Header:")
        print(pe.FILE_HEADER)
        f.write("File Header:\n")
        f.write(str(pe.FILE_HEADER) + "\n\n")


        f.write("Optional Header:\n")
        f.write(str(pe.OPTIONAL_HEADER) + "\n\n")
        print(pe.OPTIONAL_HEADER)
        print("\nSections:")

        f.write("Sections:\n")

        for section in pe.sections:
            print(section)
            f.write(section.Name.decode("utf-8") + "\n")
            print(section.Name.decode("utf-8") + "\n")
            f.write("\tVirtual Address: " + hex(section.VirtualAddress) + "\n")
            print("\tVirtual Address: " + hex(section.VirtualAddress) + "\n")
            f.write("\tVirtual Size: " + str(section.Misc_VirtualSize) + "\n")
            print("\tVirtual Size: " + str(section.Misc_VirtualSize) + "\n")
            f.write("\tSize of Raw Data: " + str(section.SizeOfRawData) + "\n")
            print("\tSize of Raw Data: " + str(section.SizeOfRawData) + "\n")
            f.write("\tCharacteristics: " + hex(section.Characteristics) + "\n")
            print("\tCharacteristics: " + hex(section.Characteristics) + "\n")
            f.write("\n")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(entry)
            f.write(entry.dll.decode("utf-8") + "\n")
        for imp in entry.imports:
            print('\t', hex(imp.address), imp.name)
            f.write("\t" + hex(imp.address) + " " + str(imp.name) + "\n")

if filename.endswith('.sh'):
    file_path = filename

    # Open the file and read its contents
    with open(file_path, "r") as f:
        script = f.read()

    # Use shlex to split the script into tokens
    tokens = shlex.split(script)

    # Get the number of tokens and lines in the script
    num_tokens = len(tokens)
    num_lines = script.count("\n")

    # Get the shebang line, if present
    shebang_line = ""
    if tokens and tokens[0].startswith("#!"):
        shebang_line = tokens.pop(0)

    # Get the list of command names used in the script
    command_names = [t for t in tokens if not t.startswith("-") and not t.startswith("$")]
    unique_command_names = sorted(set(command_names))

    # Get the list of options used in the script
    options = [t for t in tokens if t.startswith("-")]
    unique_options = sorted(set(options))

    # Print out the metadata
    with open("metadata_sh.txt", "w") as f:
        f.write("File name:", file_path)
        f.write("Number of tokens:", num_tokens)
        f.write("Number of lines:", num_lines)
        f.write("Shebang line:", shebang_line)
        f.write("Command names:", unique_command_names)
        f.write("Options:", unique_options)

    print("File name:", file_path)
    print("Number of tokens:", num_tokens)
    print("Number of lines:", num_lines)
    print("Shebang line:", shebang_line)
    print("Command names:", unique_command_names)
    print("Options:", unique_options)


    
if filename.endswith('.doc') or filename.endswith('.docx'):
    # Replace "your_file.docx" with the name of your actual DOCX file
    file_path = filename

    # Load the document using python-docx
    document = docx.Document(file_path)

    # Get the document properties
    properties = document.core_properties

    # Extract the metadata fields
    title = properties.title
    author = properties.author
    created = properties.created
    modified = properties.modified
    keywords = properties.keywords

    # Print out the metadata
    print("File name:", file_path)
    print("Title:", title)
    print("Author:", author)
    print("Created:", created)
    print("Modified:", modified)
    print("Keywords:", keywords)
else:
    print("Unsupported file format!")









# import hashlib
# import PyPDF2

# filename = input("Enter file path: ")

# if filename.endswith('.pdf'):
#     with open(filename, 'rb') as f:
#         pdf = PyPDF2.PdfFileReader(f)
#         pdf_content = f.read()
#         pdf_hash = hashlib.sha256(pdf_content).hexdigest()

#         print(f"PDF hash:\n{pdf_hash}")

# else:
#     print("Unsupported file format!")



#/Users/kashishhanda/Downloads/sample.pdf