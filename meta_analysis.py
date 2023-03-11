import PyPDF2
import pefile
import shlex
#import docx

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
    with open(file_path, "r") as f:
        script = f.read()
    tokens = shlex.split(script)
    num_tokens = len(tokens)
    num_lines = script.count("\n")
    shebang_line = ""
    if tokens and tokens[0].startswith("#!"):
        shebang_line = tokens.pop(0)
    command_names = [t for t in tokens if not t.startswith("-") and not t.startswith("$")]
    unique_command_names = sorted(set(command_names))
    options = [t for t in tokens if t.startswith("-")]
    unique_options = sorted(set(options))
    with open("metadata_sh.txt", "w") as f:
        f.write("File name: "+file_path+"\n")
        f.write("Number of tokens:"+str(num_tokens)+"\n")
        f.write("Number of lines:"+str(num_lines)+"\n")
        f.write("Shebang line:"+str(shebang_line)+"\n")
        f.write("Command names:"+str(unique_command_names)+"\n")
        f.write("Options:"+str(unique_options)+"\n")

    print("File name:", file_path)
    print("Number of tokens:", num_tokens)
    print("Number of lines:", num_lines)
    print("Shebang line:", shebang_line)
    print("Command names:", unique_command_names)
    print("Options:", unique_options)


    
# if filename.endswith('.doc') or filename.endswith('.docx'):
#     file_path = filename
#     document = docx.Document(file_path)
#     properties = document.core_properties
#     title = properties.title
#     author = properties.author
#     created = properties.created
#     modified = properties.modified
#     keywords = properties.keywords
#     print("File name:", file_path)
#     print("Title:", title)
#     print("Author:", author)
#     print("Created:", created)
#     print("Modified:", modified)
#     print("Keywords:", keywords)
else:
    print("Unsupported file format! please choose either a exe, pdf or shell file")