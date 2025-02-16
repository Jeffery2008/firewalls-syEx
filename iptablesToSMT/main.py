import sys
import os
from index import runner  # Modified import to specify directory
import shutil


def process_directory(input_dir, output_dir, max_files=None):
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Get list of files recursively
    rule_files = []
    for root, _, files in os.walk(input_dir):
        for f in files:
            # Get relative path from input_dir
            rel_path = os.path.relpath(os.path.join(root, f), input_dir)
            rule_files.append(rel_path)

    if max_files:
        rule_files = rule_files[:max_files]

    # Process each selected file
    for rel_path in rule_files:
        print(rel_path)
        input_path = os.path.join(input_dir, rel_path)

        # Create a directory for each file using the filename (without extension)
        file_name = os.path.splitext(rel_path)[0]
        output_rel_path = os.path.join(file_name, "output.smt2") # Corrected extension to .smt2
        output_path = os.path.join(output_dir, output_rel_path)

        # Create path for input file copy
        input_copy_path = os.path.join(output_dir, file_name, "input.txt")

        # Create necessary subdirectories
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # Copy input file to output directory
        shutil.copy2(input_path, input_copy_path)

        print(f"Processing file: {rel_path}")  # Verbose output
        print("Calling runner()...")  # Verbose output
        runner(input_path, output_path)
        print("runner() returned")  # Verbose output


def main():
    if len(sys.argv) not in [3, 4]:
        print("Usage: python main.py <input_directory> <output_directory> [max_files]")
        sys.exit(1)

    input_dir = sys.argv[1]
    output_dir = sys.argv[2]
    max_files = int(sys.argv[3]) if len(sys.argv) == 4 else None

    if not os.path.isdir(input_dir):
        print(f"Error: {input_dir} is not a directory")
        sys.exit(1)

    # --- Start verbose logging to file ---
    log_file = open("verbose.log", "w")  # Open log file for writing
    original_stdout = sys.stdout  # Backup original stdout
    sys.stdout = log_file  # Redirect stdout to log file
    print("Script execution started (verbose - to file)")  # Verbose output start - to file
    # --- End verbose logging to file ---

    print("Processing directory...")  # Verbose output
    process_directory(input_dir, output_dir, max_files)
    print("Script execution completed (verbose)")  # Verbose output end

    # --- Restore stdout and close log file ---
    sys.stdout = original_stdout  # Restore original stdout
    log_file.close()  # Close log file


if __name__ == "__main__":
    # --- Start verbose logging to file in main block ---
    log_file = open("verbose.log", "w")  # Open log file for writing
    original_stdout = sys.stdout  # Backup original stdout
    sys.stdout = log_file  # Redirect stdout to log file
    print("Script execution started (verbose - main - to file)")  # Verbose output start - main block - to file
    # --- End verbose logging to file in main block ---

    print("Script execution started (verbose - main)")  # Verbose output start - main block
    main()
    print("Script execution completed (verbose - main)")  # Verbose output end - main block

    # --- Restore stdout and close log file in main block ---
    sys.stdout = original_stdout  # Restore original stdout
    log_file.close()  # Close log file
