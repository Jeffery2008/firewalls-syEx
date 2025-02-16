from iptables_rule_classes import IPTablesTable, IPTablesChain, IPTablesRule  # Import classes from iptables_rule_classes.py

def runner(input_file, output_file): # Define runner function
    print("Script execution started (simplified)")
    import iptables_parser # Modified import - try simple import
    print("iptables_parser imported")

    print("Calling parse_iptables_save_file()...") # Added print statement
    try:
        tables = iptables_parser.parse_iptables_save_file(input_file) # Use input_file argument
        print("parse_iptables_save_file() called successfully")
        print("Parsed tables object:", tables)  # Print the tables object itself
    except Exception as e:
        print("Error during iptables parsing:")
        print(e)
        return # Added return to exit if parsing fails

    # Generate C code
    from code_generator import generate_c_code
    # output_c_file = "/mnt/e/Coding/Python/lumiere_program/firewalls-syEx/iptablesToSMT/iptables_rules.c"  # Absolute path - remove hardcoded path
    print("Calling generate_c_code()...") # Added print statement
    try:
        generate_c_code(tables, output_file) # Use output_file argument
        print(f"C code generated successfully to: {output_file}")
    except Exception as e:
        print("Error during C code generation:")
        print(e)
        return # Added return to exit if code generation fails
            
    print("Script completed (simplified)")

if __name__ == "__main__": # Add if __name__ == "__main__": block to prevent immediate execution when imported
    input_file = "iptablesToSMT/example.rules" # Example input - you can remove this if main.py will always provide input
    output_file = "/mnt/e/Coding/Python/lumiere_program/firewalls-syEx/iptablesToSMT/iptables_rules.c" # Example output - you can remove this too
    runner(input_file, output_file) # Call runner function when script is run directly
