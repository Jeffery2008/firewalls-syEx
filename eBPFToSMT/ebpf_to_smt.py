#!/usr/bin/env python3

import argparse
import re
import subprocess
from pycparser import c_parser, c_ast

class FilteringRuleVisitor(c_ast.NodeVisitor):
    """
    Visitor class to traverse the C AST and extract filtering rules.
    (Basic implementation - needs to be extended)
    """
    def __init__(self):
        self.protocol = None
        self.src_ip = None
        self.dst_ip = None
        self.src_port = None
        self.dst_port = None

    def visit_If(self, node):
        # Visitor for if conditions, handling FuncCall and BinaryOp for various filters
        if isinstance(node.cond, c_ast.FuncCall): # Handle FuncCall conditions (e.g., is_tcp_packet(ctx))
            func_call = node.cond
            if isinstance(func_call.name, c_ast.ID):
                if func_call.name.name == 'is_tcp_packet':
                    self.protocol = 6 # TCP protocol
                # Add more FuncCall checks for other filters if needed (e.g., is_udp_packet)

        elif isinstance(node.cond, c_ast.BinaryOp) and node.cond.op == '==': # Handle BinaryOp conditions (e.g., pkt_protocol(ctx) == 6)
            if isinstance(node.cond.left, c_ast.FuncCall):
                func_call = node.cond.left
                if isinstance(func_call.name, c_ast.ID):
                    if func_call.name.name == 'pkt_protocol': # Protocol filter (numeric protocol value)
                        if isinstance(node.cond.right, c_ast.Constant) and node.cond.right.type == 'int':
                            self.protocol = int(node.cond.right.value)
                    elif func_call.name.name == 'packet_src_ip': # Source IP filter
                        if isinstance(node.cond.right, c_ast.Constant) and node.cond.right.type == 'int':
                            self.src_ip = node.cond.right.value # Keep as hex string for SMT conversion
                    elif func_call.name.name == 'packet_dst_ip': # Destination IP filter
                        if isinstance(node.cond.right, c_ast.Constant) and node.cond.right.type == 'int':
                            self.dst_ip = node.cond.right.value # Keep as hex string
                    elif func_call.name.name == 'packet_src_port': # Source port filter
                        if isinstance(node.cond.right, c_ast.Constant) and node.cond.right.type == 'int':
                            self.src_port = int(node.cond.right.value)
                    elif func_call.name.name == 'packet_dst_port': # Destination port filter
                        if isinstance(node.cond.right, c_ast.Constant) and node.cond.right.type == 'int':
                            self.dst_port = int(node.cond.right.value)


        # Continue visiting child nodes
        self.generic_visit(node)

def convert_ebpf_to_smt(ebpf_file): # Changed to accept file path instead of code string
    """
    Converts eBPF code (C format) to SMT-LIB2 representation using pycparser, with preprocessing.
    """
    try:
        # Preprocess the eBPF code using cpp (system's C preprocessor)
        command = ['cpp', '-nostdinc', '-I.', '-IeBPFToSMT', ebpf_file] # -nostdinc, -I., -IeBPFToSMT
        preprocessed_code = subprocess.check_output(command, text=True)
    except FileNotFoundError:
        raise RuntimeError("Error: C preprocessor 'cpp' not found. Please ensure it's installed and in your PATH.")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Preprocessing failed: {e.stderr}")

    parser = c_parser.CParser()
    try:
        ast = parser.parse(preprocessed_code) # Parse preprocessed code
    except pycparser.plyparser.ParseError as e:
        raise RuntimeError(f"Parsing failed: {e}")

    visitor = FilteringRuleVisitor()
    visitor.visit(ast)

    smt_code = "; SMT code generated from eBPF using pycparser with preprocessing\n"
    smt_code += "(declare-fun pkt_protocol () Int) ; Packet protocol field\n"
    smt_code += "(declare-fun pkt_src_ip () Int) ; Packet source IP address field\n"
    smt_code += "(declare-fun pkt_dst_ip () Int) ; Packet destination IP address field\n"
    smt_code += "(declare-fun pkt_src_port () Int) ; Packet source port field\n"
    smt_code += "(declare-fun pkt_dst_port () Int) ; Packet destination port field\n"

    if visitor.protocol is not None:
        smt_code += f"(; eBPF code indicates protocol filtering)\n"
        smt_code += f"(assert (= pkt_protocol {visitor.protocol}))\n"
    else:
        smt_code += "(; eBPF code does not indicate specific protocol filtering - pass all protocols)\n"
        smt_code += "(assert true) ; Pass all protocols\n"

    # Add SMT assertions for IP and port filtering based on visitor results
    if visitor.src_ip is not None:
        smt_code += f"(; eBPF code indicates source IP filtering)\n"
        smt_code += f"(assert (= pkt_src_ip {visitor.src_ip}))\n"
    if visitor.dst_ip is not None:
        smt_code += f"(; eBPF code indicates destination IP filtering)\n"
        smt_code += f"(assert (= pkt_dst_ip {visitor.dst_ip}))\n"
    if visitor.src_port is not None:
        smt_code += f"(; eBPF code indicates source port filtering)\n"
        smt_code += f"(assert (= pkt_src_port {visitor.src_port}))\n"
    if visitor.dst_port is not None:
        smt_code += f"(; eBPF code indicates destination port filtering)\n"
        smt_code += f"(assert (= pkt_dst_port {visitor.dst_port}))\n"


    return smt_code

def ip_to_int(ip_address):
    """
    Converts IPv4 address string to integer representation.
    """
    parts = ip_address.split('.')
    return sum([int(parts[i]) << (8 * (3 - i)) for i in range(4)])


def main():
    parser = argparse.ArgumentParser(description="eBPF to SMT-LIB2 Converter")
    parser.add_argument("ebpf_file", help="Path to the eBPF code file (C format)")
    parser.add_argument("smt_file", help="Path to save the output SMT-LIB2 file")

    args = parser.parse_args()

    # Read eBPF code from file (no longer needed here - read in convert_ebpf_to_smt)
    # try:
    #     with open(args.ebpf_file, "r") as f:
    #         ebpf_code = f.read()
    # except FileNotFoundError:
    #     print(f"Error: eBPF file not found at '{args.ebpf_file}'")
    #     return

    try:
        smt_code = convert_ebpf_to_smt(args.ebpf_file) # Pass file path to convert_ebpf_to_smt
    except RuntimeError as e:
        print(f"Error during conversion: {e}")
        return

    try:
        with open(args.smt_file, "w") as f:
            f.write(smt_code)
        print(f"SMT-LIB2 code saved to '{args.smt_file}'")
    except Exception as e:
        print(f"Error writing SMT file: {e}")

if __name__ == "__main__":
    main()
