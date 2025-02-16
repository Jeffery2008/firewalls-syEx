import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import sys
import os
from pathlib import Path
from datetime import datetime

# Import tool components
from main import EBPFTranslator
from validator import validate_iptables_rules
from ebpf_validator import validate_ebpf_code, check_performance_patterns
from iptablesToSMT.main import process_firewall
from checkConsistency.main import check_consistency

class FirewallToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Firewall Analysis & Translation Tool")
        self.root.geometry("1000x800")
        
        # Create main notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill='both', padx=5, pady=5)
        
        # Create tabs
        self.setup_translation_tab()
        self.setup_validation_tab()
        self.setup_smt_tab()
        self.setup_log_tab()
        
        # Initialize translator
        self.translator = None
        self.input_file = None
        self.output_file = None
        
        # Log file path
        self.log_file = Path("translation.log")
        
        # Start log monitoring
        self.monitor_log_file()

    def setup_translation_tab(self):
        """Setup the main translation tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Translation")
        
        # Input file selection
        input_frame = ttk.LabelFrame(frame, text="Input", padding="5")
        input_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(input_frame, text="IPTables Rules File:").pack(side='left', padx=5)
        self.input_path = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.input_path).pack(side='left', fill='x', expand=True, padx=5)
        ttk.Button(input_frame, text="Browse", command=self.browse_input).pack(side='left', padx=5)
        
        # Model selection
        model_frame = ttk.LabelFrame(frame, text="Model Configuration", padding="5")
        model_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(model_frame, text="Gemini Model:").pack(side='left', padx=5)
        self.model_var = tk.StringVar(value="gemini-2.0-flash-thinking-exp-01-21")
        model_entry = ttk.Entry(model_frame, textvariable=self.model_var)
        model_entry.pack(side='left', fill='x', expand=True, padx=5)
        
        # Translation button
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        
        self.translate_btn = ttk.Button(btn_frame, text="Translate to eBPF", command=self.start_translation)
        self.translate_btn.pack(side='left', padx=5)
        
        self.progress = ttk.Progressbar(btn_frame, mode='indeterminate')
        self.progress.pack(side='left', fill='x', expand=True, padx=5)
        
        # Results
        result_frame = ttk.LabelFrame(frame, text="Results", padding="5")
        result_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, height=20)
        self.result_text.pack(fill='both', expand=True)

    def setup_validation_tab(self):
        """Setup the validation tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Validation")
        
        # Validation options
        options_frame = ttk.LabelFrame(frame, text="Validation Options", padding="5")
        options_frame.pack(fill='x', padx=5, pady=5)
        
        self.validate_syntax = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Syntax Validation", variable=self.validate_syntax).pack(side='left', padx=5)
        
        self.validate_performance = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Performance Analysis", variable=self.validate_performance).pack(side='left', padx=5)
        
        # Validation button
        ttk.Button(frame, text="Run Validation", command=self.run_validation).pack(padx=5, pady=5)
        
        # Results
        result_frame = ttk.LabelFrame(frame, text="Validation Results", padding="5")
        result_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.validation_text = scrolledtext.ScrolledText(result_frame, height=20)
        self.validation_text.pack(fill='both', expand=True)

    def setup_smt_tab(self):
        """Setup the SMT generation and verification tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="SMT & Verification")
        
        # SMT generation
        smt_frame = ttk.LabelFrame(frame, text="SMT Formula Generation", padding="5")
        smt_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(smt_frame, text="Generate SMT Formulas", command=self.generate_smt).pack(padx=5, pady=5)
        
        # Verification
        verify_frame = ttk.LabelFrame(frame, text="Equivalence Verification", padding="5")
        verify_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(verify_frame, text="Verify Equivalence", command=self.verify_equivalence).pack(padx=5, pady=5)
        
        # Results
        result_frame = ttk.LabelFrame(frame, text="Results", padding="5")
        result_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.smt_text = scrolledtext.ScrolledText(result_frame, height=20)
        self.smt_text.pack(fill='both', expand=True)

    def setup_log_tab(self):
        """Setup the log viewing tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Logs")
        
        self.log_text = scrolledtext.ScrolledText(frame, height=20)
        self.log_text.pack(fill='both', expand=True, padx=5, pady=5)

    def browse_input(self):
        """Open file dialog to select input file"""
        filename = filedialog.askopenfilename(
            title="Select IPTables Rules File",
            filetypes=[("All Files", "*.*"), ("Text Files", "*.txt")]
        )
        if filename:
            self.input_path.set(filename)
            self.input_file = filename

    def start_translation(self):
        """Start the translation process in a separate thread"""
        if not self.input_path.get():
            messagebox.showerror("Error", "Please select an input file first")
            return
            
        self.translate_btn.config(state='disabled')
        self.progress.start()
        
        thread = threading.Thread(target=self.run_translation)
        thread.daemon = True
        thread.start()

    def run_translation(self):
        """Run the translation process"""
        try:
            self.translator = EBPFTranslator(model=self.model_var.get())
            self.output_file = self.translator.translate_rules(self.input_path.get())
            
            if self.output_file:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"Translation successful!\n\n")
                self.result_text.insert(tk.END, f"Output file: {self.output_file}\n")
                self.result_text.insert(tk.END, f"Log file: {self.log_file}\n")
            else:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, "Translation failed. Check the log tab for details.\n")
        except Exception as e:
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Error during translation: {str(e)}\n")
        finally:
            self.root.after(0, self.translation_completed)

    def translation_completed(self):
        """Clean up after translation is complete"""
        self.translate_btn.config(state='normal')
        self.progress.stop()

    def run_validation(self):
        """Run validation on the translated code"""
        if not self.output_file:
            messagebox.showerror("Error", "Please run translation first")
            return
            
        self.validation_text.delete(1.0, tk.END)
        
        try:
            if self.validate_syntax.get():
                # Validate eBPF code
                if validate_ebpf_code(self.output_file, str(self.log_file)):
                    self.validation_text.insert(tk.END, "✓ Syntax validation passed\n\n")
                else:
                    self.validation_text.insert(tk.END, "✗ Syntax validation failed\n\n")
            
            if self.validate_performance.get():
                # Check performance patterns
                warnings = check_performance_patterns(self.output_file)
                if warnings:
                    self.validation_text.insert(tk.END, "Performance Warnings:\n")
                    for line_num, warning in sorted(warnings):
                        self.validation_text.insert(tk.END, f"Line {line_num}: {warning}\n")
                else:
                    self.validation_text.insert(tk.END, "✓ No performance warnings\n")
        except Exception as e:
            self.validation_text.insert(tk.END, f"Error during validation: {str(e)}\n")

    def generate_smt(self):
        """Generate SMT formulas for both iptables and eBPF"""
        if not self.output_file:
            messagebox.showerror("Error", "Please run translation first")
            return
            
        self.smt_text.delete(1.0, tk.END)
        
        try:
            # Generate SMT for eBPF
            from iptablesToSMT.code_generator import generate_smt
            ebpf_smt_file = str(Path(self.output_file).with_suffix('.smt2'))
            generate_smt(str(self.output_file), ebpf_smt_file)
            
            # Generate SMT for iptables
            iptables_smt_file = self.input_path.get() + ".smt2"
            process_firewall(self.input_path.get(), iptables_smt_file)
            
            self.smt_text.insert(tk.END, "SMT formulas generated successfully:\n\n")
            self.smt_text.insert(tk.END, f"eBPF SMT: {ebpf_smt_file}\n")
            self.smt_text.insert(tk.END, f"IPTables SMT: {iptables_smt_file}\n")
        except Exception as e:
            self.smt_text.insert(tk.END, f"Error generating SMT formulas: {str(e)}\n")

    def verify_equivalence(self):
        """Verify equivalence between iptables and eBPF"""
        if not self.output_file:
            messagebox.showerror("Error", "Please run translation first")
            return
            
        try:
            iptables_smt_file = self.input_path.get() + ".smt2"
            ebpf_smt_file = str(Path(self.output_file).with_suffix('.smt2'))
            
            is_consistent, message = check_consistency(iptables_smt_file, ebpf_smt_file)
            
            self.smt_text.insert(tk.END, "\nEquivalence Verification Results:\n")
            if is_consistent:
                self.smt_text.insert(tk.END, "✓ eBPF code is equivalent to original iptables rules!\n")
            else:
                self.smt_text.insert(tk.END, f"✗ Potential inconsistency detected:\n{message}\n")
        except Exception as e:
            self.smt_text.insert(tk.END, f"Error verifying equivalence: {str(e)}\n")

    def monitor_log_file(self):
        """Monitor and update the log tab with new log entries"""
        if self.log_file.exists():
            try:
                with open(self.log_file, 'r') as f:
                    content = f.read()
                    if content != self.log_text.get(1.0, tk.END).strip():
                        self.log_text.delete(1.0, tk.END)
                        self.log_text.insert(tk.END, content)
                        self.log_text.see(tk.END)
            except Exception:
                pass
        
        # Schedule next update
        self.root.after(1000, self.monitor_log_file)

def main():
    root = tk.Tk()
    app = FirewallToolGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
