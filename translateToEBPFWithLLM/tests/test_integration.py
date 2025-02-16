import unittest
import sys
import os
from pathlib import Path
import tkinter as tk
from threading import Thread
import time

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from gui import FirewallToolGUI

class TestIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Create test data paths"""
        cls.simple_rules = Path(__file__).parent / "test_data/simple_rules.txt"
        cls.complex_rules = Path(__file__).parent / "test_data/complex_rules.txt"
        
    def setUp(self):
        self.root = tk.Tk()
        self.app = FirewallToolGUI(self.root)
        
    def tearDown(self):
        self.root.destroy()
        
    def test_initial_state(self):
        """Test initial GUI state"""
        # Check default model
        self.assertEqual(
            self.app.model_var.get(),
            "gemini-2.0-flash-thinking-exp-01-21"
        )
        
        # Check validation options
        self.assertTrue(self.app.validate_syntax.get())
        self.assertTrue(self.app.validate_performance.get())
        
        # Check no files selected initially
        self.assertIsNone(self.app.input_file)
        self.assertIsNone(self.app.output_file)
        
    def test_translation_without_input(self):
        """Test translation button behavior without input file"""
        # Try to start translation
        self.app.start_translation()
        
        # Should not have created translator
        self.assertIsNone(self.app.translator)
        
    def test_validation_without_translation(self):
        """Test validation button behavior without prior translation"""
        # Try to run validation
        self.app.run_validation()
        
        # Should not have validation results
        validation_text = self.app.validation_text.get(1.0, tk.END).strip()
        self.assertEqual(validation_text, "")
        
    def test_smt_without_translation(self):
        """Test SMT generation without prior translation"""
        # Try to generate SMT
        self.app.generate_smt()
        
        # Should not have SMT results
        smt_text = self.app.smt_text.get(1.0, tk.END).strip()
        self.assertEqual(smt_text, "")

    def test_simple_rules_translation(self):
        """Test translation of simple rules"""
        if not self.simple_rules.exists():
            self.skipTest("Simple rules test file not found")
            
        # Set input file
        self.app.input_path.set(str(self.simple_rules))
        self.app.input_file = str(self.simple_rules)
        
        # Start translation in a thread to avoid blocking
        translation_thread = Thread(target=self.app.run_translation)
        translation_thread.daemon = True
        translation_thread.start()
        
        # Wait for translation to complete (max 30 seconds)
        start_time = time.time()
        while translation_thread.is_alive():
            self.root.update()
            if time.time() - start_time > 30:
                self.fail("Translation timeout")
            time.sleep(0.1)
            
        # Check results
        result_text = self.app.result_text.get(1.0, tk.END).strip()
        self.assertIn("Translation successful", result_text)
        self.assertIsNotNone(self.app.output_file)
        
        # Check output file exists
        self.assertTrue(Path(self.app.output_file).exists())
        
    def test_complex_rules_translation(self):
        """Test translation of complex rules"""
        if not self.complex_rules.exists():
            self.skipTest("Complex rules test file not found")
            
        # Set input file
        self.app.input_path.set(str(self.complex_rules))
        self.app.input_file = str(self.complex_rules)
        
        # Start translation in a thread
        translation_thread = Thread(target=self.app.run_translation)
        translation_thread.daemon = True
        translation_thread.start()
        
        # Wait for translation to complete (max 60 seconds for complex rules)
        start_time = time.time()
        while translation_thread.is_alive():
            self.root.update()
            if time.time() - start_time > 60:
                self.fail("Translation timeout")
            time.sleep(0.1)
            
        # Check results
        result_text = self.app.result_text.get(1.0, tk.END).strip()
        self.assertIn("Translation successful", result_text)
        self.assertIsNotNone(self.app.output_file)
        
        # Check output file exists
        self.assertTrue(Path(self.app.output_file).exists())
        
        # Verify generated eBPF code
        with open(self.app.output_file, 'r') as f:
            ebpf_code = f.read()
            # Check for key eBPF components
            self.assertIn("SEC", ebpf_code)  # BPF section macro
            self.assertIn("struct", ebpf_code)  # Packet struct definitions
            self.assertIn("return TC_ACT", ebpf_code)  # Action returns

    def test_full_pipeline(self):
        """Test complete pipeline: translation -> validation -> SMT -> verification"""
        if not self.simple_rules.exists():
            self.skipTest("Simple rules test file not found")
            
        # Set input file and run translation
        self.app.input_path.set(str(self.simple_rules))
        self.app.input_file = str(self.simple_rules)
        
        translation_thread = Thread(target=self.app.run_translation)
        translation_thread.daemon = True
        translation_thread.start()
        
        while translation_thread.is_alive():
            self.root.update()
            time.sleep(0.1)
            
        # Run validation
        self.app.run_validation()
        validation_text = self.app.validation_text.get(1.0, tk.END).strip()
        self.assertIn("validation passed", validation_text.lower())
        
        # Generate SMT formulas
        self.app.generate_smt()
        smt_text = self.app.smt_text.get(1.0, tk.END).strip()
        self.assertIn("SMT formulas generated successfully", smt_text)
        
        # Verify equivalence
        self.app.verify_equivalence()
        verification_text = self.app.smt_text.get(1.0, tk.END).strip()
        self.assertIn("equivalent", verification_text.lower())

if __name__ == '__main__':
    unittest.main()
