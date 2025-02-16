# Firewall Analysis & Translation Tool

This tool provides a complete pipeline for translating IPTables rules to eBPF, with validation and verification capabilities.

## Features

- Translation of IPTables rules to eBPF using Google's Gemini AI
- Syntax and performance validation of generated eBPF code
- SMT formula generation for formal verification
- Equivalence checking between original rules and generated code
- User-friendly GUI interface

## Installation

1. Clone the repository:
```bash
git clone https://github.com/your-username/translateToEBPFWithLLM.git
cd translateToEBPFWithLLM
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure your Gemini API key:
```bash
python setup.py --api-key YOUR_GEMINI_API_KEY
```

## Using the GUI

Launch the GUI application:
```bash
python gui.py
```

The GUI provides four main tabs:

### 1. Translation Tab
- Select your IPTables rules file using the "Browse" button
- Choose the Gemini model version (default is recommended)
- Click "Translate to eBPF" to start the translation
- View results and any messages in the results text area

### 2. Validation Tab
- Options for syntax and performance validation
- Run validation after translation is complete
- View detailed validation results and any warnings

### 3. SMT & Verification Tab
- Generate SMT formulas for both IPTables and eBPF code
- Verify semantic equivalence between original and translated rules
- View verification results and any potential inconsistencies

### 4. Logs Tab
- Real-time view of the translation and verification process
- Helpful for debugging if any issues occur

## Command Line Usage

For users who prefer command-line operation:

1. Translate rules:
```bash
python main.py path/to/iptables_rules
```

2. Validate generated code:
```bash
python ebpf_validator.py path/to/generated.bpf.c
```

3. Generate SMT and verify:
```bash
python iptablesToSMT/main.py input_rules.txt output.smt2
python checkConsistency/main.py iptables.smt2 ebpf.smt2
```

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
