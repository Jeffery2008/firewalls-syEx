# IPTables to eBPF Translation Tool

A comprehensive tool for translating IPTables rules to eBPF programs, with built-in verification and validation capabilities.

## Features

- Translate IPTables rules to eBPF programs using LLM technology
- Verify translation correctness using SMT solvers
- GUI interface for interactive rule management
- CLI support for automated workflows
- Built-in rule validation and syntax checking
- Support for complex IPTables configurations
- Performance analysis and optimization hints

## Project Structure

```
firewalls-syEx/
├── main.py                      # Main program entry point
├── utils.py                     # Utility functions and project settings
├── examples/                    # Example rule sets
│   ├── simple_rules.txt        # Basic firewall configuration
│   └── complex_rules.txt       # Advanced use cases
├── config/                     # Configuration directory
│   └── settings.json          # User settings
├── logs/                      # Log files
├── output/                    # Generated eBPF programs
├── iptablesToSMT/            # IPTables to SMT conversion
├── checkConsistency/         # Rule consistency verification
└── translateToEBPFWithLLM/   # LLM-based translation tool
```

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Configure the tool:
   ```bash
   python main.py setup --api-key YOUR_GEMINI_API_KEY
   ```

## Usage

### GUI Interface

Launch the graphical interface:
```bash
python main.py gui
```

### Command Line

Translate IPTables rules:
```bash
python main.py translate examples/simple_rules.txt
```

Options:
- `--no-verify`: Skip verification step
- `--output`: Specify custom output directory

## Example Rules

### Simple Rules (examples/simple_rules.txt)
Basic firewall configuration with:
- Standard port access (SSH, HTTP/HTTPS)
- Connection state tracking
- ICMP and loopback handling

### Complex Rules (examples/complex_rules.txt)
Advanced configuration demonstrating:
- Custom chains
- Rate limiting
- IP blacklisting
- Service-specific rules
- Network segmentation
- Advanced state matching

## Logging

Logs are stored in the `logs/` directory:
- `firewall_tool.log`: Main application log
- Translation and verification details
- Error reports and debugging information

## Configuration

Settings are stored in `config/settings.json`:
- API keys and model selection
- Output directory preferences
- Validation settings
- Performance monitoring options

## Error Handling

The tool provides detailed error messages for:
- Syntax errors in IPTables rules
- Translation failures
- Verification issues
- Configuration problems

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
